package policy

import (
	"fmt"
	"strings"

	"github.com/ppiankov/chainwatch/internal/budget"
	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/identity"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/zone"
)

// Evaluate evaluates a single action in the context of the current trace state.
//
// Evaluation order (must not be changed):
//  1. Denylist check — hard block, tier 3
//  2. Zone escalation — update state
//  3. Tier classification — zones + self-targeting + known-safe + min_tier
//     3.5. Agent enforcement — scope, purpose, sensitivity, per-agent rules (only if agentID != "")
//     3.75. Budget enforcement — per-agent session resource caps (only if budgets configured)
//  4. Purpose-bound rules — explicit overrides (first match wins)
//  5. Tier enforcement — mode + tier → decision
func Evaluate(action *model.Action, state *model.TraceState, purpose string, agentID string, dl *denylist.Denylist, cfg *PolicyConfig) model.PolicyResult {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Step 1: Denylist check (hard block, highest priority, always tier 3)
	if dl != nil {
		if blocked, reason := dl.IsBlocked(action.Resource, action.Tool); blocked {
			return model.PolicyResult{
				Decision: model.Deny,
				Tier:     TierCritical,
				Reason:   fmt.Sprintf("denylisted: %s", reason),
				PolicyID: "denylist.block",
			}
		}
	}

	action.NormalizeMeta()

	// Step 2: Zone escalation
	newZones := zone.DetectZones(action, state)
	for z := range newZones {
		state.ZonesEntered[z] = true
	}
	newLevel := zone.ComputeIrreversibilityLevel(state.ZonesEntered)
	state.EscalateLevel(newLevel)

	// Step 3: Tier classification
	tier := ClassifyTier(state.Zone)

	// Self-targeting override (Law 3: self-preservation is structural)
	if model.IsSelfTargeting(action) {
		tier = TierCritical
	}

	// Known-safe vs unknown: if no zone signal, distinguish safe from unknown
	if tier == TierSafe {
		if IsKnownSafe(action) {
			// Confirmed safe, stays tier 0
		} else {
			// Unknown action defaults to tier 1 (elevated)
			tier = TierElevated
		}
	}

	// Profile min_tier promotion (baked into cfg by profile.ApplyToPolicy)
	if cfg.MinTier > tier {
		tier = cfg.MinTier
	}

	// Step 3.5: Agent enforcement (only if agentID is provided)
	if agentID != "" {
		state.AgentID = agentID

		if result, handled := evaluateAgent(agentID, action, purpose, tier, cfg); handled {
			return result
		}
	}

	// Step 3.75: Budget enforcement (only if budgets configured)
	if len(cfg.Budgets) > 0 {
		effectiveAgent := agentID
		if effectiveAgent == "" {
			effectiveAgent = "*"
		}
		if result, handled := budget.Evaluate(effectiveAgent, state, cfg.Budgets, tier); handled {
			return result
		}
	}

	// Step 4: Purpose-bound rules (explicit overrides, first match wins)
	for _, rule := range cfg.Rules {
		if matchRule(rule, purpose, action.Resource) {
			decision := parseDecision(rule.Decision)
			reason := rule.Reason
			if reason == "" {
				reason = fmt.Sprintf("%s purpose: %s requires %s",
					rule.Purpose, rule.ResourcePattern, rule.Decision)
			}
			return model.PolicyResult{
				Decision:    decision,
				Tier:        tier,
				Reason:      reason,
				ApprovalKey: rule.ApprovalKey,
				PolicyID:    rulePolicyID(rule),
			}
		}
	}

	// Step 5: Tier enforcement
	mode := cfg.EnforcementMode
	if mode == "" {
		mode = "guarded"
	}
	decision, policyID := EnforceByTier(mode, tier)

	result := model.PolicyResult{
		Decision: decision,
		Tier:     tier,
		Reason:   fmt.Sprintf("tier %d (%s) in %s mode", tier, TierLabel(tier), mode),
		PolicyID: policyID,
	}

	if decision == model.RequireApproval {
		result.ApprovalKey = fmt.Sprintf("tier_%d_action", tier)
	}

	return result
}

// evaluateAgent enforces agent identity constraints.
// Returns (result, true) if the agent check produces a terminal decision.
// Returns (zero, false) if the action should fall through to step 4/5.
func evaluateAgent(agentID string, action *model.Action, purpose string, tier int, cfg *PolicyConfig) (model.PolicyResult, bool) {
	// No agents configured → fail closed
	if len(cfg.Agents) == 0 {
		return model.PolicyResult{
			Decision: model.Deny,
			Tier:     tier,
			Reason:   "no agents configured",
			PolicyID: "agent.no_config",
		}, true
	}

	registry := identity.NewRegistry(cfg.Agents)

	// Unknown agent → fail closed
	agentCfg := registry.Lookup(agentID)
	if agentCfg == nil {
		return model.PolicyResult{
			Decision: model.Deny,
			Tier:     tier,
			Reason:   fmt.Sprintf("unknown agent: %s", agentID),
			PolicyID: "agent.unknown",
		}, true
	}

	// Purpose validation
	if purpose != "" && !registry.ValidatePurpose(agentID, purpose) {
		return model.PolicyResult{
			Decision: model.Deny,
			Tier:     tier,
			Reason:   fmt.Sprintf("purpose %q not authorized for agent %s", purpose, agentID),
			PolicyID: fmt.Sprintf("agent.%s.purpose_denied", agentID),
		}, true
	}

	// Resource scope validation
	if action.Resource != "" && !registry.MatchResource(agentID, action.Resource) {
		return model.PolicyResult{
			Decision: model.Deny,
			Tier:     tier,
			Reason:   fmt.Sprintf("resource %q out of scope for agent %s", action.Resource, agentID),
			PolicyID: fmt.Sprintf("agent.%s.scope_denied", agentID),
		}, true
	}

	// Sensitivity cap enforcement
	if agentCfg.MaxSensitivity != "" {
		meta := action.NormalizedMeta()
		agentRank := model.SensRank[agentCfg.MaxSensitivity]
		actionRank := model.SensRank[meta.Sensitivity]
		if actionRank > agentRank {
			return model.PolicyResult{
				Decision: model.Deny,
				Tier:     tier,
				Reason: fmt.Sprintf("sensitivity %s exceeds cap %s for agent %s",
					meta.Sensitivity, agentCfg.MaxSensitivity, agentID),
				PolicyID: fmt.Sprintf("agent.%s.sensitivity_denied", agentID),
			}, true
		}
	}

	// Agent-scoped rules (first match wins)
	for _, rule := range agentCfg.Rules {
		if identity.MatchPattern(rule.ResourcePattern, action.Resource) {
			decision := parseDecision(rule.Decision)
			reason := rule.Reason
			if reason == "" {
				reason = fmt.Sprintf("agent %s rule: %s → %s", agentID, rule.ResourcePattern, rule.Decision)
			}
			return model.PolicyResult{
				Decision:    decision,
				Tier:        tier,
				Reason:      reason,
				ApprovalKey: rule.ApprovalKey,
				PolicyID:    fmt.Sprintf("agent.%s.rule.%s", agentID, rule.ResourcePattern),
			}, true
		}
	}

	// No agent rule matched — fall through to step 4/5
	return model.PolicyResult{}, false
}

func formatZones(zones map[model.Zone]bool) string {
	parts := make([]string, 0, len(zones))
	for z := range zones {
		parts = append(parts, string(z))
	}
	return strings.Join(parts, ", ")
}
