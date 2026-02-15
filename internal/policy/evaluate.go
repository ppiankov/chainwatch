package policy

import (
	"fmt"
	"strings"

	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/zone"
)

// Evaluate evaluates a single action in the context of the current trace state.
//
// Evaluation order (must not be changed):
//  1. Denylist check — hard block, tier 3
//  2. Zone escalation — update state
//  3. Tier classification — zones + self-targeting + known-safe + min_tier
//  4. Purpose-bound rules — explicit overrides (first match wins)
//  5. Tier enforcement — mode + tier → decision
func Evaluate(action *model.Action, state *model.TraceState, purpose string, dl *denylist.Denylist, cfg *PolicyConfig) model.PolicyResult {
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

func formatZones(zones map[model.Zone]bool) string {
	parts := make([]string, 0, len(zones))
	for z := range zones {
		parts = append(parts, string(z))
	}
	return strings.Join(parts, ", ")
}
