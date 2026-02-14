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
//  1. Denylist check (v0.1.x — still active)
//  2. Zone escalation (v0.2.0 — update state)
//  3. Irreversibility level check (v0.2.0 — enforce monotonic boundaries)
//  4. Legacy risk scoring (v0.1.x — for non-boundary cases)
//  5. Purpose-bound rules (v0.1.x — specific hard rules)
func Evaluate(action *model.Action, state *model.TraceState, purpose string, dl *denylist.Denylist, cfg *PolicyConfig) model.PolicyResult {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Step 1: Denylist check (hard block, highest priority)
	if dl != nil {
		if blocked, reason := dl.IsBlocked(action.Resource, action.Tool); blocked {
			return model.PolicyResult{
				Decision: model.Deny,
				Reason:   fmt.Sprintf("denylisted: %s", reason),
				PolicyID: "denylist.block",
			}
		}
	}

	action.NormalizeMeta()
	meta := action.NormalizedMeta()

	// Step 2: Zone escalation (NEW in v0.2.0)
	newZones := zone.DetectZones(action, state)
	for z := range newZones {
		state.ZonesEntered[z] = true
	}
	newLevel := zone.ComputeIrreversibilityLevel(state.ZonesEntered)
	state.EscalateLevel(newLevel)

	// Step 3: Irreversibility level check (NEW in v0.2.0)
	if state.Zone == model.Irreversible {
		zonesStr := formatZones(state.ZonesEntered)
		return model.PolicyResult{
			Decision: model.Deny,
			Reason:   fmt.Sprintf("irreversibility boundary crossed: zones=[%s]", zonesStr),
			PolicyID: "monotonic.irreversible",
		}
	}

	if state.Zone == model.Commitment {
		zonesStr := formatZones(state.ZonesEntered)
		return model.PolicyResult{
			Decision:    model.RequireApproval,
			Reason:      fmt.Sprintf("commitment zone entered: zones=[%s]", zonesStr),
			ApprovalKey: "commitment_boundary",
			PolicyID:    "monotonic.commitment",
		}
	}

	// Step 4: Legacy risk scoring
	source := action.Tool
	if source == "" {
		if idx := strings.IndexByte(action.Resource, '/'); idx >= 0 {
			source = action.Resource[:idx]
		} else {
			source = action.Resource
		}
	}
	isNewSource := !state.HasSource(source)

	risk := riskScore(meta, state, isNewSource, cfg)

	// Step 5: Purpose-bound rules from config (explicit > scoring)
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
				Reason:      reason,
				ApprovalKey: rule.ApprovalKey,
				PolicyID:    rulePolicyID(rule),
			}
		}
	}

	// Risk-based enforcement
	if risk >= cfg.Thresholds.ApprovalMin {
		return model.PolicyResult{
			Decision:    model.RequireApproval,
			Reason:      fmt.Sprintf("high cumulative risk (risk=%d) based on sensitivity, volume, and chain context", risk),
			ApprovalKey: "high_risk_action",
			PolicyID:    "risk.high",
		}
	}

	if risk > cfg.Thresholds.AllowMax {
		return model.PolicyResult{
			Decision:   model.AllowWithRedaction,
			Reason:     fmt.Sprintf("moderate risk (risk=%d); sensitive fields must be redacted", risk),
			Redactions: map[string]any{"auto": true},
			PolicyID:   "risk.moderate",
		}
	}

	return model.PolicyResult{
		Decision: model.Allow,
		Reason:   fmt.Sprintf("low risk action (risk=%d)", risk),
		PolicyID: "risk.low",
	}
}

func formatZones(zones map[model.Zone]bool) string {
	parts := make([]string, 0, len(zones))
	for z := range zones {
		parts = append(parts, string(z))
	}
	return strings.Join(parts, ", ")
}
