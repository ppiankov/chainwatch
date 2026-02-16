package policydiff

import (
	"fmt"
	"sort"

	"github.com/ppiankov/chainwatch/internal/policy"
)

// Change represents a scalar field change.
type Change struct {
	Field   string `json:"field"`
	Old     string `json:"old"`
	New     string `json:"new"`
	Comment string `json:"comment,omitempty"`
}

// RuleChange represents a rule addition, removal, or modification.
type RuleChange struct {
	Type string `json:"type"` // "added", "removed", "changed"
	Rule string `json:"rule"`
}

// DiffResult holds the comparison of two PolicyConfigs.
type DiffResult struct {
	OldPath     string       `json:"old_path"`
	NewPath     string       `json:"new_path"`
	Changes     []Change     `json:"changes"`
	RuleChanges []RuleChange `json:"rule_changes"`
	HasChanges  bool         `json:"has_changes"`
}

// Diff compares two PolicyConfigs and returns the differences.
func Diff(old, new *policy.PolicyConfig) *DiffResult {
	r := &DiffResult{}

	// Enforcement mode
	if old.EnforcementMode != new.EnforcementMode {
		r.Changes = append(r.Changes, Change{
			Field: "enforcement_mode",
			Old:   old.EnforcementMode,
			New:   new.EnforcementMode,
		})
	}

	// MinTier
	if old.MinTier != new.MinTier {
		r.Changes = append(r.Changes, Change{
			Field:   "min_tier",
			Old:     fmt.Sprintf("%d", old.MinTier),
			New:     fmt.Sprintf("%d", new.MinTier),
			Comment: intComment(old.MinTier, new.MinTier, true),
		})
	}

	// Thresholds
	diffInt(r, "thresholds.allow_max",
		old.Thresholds.AllowMax, new.Thresholds.AllowMax, false)
	diffInt(r, "thresholds.approval_min",
		old.Thresholds.ApprovalMin, new.Thresholds.ApprovalMin, false)

	// Sensitivity weights
	diffInt(r, "sensitivity_weights.low",
		old.SensitivityWeights.Low, new.SensitivityWeights.Low, true)
	diffInt(r, "sensitivity_weights.medium",
		old.SensitivityWeights.Medium, new.SensitivityWeights.Medium, true)
	diffInt(r, "sensitivity_weights.high",
		old.SensitivityWeights.High, new.SensitivityWeights.High, true)

	// Rules
	diffRules(r, old.Rules, new.Rules)

	// Map-based sections: agents, budgets, rate_limits
	diffMapKeys(r, "agents", agentKeys(old), agentKeys(new))
	diffMapKeys(r, "budgets", budgetKeys(old), budgetKeys(new))
	diffMapKeys(r, "rate_limits", rateLimitKeys(old), rateLimitKeys(new))

	r.HasChanges = len(r.Changes) > 0 || len(r.RuleChanges) > 0
	return r
}

func diffInt(r *DiffResult, field string, old, new int, higherIsStricter bool) {
	if old != new {
		r.Changes = append(r.Changes, Change{
			Field:   field,
			Old:     fmt.Sprintf("%d", old),
			New:     fmt.Sprintf("%d", new),
			Comment: intComment(old, new, higherIsStricter),
		})
	}
}

func intComment(old, new int, higherIsStricter bool) string {
	if higherIsStricter {
		if new > old {
			return "stricter"
		}
		return "looser"
	}
	// Lower is stricter (e.g., allow_max: lower threshold = fewer auto-allows)
	if new < old {
		return "stricter"
	}
	return "looser"
}

func ruleKey(r policy.Rule) string {
	return r.Purpose + "|" + r.ResourcePattern
}

func ruleLabel(r policy.Rule) string {
	return fmt.Sprintf("purpose=%s resource=%s", r.Purpose, r.ResourcePattern)
}

func diffRules(r *DiffResult, oldRules, newRules []policy.Rule) {
	oldMap := make(map[string]policy.Rule)
	for _, rule := range oldRules {
		oldMap[ruleKey(rule)] = rule
	}

	newMap := make(map[string]policy.Rule)
	for _, rule := range newRules {
		newMap[ruleKey(rule)] = rule
	}

	// Check for added and changed
	for _, rule := range newRules {
		k := ruleKey(rule)
		if oldRule, exists := oldMap[k]; exists {
			if oldRule.Decision != rule.Decision {
				r.RuleChanges = append(r.RuleChanges, RuleChange{
					Type: "changed",
					Rule: fmt.Sprintf("%s → %s (was: %s)", ruleLabel(rule), rule.Decision, oldRule.Decision),
				})
			}
		} else {
			r.RuleChanges = append(r.RuleChanges, RuleChange{
				Type: "added",
				Rule: fmt.Sprintf("%s → %s", ruleLabel(rule), rule.Decision),
			})
		}
	}

	// Check for removed
	for _, rule := range oldRules {
		k := ruleKey(rule)
		if _, exists := newMap[k]; !exists {
			r.RuleChanges = append(r.RuleChanges, RuleChange{
				Type: "removed",
				Rule: fmt.Sprintf("%s → %s", ruleLabel(rule), rule.Decision),
			})
		}
	}
}

func diffMapKeys(r *DiffResult, section string, oldKeys, newKeys []string) {
	oldSet := make(map[string]bool)
	for _, k := range oldKeys {
		oldSet[k] = true
	}
	newSet := make(map[string]bool)
	for _, k := range newKeys {
		newSet[k] = true
	}

	for _, k := range newKeys {
		if !oldSet[k] {
			r.Changes = append(r.Changes, Change{
				Field:   section,
				Old:     "",
				New:     k,
				Comment: "added",
			})
		}
	}
	for _, k := range oldKeys {
		if !newSet[k] {
			r.Changes = append(r.Changes, Change{
				Field:   section,
				Old:     k,
				New:     "",
				Comment: "removed",
			})
		}
	}
}

func agentKeys(cfg *policy.PolicyConfig) []string {
	keys := make([]string, 0, len(cfg.Agents))
	for k := range cfg.Agents {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func budgetKeys(cfg *policy.PolicyConfig) []string {
	keys := make([]string, 0, len(cfg.Budgets))
	for k := range cfg.Budgets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func rateLimitKeys(cfg *policy.PolicyConfig) []string {
	keys := make([]string, 0, len(cfg.RateLimits))
	for k := range cfg.RateLimits {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
