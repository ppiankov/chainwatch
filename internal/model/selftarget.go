package model

import "strings"

// selfTargetPatterns are resource substrings that indicate an action
// targets chainwatch itself. Self-targeting actions are always tier 3
// (Law 3: self-preservation is structural, not negotiable).
var selfTargetPatterns = []string{
	"chainwatch",
	".chainwatch/",
	"chainwatch.yaml",
}

// IsSelfTargeting returns true if the action targets chainwatch itself.
// Fail-closed: broad matching is intentionally conservative for safety.
func IsSelfTargeting(action *Action) bool {
	lower := strings.ToLower(action.Resource)
	for _, p := range selfTargetPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	if strings.Contains(strings.ToLower(action.Tool), "chainwatch") {
		return true
	}
	return false
}
