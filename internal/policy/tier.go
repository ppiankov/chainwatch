package policy

import (
	"fmt"
	"strings"

	"github.com/ppiankov/chainwatch/internal/model"
)

// Risk tier constants. Higher tier = more restricted.
const (
	TierSafe     = 0 // Allow, log
	TierElevated = 1 // Allow, log with detail
	TierGuarded  = 2 // Require approval, log
	TierCritical = 3 // Deny by default, break-glass only
)

// TierLabel returns a human-readable label for the tier.
func TierLabel(tier int) string {
	switch tier {
	case TierSafe:
		return "safe"
	case TierElevated:
		return "elevated"
	case TierGuarded:
		return "guarded"
	case TierCritical:
		return "critical"
	default:
		return fmt.Sprintf("unknown(%d)", tier)
	}
}

// ClassifyTier maps a BoundaryZone to a risk tier.
// Safe(0)→0, Sensitive(1)→1, Commitment(2)→2, Irreversible(3)→3.
func ClassifyTier(zone model.BoundaryZone) int {
	return int(zone)
}

// IsKnownSafe returns true if the action is obviously safe (tier 0).
// Read-only operations on non-sensitive data and trivial commands qualify.
func IsKnownSafe(action *model.Action) bool {
	meta := action.NormalizedMeta()
	if meta.Sensitivity != model.SensLow {
		return false
	}

	op := strings.ToLower(action.Operation)
	// Read-only file/HTTP operations on non-sensitive data
	if op == "read" || op == "get" {
		return true
	}

	// Known safe commands
	if action.Tool == "command" {
		base := extractBaseName(action.Resource)
		for _, safe := range knownSafeCommands {
			if base == safe {
				return true
			}
		}
	}

	return false
}

var knownSafeCommands = []string{
	"ls", "cat", "whoami", "pwd", "echo", "date", "hostname", "uname",
	"wc", "head", "tail", "which", "env", "printenv", "id",
}

// extractBaseName returns the first word of a command string (the binary name).
func extractBaseName(resource string) string {
	parts := strings.Fields(resource)
	if len(parts) == 0 {
		return ""
	}
	name := parts[0]
	// Strip path prefix: /usr/bin/ls → ls
	if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
		name = name[idx+1:]
	}
	return strings.ToLower(name)
}

// EnforceByTier maps a tier and enforcement mode to a decision and policy ID.
func EnforceByTier(mode string, tier int) (model.Decision, string) {
	switch mode {
	case "advisory":
		return model.Allow, "tier.advisory"
	case "locked":
		switch {
		case tier >= TierGuarded:
			return model.Deny, "tier.locked.deny"
		case tier >= TierElevated:
			return model.RequireApproval, "tier.locked.approval"
		default:
			return model.Allow, "tier.locked.allow"
		}
	default: // "guarded" (default)
		switch {
		case tier >= TierCritical:
			return model.Deny, "tier.guarded.deny"
		case tier >= TierGuarded:
			return model.RequireApproval, "tier.guarded.approval"
		default:
			return model.Allow, "tier.guarded.allow"
		}
	}
}
