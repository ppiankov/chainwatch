package sim

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DiffEntry represents one action where the decision changed.
type DiffEntry struct {
	Timestamp   string `json:"ts"`
	TraceID     string `json:"trace_id"`
	Tool        string `json:"tool"`
	Resource    string `json:"resource"`
	OldDecision string `json:"old_decision"`
	NewDecision string `json:"new_decision"`
	OldReason   string `json:"old_reason"`
	NewReason   string `json:"new_reason"`
	OldTier     int    `json:"old_tier"`
	NewTier     int    `json:"new_tier"`
}

// SimResult holds the complete simulation output.
type SimResult struct {
	PolicyPath     string      `json:"policy_path"`
	TotalActions   int         `json:"total_actions"`
	ChangedActions int         `json:"changed_actions"`
	NewlyBlocked   int         `json:"newly_blocked"`
	NewlyAllowed   int         `json:"newly_allowed"`
	Changes        []DiffEntry `json:"changes"`
}

// isPermissive returns true for decisions that allow action execution.
func isPermissive(decision string) bool {
	switch decision {
	case "allow", "allow_with_redaction", "rewrite_output":
		return true
	default:
		return false
	}
}

// isRestrictive returns true for decisions that block action execution.
func isRestrictive(decision string) bool {
	switch decision {
	case "deny", "require_approval":
		return true
	default:
		return false
	}
}

// FormatText renders the simulation result as human-readable text.
func FormatText(r *SimResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Simulating %s against %d recorded actions...\n", r.PolicyPath, r.TotalActions)

	if len(r.Changes) == 0 {
		b.WriteString("\nNo changes detected.\n")
		return b.String()
	}

	b.WriteString("\n")
	for _, d := range r.Changes {
		ts := d.Timestamp
		if len(ts) > 8 {
			// Extract HH:MM:SS from timestamp
			ts = ts[11:]
			if len(ts) > 8 {
				ts = ts[:8]
			}
		}
		resource := d.Resource
		if len(resource) > 40 {
			resource = resource[:37] + "..."
		}
		fmt.Fprintf(&b, "  CHANGED  %s  %-12s %-40s %s → %s\n",
			ts, d.Tool, resource, d.OldDecision, d.NewDecision)
	}

	fmt.Fprintf(&b, "\n%d of %d actions changed.", r.ChangedActions, r.TotalActions)
	if r.NewlyBlocked > 0 || r.NewlyAllowed > 0 {
		fmt.Fprintf(&b, " %d newly blocked, %d newly allowed.", r.NewlyBlocked, r.NewlyAllowed)
	}
	b.WriteString("\n")

	return b.String()
}

// FormatJSON renders the simulation result as JSON.
func FormatJSON(r *SimResult) (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal sim result: %w", err)
	}
	return string(data), nil
}
