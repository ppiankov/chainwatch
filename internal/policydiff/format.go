package policydiff

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FormatText renders the diff result as human-readable text.
func FormatText(r *DiffResult) string {
	if !r.HasChanges {
		return fmt.Sprintf("Policy diff: %s → %s\n\nNo changes detected.\n", r.OldPath, r.NewPath)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Policy diff: %s → %s\n", r.OldPath, r.NewPath)

	// Group scalar changes by section
	thresholds := filterChanges(r.Changes, "thresholds.")
	weights := filterChanges(r.Changes, "sensitivity_weights.")
	topLevel := filterTopLevel(r.Changes)
	mapChanges := filterChanges(r.Changes, "agents", "budgets", "rate_limits")

	if len(topLevel) > 0 {
		b.WriteString("\n")
		for _, c := range topLevel {
			fmt.Fprintf(&b, "  %-24s %s → %s", c.Field+":", c.Old, c.New)
			if c.Comment != "" {
				fmt.Fprintf(&b, "  (%s)", c.Comment)
			}
			b.WriteString("\n")
		}
	}

	if len(thresholds) > 0 {
		b.WriteString("\n  Thresholds:\n")
		for _, c := range thresholds {
			name := strings.TrimPrefix(c.Field, "thresholds.")
			fmt.Fprintf(&b, "    %-18s %s → %s", name+":", c.Old, c.New)
			if c.Comment != "" {
				fmt.Fprintf(&b, "  (%s)", c.Comment)
			}
			b.WriteString("\n")
		}
	}

	if len(weights) > 0 {
		b.WriteString("\n  Sensitivity Weights:\n")
		for _, c := range weights {
			name := strings.TrimPrefix(c.Field, "sensitivity_weights.")
			fmt.Fprintf(&b, "    %-18s %s → %s", name+":", c.Old, c.New)
			if c.Comment != "" {
				fmt.Fprintf(&b, "  (%s)", c.Comment)
			}
			b.WriteString("\n")
		}
	}

	if len(r.RuleChanges) > 0 {
		b.WriteString("\n  Rules:\n")
		for _, rc := range r.RuleChanges {
			switch rc.Type {
			case "added":
				fmt.Fprintf(&b, "    + %s\n", rc.Rule)
			case "removed":
				fmt.Fprintf(&b, "    - %s\n", rc.Rule)
			case "changed":
				fmt.Fprintf(&b, "    ~ %s\n", rc.Rule)
			}
		}
	}

	if len(mapChanges) > 0 {
		b.WriteString("\n")
		for _, c := range mapChanges {
			switch c.Comment {
			case "added":
				fmt.Fprintf(&b, "  %s: + %s\n", c.Field, c.New)
			case "removed":
				fmt.Fprintf(&b, "  %s: - %s\n", c.Field, c.Old)
			}
		}
	}

	return b.String()
}

// FormatJSON renders the diff result as JSON.
func FormatJSON(r *DiffResult) (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal diff result: %w", err)
	}
	return string(data), nil
}

func filterChanges(changes []Change, prefixes ...string) []Change {
	var out []Change
	for _, c := range changes {
		for _, p := range prefixes {
			if strings.HasPrefix(c.Field, p) || c.Field == p {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

func filterTopLevel(changes []Change) []Change {
	var out []Change
	for _, c := range changes {
		if !strings.Contains(c.Field, ".") &&
			c.Field != "agents" && c.Field != "budgets" && c.Field != "rate_limits" {
			out = append(out, c)
		}
	}
	return out
}
