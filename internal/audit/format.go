package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const separator = "──────────────────────────────────────────────────────────────────"

// FormatTimeline renders a ReplayResult as a human-readable text timeline.
func FormatTimeline(result *ReplayResult) string {
	if len(result.Entries) == 0 {
		return fmt.Sprintf("Trace: %s | No entries found.\n", result.TraceID)
	}

	var b strings.Builder

	// Header
	first := result.Summary.FirstTimestamp
	last := result.Summary.LastTimestamp
	firstTime := formatDateRange(first)
	lastTime := formatTimeOnly(last)
	b.WriteString(fmt.Sprintf("Trace: %s | %s–%s UTC\n", result.TraceID, firstTime, lastTime))
	b.WriteString(separator + "\n")

	// Entries
	for _, e := range result.Entries {
		ts := formatTimeOnly(e.Timestamp)
		tier := fmt.Sprintf("T%d", e.Tier)
		decision := strings.ToUpper(e.Decision)
		tool := truncate(e.Action.Tool, 12)
		resource := truncate(e.Action.Resource, 40)

		tag := ""
		if e.Type == "break_glass_used" {
			tag = "  [break-glass]"
		}

		b.WriteString(fmt.Sprintf("%-10s %-3s %-18s %-13s %-40s%s\n",
			ts, tier, decision, tool, resource, tag))
	}

	// Footer
	b.WriteString(separator + "\n")
	b.WriteString(formatSummary(result.Summary))

	return b.String()
}

// FormatJSON renders a ReplayResult as indented JSON.
func FormatJSON(result *ReplayResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal replay result: %w", err)
	}
	return string(data), nil
}

func formatDateRange(ts string) string {
	t, err := time.Parse(TimestampFormat, ts)
	if err != nil {
		return ts
	}
	return t.Format("2006-01-02 15:04:05")
}

func formatTimeOnly(ts string) string {
	t, err := time.Parse(TimestampFormat, ts)
	if err != nil {
		return ts
	}
	return t.Format("15:04:05")
}

func formatSummary(s ReplaySummary) string {
	parts := []string{}
	if s.AllowCount > 0 {
		parts = append(parts, fmt.Sprintf("%d allow", s.AllowCount))
	}
	if s.DenyCount > 0 {
		parts = append(parts, fmt.Sprintf("%d deny", s.DenyCount))
	}
	if s.ApprovalCount > 0 {
		parts = append(parts, fmt.Sprintf("%d approval", s.ApprovalCount))
	}
	if s.RedactCount > 0 {
		parts = append(parts, fmt.Sprintf("%d redact", s.RedactCount))
	}
	if s.BreakGlassCount > 0 {
		parts = append(parts, fmt.Sprintf("%d break-glass", s.BreakGlassCount))
	}

	tierLabel := tierLabelFor(s.MaxTier)
	return fmt.Sprintf("Summary: %s | Max tier: %d (%s)\n",
		strings.Join(parts, ", "), s.MaxTier, tierLabel)
}

func tierLabelFor(tier int) string {
	switch tier {
	case 0:
		return "safe"
	case 1:
		return "elevated"
	case 2:
		return "guarded"
	case 3:
		return "critical"
	default:
		return "unknown"
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
