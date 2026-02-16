package scenario

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FormatText renders a list of run results as human-readable text.
func FormatText(results []*RunResult) string {
	var b strings.Builder

	totalFiles := len(results)
	fmt.Fprintf(&b, "Checking %d scenario file", totalFiles)
	if totalFiles != 1 {
		b.WriteString("s")
	}
	b.WriteString("...\n\n")

	totalCases := 0
	totalPassed := 0
	failedScenarios := 0

	for _, r := range results {
		totalCases += r.Total
		totalPassed += r.Passed

		if r.Failed == 0 {
			fmt.Fprintf(&b, "  PASS  %s (%d/%d)\n", r.Name, r.Passed, r.Total)
		} else {
			failedScenarios++
			fmt.Fprintf(&b, "  FAIL  %s (%d/%d)\n", r.Name, r.Passed, r.Total)
			for _, c := range r.Cases {
				if !c.Passed {
					resource := c.Resource
					if len(resource) > 40 {
						resource = resource[:37] + "..."
					}
					fmt.Fprintf(&b, "    FAIL  case %d: %-12s %-40s expected %s, got %s\n",
						c.Index, c.Tool, resource, c.Expected, c.Actual)
				}
			}
		}
	}

	fmt.Fprintf(&b, "\n%d of %d cases passed.", totalPassed, totalCases)
	if failedScenarios > 0 {
		fmt.Fprintf(&b, " %d of %d scenarios failed.", failedScenarios, totalFiles)
	}
	b.WriteString("\n")

	return b.String()
}

// FormatJSON renders run results as JSON.
func FormatJSON(results []*RunResult) (string, error) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal results: %w", err)
	}
	return string(data), nil
}
