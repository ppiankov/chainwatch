package certify

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FormatText renders a certification result as human-readable text.
func FormatText(r *CertResult) string {
	var b strings.Builder

	header := fmt.Sprintf("Certification: %s v%s — Profile: %s", r.Suite, r.Version, r.Profile)
	fmt.Fprintln(&b, header)
	fmt.Fprintln(&b, strings.Repeat("═", len(header)))

	for _, cat := range r.Categories {
		status := "PASS"
		if cat.Failed > 0 {
			status = "FAIL"
		}
		fmt.Fprintf(&b, "  %-30s %d/%-4d %s\n", cat.Name, cat.Passed, cat.Total, status)

		if cat.Failed > 0 {
			for _, c := range cat.Cases {
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

	fmt.Fprintln(&b, strings.Repeat("─", len(header)))

	status := "PASS"
	if r.Failed > 0 {
		status = "FAIL"
	}
	fmt.Fprintf(&b, "Result: %s (%d/%d)\n", status, r.Passed, r.Total)

	return b.String()
}

// FormatJSON renders a certification result as JSON.
func FormatJSON(r *CertResult) (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal cert result: %w", err)
	}
	return string(data), nil
}
