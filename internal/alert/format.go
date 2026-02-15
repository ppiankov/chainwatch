package alert

import (
	"encoding/json"
	"fmt"
)

// FormatPayload builds the webhook body for the given format.
func FormatPayload(format string, event AlertEvent) ([]byte, error) {
	switch format {
	case "slack":
		return formatSlack(event)
	case "pagerduty":
		return formatPagerDuty(event)
	default:
		return formatGeneric(event)
	}
}

func formatGeneric(event AlertEvent) ([]byte, error) {
	return json.Marshal(event)
}

func formatSlack(event AlertEvent) ([]byte, error) {
	tierLabel := tierLabelFor(event.Tier)

	payload := map[string]any{
		"blocks": []any{
			map[string]any{
				"type": "header",
				"text": map[string]any{
					"type": "plain_text",
					"text": fmt.Sprintf("chainwatch: %s", event.Decision),
				},
			},
			map[string]any{
				"type": "section",
				"fields": []any{
					map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*Tool:* %s", event.Tool)},
					map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*Resource:* %s", event.Resource)},
					map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*Tier:* %d (%s)", event.Tier, tierLabel)},
					map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*Reason:* %s", event.Reason)},
				},
			},
		},
	}
	return json.Marshal(payload)
}

func formatPagerDuty(event AlertEvent) ([]byte, error) {
	severity := "info"
	switch {
	case event.Tier >= 3:
		severity = "critical"
	case event.Tier >= 2:
		severity = "error"
	case event.Tier >= 1:
		severity = "warning"
	}

	payload := map[string]any{
		"event_action": "trigger",
		"payload": map[string]any{
			"summary":  fmt.Sprintf("chainwatch %s: %s", event.Decision, event.Resource),
			"severity": severity,
			"source":   "chainwatch",
			"custom_details": map[string]any{
				"tool":     event.Tool,
				"resource": event.Resource,
				"tier":     event.Tier,
				"reason":   event.Reason,
				"trace_id": event.TraceID,
			},
		},
	}
	return json.Marshal(payload)
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
