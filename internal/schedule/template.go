package schedule

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ppiankov/chainwatch/internal/inventory"
)

const (
	defaultNullbotBin    = "nullbot"
	defaultInventoryPath = "inventory.yaml"
	defaultOutputFormat  = "wo"
)

// SystemdUnit holds a paired timer and service unit file.
type SystemdUnit struct {
	Name    string
	Timer   string
	Service string
}

// EventBridgeRule holds an AWS EventBridge rule definition.
type EventBridgeRule struct {
	Name               string            `json:"name"`
	ScheduleExpression string            `json:"schedule_expression"`
	Description        string            `json:"description"`
	Target             EventBridgeTarget `json:"target"`
}

// EventBridgeTarget is the target for an EventBridge rule.
type EventBridgeTarget struct {
	Arn   string `json:"arn"`
	Input string `json:"input"`
}

// GenerateCrontab produces crontab entries from inventory schedules.
func GenerateCrontab(inv *inventory.Inventory) string {
	schedules := enabledSchedules(inv)
	if len(schedules) == 0 {
		return ""
	}

	invPath := inventoryPath(inv)
	var lines []string
	lines = append(lines, "# chainwatch nullbot observe schedules")
	lines = append(lines, fmt.Sprintf("# Generated from %s", invPath))
	lines = append(lines, "")

	for _, sched := range schedules {
		typesFlag := typesArg(sched)
		cmd := fmt.Sprintf(
			"%s observe --inventory %s%s --format %s | orchestrator dispatch --inventory %s",
			defaultNullbotBin, invPath, typesFlag, defaultOutputFormat, invPath,
		)
		lines = append(lines, fmt.Sprintf("# %s", sched.Name))
		lines = append(lines, fmt.Sprintf("%s %s", sched.Interval, cmd))
	}

	return strings.Join(lines, "\n") + "\n"
}

// GenerateSystemdTimers produces systemd timer+service unit pairs.
func GenerateSystemdTimers(inv *inventory.Inventory) []SystemdUnit {
	schedules := enabledSchedules(inv)
	if len(schedules) == 0 {
		return nil
	}

	invPath := inventoryPath(inv)
	units := make([]SystemdUnit, 0, len(schedules))

	for _, sched := range schedules {
		unitName := fmt.Sprintf("nullbot-%s", sched.Name)
		typesFlag := typesArg(sched)

		timer := fmt.Sprintf(`[Unit]
Description=nullbot %s timer

[Timer]
OnCalendar=%s
Persistent=true

[Install]
WantedBy=timers.target
`, sched.Name, cronToCalendar(sched.Interval))

		service := fmt.Sprintf(`[Unit]
Description=nullbot %s

[Service]
Type=oneshot
ExecStart=/bin/sh -c '%s observe --inventory %s%s --format %s | orchestrator dispatch --inventory %s'
`, sched.Name, defaultNullbotBin, invPath, typesFlag, defaultOutputFormat, invPath)

		units = append(units, SystemdUnit{
			Name:    unitName,
			Timer:   timer,
			Service: service,
		})
	}

	return units
}

// GenerateEventBridgeRules produces AWS EventBridge rule definitions.
func GenerateEventBridgeRules(inv *inventory.Inventory) []EventBridgeRule {
	schedules := enabledSchedules(inv)
	if len(schedules) == 0 {
		return nil
	}

	invPath := inventoryPath(inv)
	rules := make([]EventBridgeRule, 0, len(schedules))

	for _, sched := range schedules {
		typesFlag := typesArg(sched)
		cmd := fmt.Sprintf(
			"%s observe --inventory %s%s --format %s",
			defaultNullbotBin, invPath, typesFlag, defaultOutputFormat,
		)

		inputPayload, _ := json.Marshal(map[string]string{
			"command": cmd,
		})

		rules = append(rules, EventBridgeRule{
			Name:               fmt.Sprintf("nullbot-%s", sched.Name),
			ScheduleExpression: fmt.Sprintf("cron(%s)", sched.Interval),
			Description:        fmt.Sprintf("nullbot %s schedule", sched.Name),
			Target: EventBridgeTarget{
				Arn:   "<LAMBDA_ARN>",
				Input: string(inputPayload),
			},
		})
	}

	return rules
}

func enabledSchedules(inv *inventory.Inventory) []inventory.Schedule {
	var out []inventory.Schedule
	for _, s := range inv.Schedules {
		if s.Enabled {
			out = append(out, s)
		}
	}
	return out
}

func inventoryPath(inv *inventory.Inventory) string {
	if p := inv.Path(); p != "" {
		return p
	}
	return defaultInventoryPath
}

func typesArg(sched inventory.Schedule) string {
	if len(sched.Types) == 0 {
		return ""
	}
	return fmt.Sprintf(" --types %s", strings.Join(sched.Types, ","))
}

// cronToCalendar converts a 5-field cron expression to a systemd OnCalendar
// approximation. This is a best-effort conversion for template generation.
func cronToCalendar(cron string) string {
	fields := strings.Fields(cron)
	if len(fields) != 5 {
		return cron
	}

	minute, hour, dom, month, dow := fields[0], fields[1], fields[2], fields[3], fields[4]

	// Map day-of-week cron values to systemd abbreviations.
	dowMap := map[string]string{
		"0": "Sun", "1": "Mon", "2": "Tue", "3": "Wed",
		"4": "Thu", "5": "Fri", "6": "Sat", "7": "Sun",
	}

	dowPart := "*"
	if dow != "*" {
		var parts []string
		for _, segment := range strings.Split(dow, ",") {
			if ranged := strings.Split(segment, "-"); len(ranged) == 2 {
				from, ok1 := dowMap[ranged[0]]
				to, ok2 := dowMap[ranged[1]]
				if ok1 && ok2 {
					parts = append(parts, from+".."+to)
				} else {
					parts = append(parts, segment)
				}
			} else if mapped, ok := dowMap[segment]; ok {
				parts = append(parts, mapped)
			} else {
				parts = append(parts, segment)
			}
		}
		dowPart = strings.Join(parts, ",")
	}

	datePart := ""
	if dom != "*" || month != "*" {
		monthStr := month
		if monthStr == "*" {
			monthStr = "*"
		}
		datePart = fmt.Sprintf("%s-%s-%s", "*", monthStr, dom)
	} else {
		datePart = "*-*-*"
	}

	hourStr := hour
	if hourStr == "*" {
		hourStr = "*"
	}
	minuteStr := minute
	if minuteStr == "*" {
		minuteStr = "*"
	}

	// Handle */N interval syntax.
	if strings.HasPrefix(hour, "*/") {
		// Keep as-is for the template; systemd doesn't natively support */N
		// but it's useful as a human-readable approximation.
	}

	if dowPart != "*" {
		return fmt.Sprintf("%s %s %s:%s:00", dowPart, datePart, hourStr, minuteStr)
	}
	return fmt.Sprintf("%s %s:%s:00", datePart, hourStr, minuteStr)
}
