package schedule

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ppiankov/chainwatch/internal/inventory"
)

func newTestInventory(t *testing.T, yaml string) *inventory.Inventory {
	t.Helper()
	inv, err := inventory.Parse([]byte(strings.TrimSpace(yaml)), t.TempDir())
	if err != nil {
		t.Fatalf("parse test inventory: %v", err)
	}
	return inv
}

const baseInventoryYAML = `
clickhouse:
  clusters:
    - name: prod
      hosts: [ch-01]
      config_repo: infra/clickhouse
`

func TestGenerateCrontabDefault(t *testing.T) {
	inv := newTestInventory(t, baseInventoryYAML)
	out := GenerateCrontab(inv)

	if !strings.Contains(out, "# chainwatch nullbot observe schedules") {
		t.Fatal("expected header comment")
	}
	if !strings.Contains(out, "# operational-check") {
		t.Fatal("expected operational-check schedule")
	}
	if !strings.Contains(out, "0 * * * * nullbot observe") {
		t.Fatal("expected hourly cron entry")
	}
	if !strings.Contains(out, "--types clickhouse,clickhouse-config") {
		t.Fatal("expected types flag for operational-check")
	}
	if !strings.Contains(out, "# drift-detection") {
		t.Fatal("expected drift-detection schedule")
	}
	if !strings.Contains(out, "# full-investigation") {
		t.Fatal("expected full-investigation schedule")
	}
	// full-investigation has no types, so no --types flag
	if strings.Contains(out, "full-investigation\n0 3 * * * nullbot observe --inventory inventory.yaml --types") {
		t.Fatal("full-investigation should not have --types flag")
	}
	if !strings.Contains(out, "| orchestrator dispatch") {
		t.Fatal("expected pipe to orchestrator dispatch")
	}
}

func TestGenerateCrontabCustomSchedules(t *testing.T) {
	yaml := `
clickhouse:
  clusters:
    - name: prod
      hosts: [ch-01]
      config_repo: infra/clickhouse
schedules:
  - name: hourly-check
    types: [clickhouse]
    interval: "0 * * * *"
    enabled: true
  - name: disabled-check
    types: [clickhouse]
    interval: "0 6 * * *"
    enabled: false
`
	inv := newTestInventory(t, yaml)
	out := GenerateCrontab(inv)

	if !strings.Contains(out, "# hourly-check") {
		t.Fatal("expected hourly-check")
	}
	if strings.Contains(out, "disabled-check") {
		t.Fatal("disabled schedule should not appear in crontab")
	}
}

func TestGenerateSystemdTimersDefault(t *testing.T) {
	inv := newTestInventory(t, baseInventoryYAML)
	units := GenerateSystemdTimers(inv)

	if len(units) != 3 {
		t.Fatalf("expected 3 systemd units, got %d", len(units))
	}

	op := units[0]
	if op.Name != "nullbot-operational-check" {
		t.Fatalf("unit name = %q, want nullbot-operational-check", op.Name)
	}
	if !strings.Contains(op.Timer, "[Timer]") {
		t.Fatal("expected [Timer] section")
	}
	if !strings.Contains(op.Timer, "OnCalendar=") {
		t.Fatal("expected OnCalendar directive")
	}
	if !strings.Contains(op.Timer, "Persistent=true") {
		t.Fatal("expected Persistent=true")
	}
	if !strings.Contains(op.Service, "[Service]") {
		t.Fatal("expected [Service] section")
	}
	if !strings.Contains(op.Service, "Type=oneshot") {
		t.Fatal("expected Type=oneshot")
	}
	if !strings.Contains(op.Service, "nullbot observe") {
		t.Fatal("expected nullbot observe command in service")
	}
	if !strings.Contains(op.Service, "--types clickhouse,clickhouse-config") {
		t.Fatal("expected types in service ExecStart")
	}
}

func TestGenerateEventBridgeRulesDefault(t *testing.T) {
	inv := newTestInventory(t, baseInventoryYAML)
	rules := GenerateEventBridgeRules(inv)

	if len(rules) != 3 {
		t.Fatalf("expected 3 EventBridge rules, got %d", len(rules))
	}

	r := rules[0]
	if r.Name != "nullbot-operational-check" {
		t.Fatalf("rule name = %q, want nullbot-operational-check", r.Name)
	}
	if !strings.HasPrefix(r.ScheduleExpression, "cron(") {
		t.Fatalf("schedule expression = %q, want cron(...)", r.ScheduleExpression)
	}
	if r.Target.Arn != "<LAMBDA_ARN>" {
		t.Fatalf("target ARN = %q, want placeholder", r.Target.Arn)
	}

	// Verify target input is valid JSON with command key.
	var payload map[string]string
	if err := json.Unmarshal([]byte(r.Target.Input), &payload); err != nil {
		t.Fatalf("target input is not valid JSON: %v", err)
	}
	if _, ok := payload["command"]; !ok {
		t.Fatal("target input missing 'command' key")
	}
	if !strings.Contains(payload["command"], "nullbot observe") {
		t.Fatal("command should contain nullbot observe")
	}
}

func TestDefaultSchedules(t *testing.T) {
	defaults := inventory.DefaultSchedules()
	if len(defaults) != 3 {
		t.Fatalf("expected 3 default schedules, got %d", len(defaults))
	}

	names := make(map[string]bool)
	for _, s := range defaults {
		names[s.Name] = true
		if !s.Enabled {
			t.Fatalf("default schedule %q should be enabled", s.Name)
		}
		if s.Interval == "" {
			t.Fatalf("default schedule %q has empty interval", s.Name)
		}
	}

	for _, expected := range []string{"operational-check", "drift-detection", "full-investigation"} {
		if !names[expected] {
			t.Fatalf("missing default schedule %q", expected)
		}
	}
}

func TestEmptySchedules(t *testing.T) {
	// Create inventory with explicit empty schedules list.
	yaml := `
clickhouse:
  clusters:
    - name: prod
      hosts: [ch-01]
      config_repo: infra/clickhouse
schedules:
  - name: only-one
    types: [clickhouse]
    interval: "0 * * * *"
    enabled: false
`
	inv := newTestInventory(t, yaml)

	// All disabled — should produce empty output.
	if out := GenerateCrontab(inv); out != "" {
		t.Fatalf("expected empty crontab for all-disabled schedules, got:\n%s", out)
	}
	if units := GenerateSystemdTimers(inv); len(units) != 0 {
		t.Fatalf("expected 0 systemd units, got %d", len(units))
	}
	if rules := GenerateEventBridgeRules(inv); len(rules) != 0 {
		t.Fatalf("expected 0 EventBridge rules, got %d", len(rules))
	}
}

func TestCronToCalendar(t *testing.T) {
	tests := []struct {
		cron string
		want string
	}{
		{"0 * * * *", "*-*-* *:0:00"},
		{"0 3 * * *", "*-*-* 3:0:00"},
		{"0 */6 * * *", "*-*-* */6:0:00"},
		{"0 9 * * 1-5", "Mon..Fri *-*-* 9:0:00"},
	}

	for _, tt := range tests {
		got := cronToCalendar(tt.cron)
		if got != tt.want {
			t.Errorf("cronToCalendar(%q) = %q, want %q", tt.cron, got, tt.want)
		}
	}
}
