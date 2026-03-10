package observe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// allBuiltinTypes lists every built-in runbook type for loop tests.
var allBuiltinTypes = []string{
	"wordpress", "linux", "postfix", "postfix-inbound", "nginx", "mysql",
	"kubernetes", "prometheus", "cloud-infra",
	"aws-billing", "k8s-utilization", "cost-anomaly",
	"clickhouse", "clickhouse-config",
}

// scopedBuiltinTypes lists runbooks that investigate a target directory/namespace via {{SCOPE}}.
// Account-level runbooks (aws-billing, cost-anomaly) and server-level (clickhouse) use
// fixed endpoints rather than a scoped directory.
var scopedBuiltinTypes = []string{
	"wordpress", "linux", "postfix", "postfix-inbound", "nginx", "mysql",
	"kubernetes", "prometheus", "cloud-infra",
	"k8s-utilization",
}

func TestGetRunbookWordPress(t *testing.T) {
	for _, name := range []string{"wordpress", "wp"} {
		rb := GetRunbook(name)
		if rb.Type != "wordpress" {
			t.Errorf("GetRunbook(%q) type = %q, want wordpress", name, rb.Type)
		}
		if len(rb.Steps) < 8 {
			t.Errorf("WordPress runbook has %d steps, want at least 8", len(rb.Steps))
		}
	}
}

func TestGetRunbookLinux(t *testing.T) {
	for _, name := range []string{"linux", "system", "generic"} {
		rb := GetRunbook(name)
		if rb.Type != "linux" {
			t.Errorf("GetRunbook(%q) type = %q, want linux", name, rb.Type)
		}
		if len(rb.Steps) < 8 {
			t.Errorf("Linux runbook has %d steps, want at least 8", len(rb.Steps))
		}
	}
}

func TestGetRunbookPostfix(t *testing.T) {
	for _, name := range []string{"postfix", "mail"} {
		rb := GetRunbook(name)
		if rb.Type != "postfix" {
			t.Errorf("GetRunbook(%q) type = %q, want postfix", name, rb.Type)
		}
		if len(rb.Steps) < 8 {
			t.Errorf("Postfix runbook has %d steps, want at least 8", len(rb.Steps))
		}
	}
}

func TestGetRunbookNginx(t *testing.T) {
	for _, name := range []string{"nginx", "web"} {
		rb := GetRunbook(name)
		if rb.Type != "nginx" {
			t.Errorf("GetRunbook(%q) type = %q, want nginx", name, rb.Type)
		}
		if len(rb.Steps) < 8 {
			t.Errorf("Nginx runbook has %d steps, want at least 8", len(rb.Steps))
		}
	}
}

func TestGetRunbookMySQL(t *testing.T) {
	for _, name := range []string{"mysql", "mariadb", "db"} {
		rb := GetRunbook(name)
		if rb.Type != "mysql" {
			t.Errorf("GetRunbook(%q) type = %q, want mysql", name, rb.Type)
		}
		if len(rb.Steps) < 8 {
			t.Errorf("MySQL runbook has %d steps, want at least 8", len(rb.Steps))
		}
	}
}

func TestGetRunbookPostfixInbound(t *testing.T) {
	for _, name := range []string{"postfix-inbound", "inbound", "mail-trace"} {
		rb := GetRunbook(name)
		if rb.Type != "postfix-inbound" {
			t.Errorf("GetRunbook(%q) type = %q, want postfix-inbound", name, rb.Type)
		}
		if len(rb.Steps) < 5 {
			t.Errorf("Postfix inbound runbook has %d steps, want at least 5", len(rb.Steps))
		}
	}
}

func TestPostfixInboundHasQueryPlaceholder(t *testing.T) {
	rb := GetRunbook("postfix-inbound")
	hasQuery := false
	for _, step := range rb.Steps {
		if strings.Contains(step.Command, "{{QUERY}}") {
			hasQuery = true
			break
		}
	}
	if !hasQuery {
		t.Error("postfix-inbound runbook should contain {{QUERY}} placeholder")
	}
}

func TestGetRunbookUnknownFallsToLinux(t *testing.T) {
	rb := GetRunbook("unknown-service-xyz")
	if rb.Type != "linux" {
		t.Errorf("unknown type should fall back to linux, got %q", rb.Type)
	}
}

func TestGetRunbookEmptyFallsToLinux(t *testing.T) {
	rb := GetRunbook("")
	if rb.Type != "linux" {
		t.Errorf("empty type should fall back to linux, got %q", rb.Type)
	}
}

func TestBuiltinRunbooksHaveScopePlaceholder(t *testing.T) {
	// Runbooks that investigate a target directory/namespace should use {{SCOPE}}.
	for _, name := range scopedBuiltinTypes {
		rb := GetRunbook(name)
		hasScopePlaceholder := false
		for _, step := range rb.Steps {
			if strings.Contains(step.Command, "{{SCOPE}}") {
				hasScopePlaceholder = true
				break
			}
		}
		if !hasScopePlaceholder {
			t.Errorf("%s runbook should contain {{SCOPE}} placeholder", name)
		}
	}
}

func TestBuiltinRunbooksNoDestructiveCommands(t *testing.T) {
	for _, name := range allBuiltinTypes {
		rb := GetRunbook(name)
		for _, step := range rb.Steps {
			if err := checkDestructive(step); err != nil {
				t.Errorf("%s runbook: %v", name, err)
			}
		}
	}
}

func TestBuiltinRunbooksHavePurpose(t *testing.T) {
	for _, name := range allBuiltinTypes {
		rb := GetRunbook(name)
		for i, step := range rb.Steps {
			if step.Purpose == "" {
				t.Errorf("%s step %d has empty purpose", rb.Name, i)
			}
			if step.Command == "" {
				t.Errorf("%s step %d has empty command", rb.Name, i)
			}
		}
	}
}

func TestBuiltinRunbooksSource(t *testing.T) {
	rb := GetRunbook("linux")
	if rb.Source != "built-in" {
		t.Errorf("built-in runbook source = %q, want built-in", rb.Source)
	}
}

func TestListRunbooks(t *testing.T) {
	list := ListRunbooks()
	if len(list) < 14 {
		t.Errorf("ListRunbooks() returned %d runbooks, want at least 14", len(list))
	}

	types := make(map[string]bool)
	for _, info := range list {
		types[info.Type] = true
		if info.Name == "" {
			t.Errorf("runbook type %q has empty name", info.Type)
		}
		if info.Steps == 0 {
			t.Errorf("runbook type %q has 0 steps", info.Type)
		}
	}

	for _, expected := range allBuiltinTypes {
		if !types[expected] {
			t.Errorf("ListRunbooks() missing type %q", expected)
		}
	}
}

func TestValidateRunbookRejectsEmpty(t *testing.T) {
	tests := []struct {
		name string
		rb   Runbook
	}{
		{"no name", Runbook{Type: "x", Steps: []Step{{Command: "ls", Purpose: "list"}}}},
		{"no type", Runbook{Name: "x", Steps: []Step{{Command: "ls", Purpose: "list"}}}},
		{"no steps", Runbook{Name: "x", Type: "x"}},
		{"empty command", Runbook{Name: "x", Type: "x", Steps: []Step{{Purpose: "list"}}}},
		{"empty purpose", Runbook{Name: "x", Type: "x", Steps: []Step{{Command: "ls"}}}},
	}
	for _, tt := range tests {
		if err := ValidateRunbook(&tt.rb); err == nil {
			t.Errorf("ValidateRunbook(%s) should fail", tt.name)
		}
	}
}

func TestValidateRunbookRejectsDestructive(t *testing.T) {
	rb := Runbook{
		Name: "bad", Type: "bad",
		Steps: []Step{{Command: "rm -rf /tmp/x", Purpose: "destroy"}},
	}
	if err := ValidateRunbook(&rb); err == nil {
		t.Error("expected rejection for destructive command")
	}
}

func TestParseRunbookYAML(t *testing.T) {
	yaml := `
name: "Test runbook"
type: test
aliases: [t, testing]
steps:
  - command: "echo hello"
    purpose: "say hello"
  - command: "ls {{SCOPE}}"
    purpose: "list scope"
    cluster: true
`
	rb, err := ParseRunbook([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseRunbook failed: %v", err)
	}
	if rb.Name != "Test runbook" {
		t.Errorf("name = %q, want Test runbook", rb.Name)
	}
	if rb.Type != "test" {
		t.Errorf("type = %q, want test", rb.Type)
	}
	if len(rb.Aliases) != 2 {
		t.Errorf("aliases = %v, want [t testing]", rb.Aliases)
	}
	if len(rb.Steps) != 2 {
		t.Errorf("steps = %d, want 2", len(rb.Steps))
	}
	if rb.Steps[0].Cluster {
		t.Error("step 0 cluster = true, want false")
	}
	if !rb.Steps[1].Cluster {
		t.Error("step 1 cluster = false, want true")
	}
}

func TestParseRunbookYAMLRejectsInvalid(t *testing.T) {
	yaml := `name: ""`
	_, err := ParseRunbook([]byte(yaml))
	if err == nil {
		t.Error("expected error for invalid YAML runbook")
	}
}

func TestValidateRunbookSensitivity(t *testing.T) {
	base := Runbook{
		Name:  "test",
		Type:  "test",
		Steps: []Step{{Command: "echo hello", Purpose: "greet"}},
	}

	// Valid values: empty, "local", "any".
	for _, val := range []string{"", "local", "any"} {
		rb := base
		rb.Sensitivity = val
		if err := ValidateRunbook(&rb); err != nil {
			t.Errorf("ValidateRunbook with sensitivity=%q should pass, got: %v", val, err)
		}
	}

	// Invalid values should fail.
	for _, val := range []string{"cloud", "remote", "LOCAL", "high"} {
		rb := base
		rb.Sensitivity = val
		if err := ValidateRunbook(&rb); err == nil {
			t.Errorf("ValidateRunbook with sensitivity=%q should fail", val)
		}
	}
}

func TestPostfixInboundSensitivityLocal(t *testing.T) {
	rb := GetRunbook("postfix-inbound")
	if rb.Sensitivity != "local" {
		t.Errorf("postfix-inbound sensitivity = %q, want \"local\"", rb.Sensitivity)
	}
}

// --- SRE runbooks (CW65) ---

func TestGetRunbookKubernetes(t *testing.T) {
	for _, name := range []string{"kubernetes", "k8s", "kube"} {
		rb := GetRunbook(name)
		if rb.Type != "kubernetes" {
			t.Errorf("GetRunbook(%q) type = %q, want kubernetes", name, rb.Type)
		}
		if len(rb.Steps) < 8 {
			t.Errorf("Kubernetes runbook has %d steps, want at least 8", len(rb.Steps))
		}
	}
}

func TestGetRunbookPrometheus(t *testing.T) {
	for _, name := range []string{"prometheus", "prom", "metrics"} {
		rb := GetRunbook(name)
		if rb.Type != "prometheus" {
			t.Errorf("GetRunbook(%q) type = %q, want prometheus", name, rb.Type)
		}
		if len(rb.Steps) < 6 {
			t.Errorf("Prometheus runbook has %d steps, want at least 6", len(rb.Steps))
		}
	}
}

func TestPrometheusHasQueryPlaceholder(t *testing.T) {
	rb := GetRunbook("prometheus")
	hasQuery := false
	for _, step := range rb.Steps {
		if strings.Contains(step.Command, "{{QUERY}}") {
			hasQuery = true
			break
		}
	}
	if !hasQuery {
		t.Error("prometheus runbook should contain {{QUERY}} placeholder")
	}
}

func TestGetRunbookCloudInfra(t *testing.T) {
	for _, name := range []string{"cloud-infra", "aws", "cloud"} {
		rb := GetRunbook(name)
		if rb.Type != "cloud-infra" {
			t.Errorf("GetRunbook(%q) type = %q, want cloud-infra", name, rb.Type)
		}
		if len(rb.Steps) < 6 {
			t.Errorf("Cloud infra runbook has %d steps, want at least 6", len(rb.Steps))
		}
	}
}

// --- FinOps runbooks (CW67) ---

func TestGetRunbookAWSBilling(t *testing.T) {
	for _, name := range []string{"aws-billing", "billing", "cost", "finops"} {
		rb := GetRunbook(name)
		if rb.Type != "aws-billing" {
			t.Errorf("GetRunbook(%q) type = %q, want aws-billing", name, rb.Type)
		}
		if len(rb.Steps) < 6 {
			t.Errorf("AWS billing runbook has %d steps, want at least 6", len(rb.Steps))
		}
	}
}

func TestGetRunbookK8sUtilization(t *testing.T) {
	for _, name := range []string{"k8s-utilization", "k8s-cost", "k8s-resources", "utilization"} {
		rb := GetRunbook(name)
		if rb.Type != "k8s-utilization" {
			t.Errorf("GetRunbook(%q) type = %q, want k8s-utilization", name, rb.Type)
		}
		if len(rb.Steps) < 6 {
			t.Errorf("K8s utilization runbook has %d steps, want at least 6", len(rb.Steps))
		}
	}
}

func TestGetRunbookCostAnomaly(t *testing.T) {
	for _, name := range []string{"cost-anomaly", "spend-spike", "cost-spike"} {
		rb := GetRunbook(name)
		if rb.Type != "cost-anomaly" {
			t.Errorf("GetRunbook(%q) type = %q, want cost-anomaly", name, rb.Type)
		}
		if len(rb.Steps) < 5 {
			t.Errorf("Cost anomaly runbook has %d steps, want at least 5", len(rb.Steps))
		}
	}
}

// --- ClickHouse runbook (CW69) ---

func TestGetRunbookClickHouse(t *testing.T) {
	for _, name := range []string{"clickhouse", "ch", "clickhouse-server"} {
		rb := GetRunbook(name)
		if rb.Type != "clickhouse" {
			t.Errorf("GetRunbook(%q) type = %q, want clickhouse", name, rb.Type)
		}
		if len(rb.Steps) < 8 {
			t.Errorf("ClickHouse runbook has %d steps, want at least 8", len(rb.Steps))
		}
	}
}

func TestClickHouseSensitivityLocal(t *testing.T) {
	rb := GetRunbook("clickhouse")
	if rb.Sensitivity != "local" {
		t.Errorf("clickhouse sensitivity = %q, want \"local\"", rb.Sensitivity)
	}
}

func TestClickHouseClusterAwareSteps(t *testing.T) {
	rb := GetRunbook("clickhouse")

	requiredQueries := []string{
		"system.clusters",
		"system.distributed_ddl_queue",
		"replication_queue",
		"countIf(active) AS active_parts",
	}
	for _, query := range requiredQueries {
		found := false
		for _, step := range rb.Steps {
			if strings.Contains(step.Command, query) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("clickhouse runbook missing required cluster-aware query fragment: %q", query)
		}
	}

	clusterSteps := 0
	for _, step := range rb.Steps {
		if !step.Cluster {
			continue
		}
		clusterSteps++
		if !strings.Contains(step.Command, "system.clusters") &&
			!strings.Contains(step.Command, "system.distributed_ddl_queue") &&
			!strings.Contains(step.Command, "system.replication_queue") &&
			!strings.Contains(step.Command, "clusterAllReplicas") {
			t.Errorf("cluster step does not look cluster-specific: %q", step.Purpose)
		}
	}

	if clusterSteps < 4 {
		t.Errorf("clickhouse runbook has %d cluster-only steps, want at least 4", clusterSteps)
	}
}

func TestGetRunbookClickHouseConfig(t *testing.T) {
	rb := GetRunbook("clickhouse-config")
	if rb.Type != "clickhouse-config" {
		t.Fatalf("GetRunbook(clickhouse-config) type = %q, want clickhouse-config", rb.Type)
	}
	if rb.Sensitivity != "local" {
		t.Fatalf("clickhouse-config sensitivity = %q, want local", rb.Sensitivity)
	}
	if len(rb.Steps) < 3 {
		t.Fatalf("clickhouse-config has %d steps, want at least 3", len(rb.Steps))
	}
}

func TestClickHouseConfigHasRequiredPlaceholders(t *testing.T) {
	rb := GetRunbook("clickhouse-config")

	hasScope := false
	hasConfigRepo := false
	hasConfigPath := false

	for _, step := range rb.Steps {
		if strings.Contains(step.Command, "{{SCOPE}}") {
			hasScope = true
		}
		if strings.Contains(step.Command, "{{CONFIG_REPO}}") {
			hasConfigRepo = true
		}
		if strings.Contains(step.Command, "{{CONFIG_PATH}}") {
			hasConfigPath = true
		}
	}

	if !hasScope {
		t.Fatal("clickhouse-config runbook should contain {{SCOPE}}")
	}
	if !hasConfigRepo {
		t.Fatal("clickhouse-config runbook should contain {{CONFIG_REPO}}")
	}
	if !hasConfigPath {
		t.Fatal("clickhouse-config runbook should contain {{CONFIG_PATH}}")
	}
}

func TestUserRunbookOverride(t *testing.T) {
	// Create a temp directory to act as user runbook dir.
	dir := t.TempDir()
	customYAML := `
name: "Custom Linux"
type: linux
steps:
  - command: "echo custom"
    purpose: "custom step"
`
	path := filepath.Join(dir, "linux.yaml")
	if err := os.WriteFile(path, []byte(customYAML), 0600); err != nil {
		t.Fatal(err)
	}

	// Load directly from the temp path (simulates user override).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := ParseRunbook(data)
	if err != nil {
		t.Fatalf("ParseRunbook failed: %v", err)
	}
	if rb.Name != "Custom Linux" {
		t.Errorf("name = %q, want Custom Linux", rb.Name)
	}
	if len(rb.Steps) != 1 {
		t.Errorf("steps = %d, want 1", len(rb.Steps))
	}
}
