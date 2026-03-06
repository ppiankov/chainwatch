package observe

import (
	"strings"
	"testing"

	"github.com/ppiankov/chainwatch/internal/wo"
)

func TestCollectEvidence(t *testing.T) {
	result := &RunResult{
		Steps: []StepResult{
			{Command: "uname -a", Purpose: "identify system", Output: "Linux prod 5.15.0", ExitCode: 0},
			{Command: "rm -rf /", Purpose: "blocked by policy", Output: "", ExitCode: 77, Blocked: true},
			{Command: "ps aux", Purpose: "list processes", Output: "root 1 init\nnginx 42 nginx", ExitCode: 0},
			{Command: "cat /empty", Purpose: "empty output", Output: "", ExitCode: 0},
		},
	}

	evidence := CollectEvidence(result)

	// Should include non-blocked, non-empty steps.
	if !strings.Contains(evidence, "Linux prod 5.15.0") {
		t.Error("evidence should contain uname output")
	}
	if !strings.Contains(evidence, "nginx 42 nginx") {
		t.Error("evidence should contain ps output")
	}

	// Should NOT include blocked step.
	if strings.Contains(evidence, "rm -rf") {
		t.Error("evidence should not contain blocked command output")
	}

	// Should NOT include empty output.
	if strings.Contains(evidence, "empty output") {
		t.Error("evidence should not contain empty output step")
	}

	// Should have structured headers.
	if !strings.Contains(evidence, "=== identify system ===") {
		t.Error("evidence should have structured headers")
	}
}

func TestCollectEvidenceEmpty(t *testing.T) {
	result := &RunResult{}
	evidence := CollectEvidence(result)
	if evidence != "" {
		t.Errorf("empty result should produce empty evidence, got: %q", evidence)
	}
}

func TestCollectEvidenceAllBlocked(t *testing.T) {
	result := &RunResult{
		Steps: []StepResult{
			{Command: "cat /etc/shadow", Purpose: "blocked", Output: "denied", ExitCode: 77, Blocked: true},
		},
	}
	evidence := CollectEvidence(result)
	if evidence != "" {
		t.Error("all-blocked result should produce empty evidence")
	}
}

func TestInspectProfileIsClawbot(t *testing.T) {
	// Structural guarantee: observe mode always uses the clawbot profile.
	// If this test fails, someone tried to change the hard-locked profile.
	if inspectProfile != "clawbot" {
		t.Fatalf("inspectProfile = %q, must be \"clawbot\" — observe mode is inspect-only", inspectProfile)
	}
}

func TestRunnerConfigHasNoProfileField(t *testing.T) {
	// Structural guarantee: RunnerConfig does not accept a profile override.
	// This test documents the invariant. The compiler enforces it — if someone
	// adds a Profile field and sets it, this test forces a conversation about why.
	cfg := RunnerConfig{
		Scope:      "/var/www/site",
		Chainwatch: "chainwatch",
		AuditLog:   "/tmp/test.jsonl",
	}
	// If RunnerConfig gains a Profile field, this test must be updated with
	// justification for why observe mode needs a configurable profile.
	_ = cfg
}

func TestRunMultiMergesSteps(t *testing.T) {
	// RunMulti should merge steps from both runbooks.
	cfg := RunnerConfig{
		Scope:      "/tmp/test",
		Chainwatch: "/nonexistent/chainwatch",
		AuditLog:   "/tmp/test-multi.jsonl",
	}

	// Use real runbook types; steps will fail (chainwatch binary missing) but merge correctly.
	rbLinux := GetRunbook("linux")
	rbNginx := GetRunbook("nginx")
	expectedSteps := len(rbLinux.Steps) + len(rbNginx.Steps)

	result, err := RunMulti(cfg, []string{"linux", "nginx"})
	if err != nil {
		t.Fatalf("RunMulti returned error: %v", err)
	}

	if len(result.Steps) != expectedSteps {
		t.Fatalf("expected %d merged steps, got %d", expectedSteps, len(result.Steps))
	}
}

func TestRunMultiTypeField(t *testing.T) {
	cfg := RunnerConfig{
		Scope:      "/tmp/test",
		Chainwatch: "/nonexistent/chainwatch",
		AuditLog:   "/tmp/test-multi.jsonl",
	}

	result, err := RunMulti(cfg, []string{"linux", "wordpress"})
	if err != nil {
		t.Fatalf("RunMulti returned error: %v", err)
	}

	if result.Type != "linux+wordpress" {
		t.Errorf("expected type 'linux+wordpress', got %q", result.Type)
	}
}

func TestRunnerConfigTypesField(t *testing.T) {
	// Verify Types field exists and is usable.
	cfg := RunnerConfig{
		Scope: "/tmp/test",
		Types: []string{"kubernetes", "prometheus"},
	}
	if len(cfg.Types) != 2 {
		t.Fatalf("expected 2 types, got %d", len(cfg.Types))
	}
}

func TestRunSkipsClusterOnlySteps(t *testing.T) {
	rb := &Runbook{
		Name: "cluster-gated",
		Type: "test",
		Steps: []Step{
			{Command: "echo base", Purpose: "base step"},
			{Command: "echo cluster", Purpose: "cluster step", Cluster: true},
		},
	}

	result, err := Run(RunnerConfig{
		Scope:      "/tmp/test",
		Chainwatch: "/nonexistent/chainwatch",
		AuditLog:   "/tmp/test-cluster-skip.jsonl",
	}, rb)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(result.Steps) != 1 {
		t.Fatalf("expected 1 executed step when cluster mode is disabled, got %d", len(result.Steps))
	}
	if result.Steps[0].Purpose != "base step" {
		t.Fatalf("expected base step to run, got %q", result.Steps[0].Purpose)
	}
}

func TestRunIncludesClusterOnlyStepsWhenEnabled(t *testing.T) {
	rb := &Runbook{
		Name: "cluster-enabled",
		Type: "test",
		Steps: []Step{
			{Command: "echo base", Purpose: "base step"},
			{Command: "echo cluster", Purpose: "cluster step", Cluster: true},
		},
	}

	result, err := Run(RunnerConfig{
		Scope:      "/tmp/test",
		Cluster:    true,
		Chainwatch: "/nonexistent/chainwatch",
		AuditLog:   "/tmp/test-cluster-enable.jsonl",
	}, rb)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(result.Steps) != 2 {
		t.Fatalf("expected 2 executed steps when cluster mode is enabled, got %d", len(result.Steps))
	}
}

func TestRunMultiPropagatesClusterMode(t *testing.T) {
	clickhouse := GetRunbook("clickhouse")
	clusterOnly := 0
	for _, step := range clickhouse.Steps {
		if step.Cluster {
			clusterOnly++
		}
	}
	if clusterOnly == 0 {
		t.Fatal("clickhouse runbook should include cluster-only steps")
	}

	baseCount := len(clickhouse.Steps) - clusterOnly

	withoutCluster, err := RunMulti(RunnerConfig{
		Scope:      "/tmp/test",
		Chainwatch: "/nonexistent/chainwatch",
		AuditLog:   "/tmp/test-cluster-multi-off.jsonl",
	}, []string{"clickhouse"})
	if err != nil {
		t.Fatalf("RunMulti without cluster mode returned error: %v", err)
	}
	if len(withoutCluster.Steps) != baseCount {
		t.Fatalf("expected %d steps without cluster mode, got %d", baseCount, len(withoutCluster.Steps))
	}

	withCluster, err := RunMulti(RunnerConfig{
		Scope:      "/tmp/test",
		Cluster:    true,
		Chainwatch: "/nonexistent/chainwatch",
		AuditLog:   "/tmp/test-cluster-multi-on.jsonl",
	}, []string{"clickhouse"})
	if err != nil {
		t.Fatalf("RunMulti with cluster mode returned error: %v", err)
	}
	if len(withCluster.Steps) != len(clickhouse.Steps) {
		t.Fatalf("expected %d steps with cluster mode, got %d", len(clickhouse.Steps), len(withCluster.Steps))
	}
}

func TestRunExpandsInventoryParamsAndMetadata(t *testing.T) {
	rb := &Runbook{
		Name: "inventory",
		Type: "inventory",
		Steps: []Step{
			{
				Command: "echo {{SCOPE}} {{CLUSTER}} {{HOST}} {{SSH_USER}} {{CLICKHOUSE_PORT}} {{CONFIG_REPO}} {{CONFIG_PATH}}",
				Purpose: "expand inventory placeholders",
			},
		},
	}

	result, err := Run(RunnerConfig{
		Scope:       "/var/lib/clickhouse",
		ClusterName: "dev-analytics",
		Host:        "ch-dev-01",
		SSHUser:     "nullbot",
		Port:        9000,
		ConfigRepo:  "/tmp/infra/analytics",
		ConfigPath:  "/tmp/infra/analytics/config/users.d",
		Chainwatch:  "/nonexistent/chainwatch",
		AuditLog:    "/tmp/test-inventory-params.jsonl",
	}, rb)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(result.Steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(result.Steps))
	}

	expectedCmd := "echo /var/lib/clickhouse dev-analytics ch-dev-01 nullbot 9000 /tmp/infra/analytics /tmp/infra/analytics/config/users.d"
	if result.Steps[0].Command != expectedCmd {
		t.Fatalf("expanded command = %q, want %q", result.Steps[0].Command, expectedCmd)
	}
	if result.Steps[0].Cluster != "dev-analytics" {
		t.Fatalf("step cluster = %q, want dev-analytics", result.Steps[0].Cluster)
	}
	if result.Steps[0].Host != "ch-dev-01" {
		t.Fatalf("step host = %q, want ch-dev-01", result.Steps[0].Host)
	}
}

func TestManualObservation(t *testing.T) {
	obs := ManualObservation(wo.SuspiciousCode, wo.SeverityHigh, "eval(base64_decode in header.php")
	if obs.Type != wo.SuspiciousCode {
		t.Errorf("type: got %s, want suspicious_code", obs.Type)
	}
	if obs.Severity != wo.SeverityHigh {
		t.Errorf("severity: got %s, want high", obs.Severity)
	}
	if obs.Detail != "eval(base64_decode in header.php" {
		t.Errorf("detail mismatch: %s", obs.Detail)
	}
}
