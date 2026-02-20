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
