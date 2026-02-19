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
