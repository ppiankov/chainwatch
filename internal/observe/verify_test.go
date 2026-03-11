package observe

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestVerifyDriftResolved(t *testing.T) {
	originalEvidence := "replication lag detected"
	originalHash := hashVerifyEvidence("echo fixed", "check drift", originalEvidence)

	result, err := VerifyWithRunner(context.Background(), VerifyConfig{
		WOID:                "wo-verify-1",
		RunnerConfig:        RunnerConfig{Scope: "/var/lib/clickhouse", Type: "clickhouse"},
		OriginalFindingHash: originalHash,
		MaxRetries:          1,
		RetryDelay:          time.Nanosecond,
	}, func(context.Context, RunnerConfig) (*RunResult, error) {
		return &RunResult{
			Steps: []StepResult{{
				Command: "echo fixed",
				Purpose: "check drift",
				Output:  "replication healthy",
			}},
		}, nil
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("Passed = false, want true")
	}
	if result.Attempt != 1 {
		t.Fatalf("Attempt = %d, want 1", result.Attempt)
	}
	if result.CurrentHash == originalHash {
		t.Fatal("CurrentHash should differ from original hash")
	}
	if !strings.Contains(result.Detail, "no longer") {
		t.Fatalf("Detail = %q, want resolution detail", result.Detail)
	}
}

func TestVerifyDriftPersists(t *testing.T) {
	originalEvidence := "replication lag detected"
	originalHash := hashVerifyEvidence("echo still-bad", "check drift", originalEvidence)
	attempts := 0

	result, err := VerifyWithRunner(context.Background(), VerifyConfig{
		WOID:                "wo-verify-2",
		RunnerConfig:        RunnerConfig{Scope: "/var/lib/clickhouse", Type: "clickhouse"},
		OriginalFindingHash: originalHash,
		MaxRetries:          1,
		RetryDelay:          time.Nanosecond,
	}, func(context.Context, RunnerConfig) (*RunResult, error) {
		attempts++
		return &RunResult{
			Steps: []StepResult{{
				Command: "echo still-bad",
				Purpose: "check drift",
				Output:  originalEvidence,
			}},
		}, nil
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Passed {
		t.Fatalf("Passed = true, want false")
	}
	if result.Attempt != 2 {
		t.Fatalf("Attempt = %d, want 2", result.Attempt)
	}
	if attempts != 2 {
		t.Fatalf("runner attempts = %d, want 2", attempts)
	}
	if result.CurrentHash != originalHash {
		t.Fatalf("CurrentHash = %q, want %q", result.CurrentHash, originalHash)
	}
	if !strings.Contains(result.Detail, "persists") {
		t.Fatalf("Detail = %q, want persistence detail", result.Detail)
	}
}

func TestVerifyRetry(t *testing.T) {
	originalEvidence := "ttl missing on events"
	originalHash := hashVerifyEvidence("echo verify", "check drift", originalEvidence)
	attempts := 0

	result, err := VerifyWithRunner(context.Background(), VerifyConfig{
		WOID:                "wo-verify-3",
		RunnerConfig:        RunnerConfig{Scope: "/var/lib/clickhouse", Type: "clickhouse"},
		OriginalFindingHash: originalHash,
		MaxRetries:          1,
		RetryDelay:          time.Nanosecond,
	}, func(context.Context, RunnerConfig) (*RunResult, error) {
		attempts++
		output := originalEvidence
		if attempts == 2 {
			output = "ttl present on events"
		}
		return &RunResult{
			Steps: []StepResult{{
				Command: "echo verify",
				Purpose: "check drift",
				Output:  output,
			}},
		}, nil
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("Passed = false, want true")
	}
	if result.Attempt != 2 {
		t.Fatalf("Attempt = %d, want 2", result.Attempt)
	}
	if attempts != 2 {
		t.Fatalf("runner attempts = %d, want 2", attempts)
	}
}

func TestVerifyHashComparison(t *testing.T) {
	hashA := ComputeEvidenceHash("evidence-a")
	hashARepeat := ComputeEvidenceHash("evidence-a")
	hashB := ComputeEvidenceHash("evidence-b")

	if hashA != hashARepeat {
		t.Fatalf("hashA = %q, want stable repeat %q", hashA, hashARepeat)
	}
	if hashA == hashB {
		t.Fatalf("hashA = %q, hashB = %q, want different hashes", hashA, hashB)
	}
}

func TestVerifyEmptyEvidence(t *testing.T) {
	originalHash := hashVerifyEvidence("echo empty", "check drift", "finding existed before remediation")

	result, err := VerifyWithRunner(context.Background(), VerifyConfig{
		WOID:                "wo-verify-4",
		RunnerConfig:        RunnerConfig{Scope: "/var/lib/clickhouse", Type: "clickhouse"},
		OriginalFindingHash: originalHash,
		MaxRetries:          1,
		RetryDelay:          time.Nanosecond,
	}, func(context.Context, RunnerConfig) (*RunResult, error) {
		return &RunResult{
			Steps: []StepResult{{
				Command: "echo empty",
				Purpose: "check drift",
				Output:  "",
			}},
		}, nil
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("Passed = false, want true")
	}
	if got, want := result.CurrentHash, ComputeEvidenceHash(""); got != want {
		t.Fatalf("CurrentHash = %q, want %q", got, want)
	}
	if !strings.Contains(result.Detail, "no evidence") {
		t.Fatalf("Detail = %q, want empty evidence detail", result.Detail)
	}
}

func hashVerifyEvidence(command string, purpose string, output string) string {
	return ComputeEvidenceHash(CollectEvidence(&RunResult{
		Steps: []StepResult{{
			Command: command,
			Purpose: purpose,
			Output:  output,
		}},
	}))
}
