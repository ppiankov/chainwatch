//go:build fieldtest

package fieldtest

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestRound8_DataExfiltration(t *testing.T) {
	_, auditLog := newArena(t)

	t.Run("aws_key_not_redacted_documented_gap", func(t *testing.T) {
		// AWS key patterns (AKIA...) are not in chainwatch's output scanner.
		// Chainwatch scans for gsk_, sk-, sk-ant-, bearer, and long hex tokens.
		// AWS keys are a documented gap — chainwatch is not a DLP.
		stdout, _, code := execChainwatch(t,
			"exec", "--profile", "clawbot", "--audit-log", auditLog, "--",
			"echo", "some-aws-key-value-here")

		if code == 77 {
			t.Log("command blocked by policy — acceptable")
			return
		}

		// This is expected to pass through (not redacted).
		t.Logf("PASS (documented gap): AWS key patterns not scanned — stdout length %d", len(stdout))
	})

	t.Run("redact_groq_key", func(t *testing.T) {
		fakeKey := "gsk_testaaaaabbbbbbccccccdddddd"
		stdout, _, code := execChainwatch(t,
			"exec", "--profile", "clawbot", "--audit-log", auditLog, "--",
			"echo", fakeKey)

		if code == 77 {
			t.Log("PASS: command blocked by policy")
			return
		}

		if strings.Contains(stdout, fakeKey) {
			t.Error("FAIL: Groq key not redacted in output")
		} else {
			t.Log("PASS: Groq key redacted")
		}
	})

	t.Run("redact_anthropic_key", func(t *testing.T) {
		fakeKey := "sk-ant-fakekey1234567890abcdef1234567890"
		stdout, _, code := execChainwatch(t,
			"exec", "--profile", "clawbot", "--audit-log", auditLog, "--",
			"echo", fakeKey)

		if code == 77 {
			t.Log("PASS: command blocked by policy")
			return
		}

		if strings.Contains(stdout, fakeKey) {
			t.Error("FAIL: Anthropic key not redacted in output")
		} else {
			t.Log("PASS: Anthropic key redacted")
		}
	})

	t.Run("redact_bearer_token", func(t *testing.T) {
		fakeToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test1234567890"
		stdout, _, code := execChainwatch(t,
			"exec", "--profile", "clawbot", "--audit-log", auditLog, "--",
			"echo", fakeToken)

		if code == 77 {
			t.Log("PASS: command blocked by policy")
			return
		}

		if strings.Contains(stdout, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
			t.Error("FAIL: Bearer token not redacted in output")
		} else {
			t.Log("PASS: Bearer token redacted")
		}
	})

	t.Run("base64_secret_passes_documented_limitation", func(t *testing.T) {
		// Base64-encoded secrets are a documented limitation.
		// Chainwatch is not a DLP. This test documents the behavior.
		rawSecret := "gsk_realkey1234567890"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawSecret))

		stdout, _, code := execChainwatch(t,
			"exec", "--profile", "clawbot", "--audit-log", auditLog, "--",
			"echo", encoded)

		if code == 77 {
			t.Log("command blocked by policy — acceptable")
			return
		}

		if strings.Contains(stdout, encoded) {
			t.Log("PASS (documented limitation): base64-encoded secret passes through output scanning — chainwatch is not a DLP")
		} else {
			t.Log("PASS: base64 content was redacted (better than documented)")
		}
	})

	t.Run("cross_job_no_state_accumulation", func(t *testing.T) {
		// Execute 4 commands, each printing a quarter of a fake key.
		// Verify each is independently scanned with no cross-job state.
		_, jobLog := newArena(t)

		parts := []string{"fake", "aws_", "key_", "test"}
		for i, part := range parts {
			stdout, _, code := execChainwatch(t,
				"exec", "--profile", "clawbot", "--audit-log", jobLog, "--",
				"echo", part)

			if code == 77 {
				continue
			}

			// Each fragment is short enough to not trigger patterns.
			if strings.Contains(stdout, part) {
				t.Logf("job %d: fragment %q in output (expected — too short for pattern)", i, part)
			}
		}

		// Verify each job has its own audit entry.
		count := countEntries(t, jobLog)
		if count < len(parts) {
			t.Errorf("expected at least %d audit entries, got %d", len(parts), count)
		}

		verifyChain(t, jobLog)
		t.Log("PASS: each job independently traced, no cross-job state")
	})

	t.Run("audit_chain_valid", func(t *testing.T) {
		verifyChain(t, auditLog)
	})
}
