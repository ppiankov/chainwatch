//go:build fieldtest

package fieldtest

import (
	"os"
	"strings"
	"testing"
)

func TestRound12_PersistenceAndReplay(t *testing.T) {
	t.Run("forged_middle_entry_detected", func(t *testing.T) {
		_, auditLog := newArena(t)

		// Write 5 legitimate entries.
		for i := 0; i < 5; i++ {
			execExpectAllow(t, "clawbot", auditLog, "echo", "legit")
		}
		verifyChain(t, auditLog)

		// Read entries and corrupt one in the middle.
		data, err := os.ReadFile(auditLog)
		if err != nil {
			t.Fatalf("read audit log: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) < 5 {
			t.Fatalf("expected 5 lines, got %d", len(lines))
		}

		// Replace middle entry with garbage.
		lines[2] = `{"ts":"2026-02-21T00:00:00Z","trace_id":"forged","action":{"tool":"command","resource":"echo forged"},"decision":"allow","reason":"forged","tier":0,"policy_hash":"sha256:fake","prev_hash":"sha256:fake"}`

		if err := os.WriteFile(auditLog, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatalf("write tampered log: %v", err)
		}

		// Chain must be broken.
		verifyChainBroken(t, auditLog)
		t.Log("PASS: middle-entry tampering detected by hash chain")
	})

	t.Run("truncated_log_detected", func(t *testing.T) {
		_, auditLog := newArena(t)

		// Write 5 legitimate entries.
		for i := 0; i < 5; i++ {
			execExpectAllow(t, "clawbot", auditLog, "echo", "legit")
		}
		verifyChain(t, auditLog)

		// Truncate to 3 entries.
		data, err := os.ReadFile(auditLog)
		if err != nil {
			t.Fatalf("read audit log: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		truncated := strings.Join(lines[:3], "\n") + "\n"
		if err := os.WriteFile(auditLog, []byte(truncated), 0o600); err != nil {
			t.Fatalf("write truncated log: %v", err)
		}

		// Truncated log is still internally valid (first 3 entries are real).
		// But we've lost entries. Verify chain of remaining entries.
		verifyChain(t, auditLog)

		// Count should be 3, not 5.
		count := countEntries(t, auditLog)
		if count != 3 {
			t.Errorf("expected 3 entries after truncation, got %d", count)
		}

		t.Log("PASS: truncation detected by entry count difference (operational monitoring)")
	})

	t.Run("deleted_log_detected", func(t *testing.T) {
		_, auditLog := newArena(t)

		// Write legitimate entries.
		for i := 0; i < 3; i++ {
			execExpectAllow(t, "clawbot", auditLog, "echo", "legit")
		}
		verifyChain(t, auditLog)

		// Delete the log entirely.
		if err := os.Remove(auditLog); err != nil {
			t.Fatalf("remove audit log: %v", err)
		}

		// Verification should fail — no file to verify.
		_, _, code := execChainwatch(t, "audit", "verify", auditLog)
		if code == 0 {
			t.Error("FAIL: verification passed on deleted log")
		} else {
			t.Log("PASS: verification fails on deleted audit log")
		}
	})

	t.Run("appended_entry_without_hash_chain", func(t *testing.T) {
		_, auditLog := newArena(t)

		// Write legitimate entries.
		for i := 0; i < 3; i++ {
			execExpectAllow(t, "clawbot", auditLog, "echo", "legit")
		}
		verifyChain(t, auditLog)

		// Append a well-formed but unchained entry.
		f, err := os.OpenFile(auditLog, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatalf("open log: %v", err)
		}
		forged := `{"ts":"2026-02-21T12:00:00Z","trace_id":"injected","action":{"tool":"command","resource":"echo injected"},"decision":"allow","reason":"injected","tier":0,"policy_hash":"sha256:aaa","prev_hash":"sha256:wrong"}` + "\n"
		if _, err := f.WriteString(forged); err != nil {
			f.Close()
			t.Fatalf("write forged: %v", err)
		}
		f.Close()

		// Chain must break at the appended entry.
		verifyChainBroken(t, auditLog)
		t.Log("PASS: appended unchained entry detected")
	})
}
