//go:build fieldtest

package fieldtest

import (
	"fmt"
	"testing"
)

func TestRound10_OperationalStress(t *testing.T) {
	t.Run("rapid_sequential_commands", func(t *testing.T) {
		_, auditLog := newArena(t)

		// Fire 50 commands rapidly — mix of allowed and denied.
		allowed := 0
		denied := 0
		total := 50

		for i := 0; i < total; i++ {
			var args []string
			if i%3 == 0 {
				// Every 3rd command is a blocked one.
				args = []string{"exec", "--profile", "clawbot", "--audit-log", auditLog, "--", "rm", "-rf", "/"}
				_, _, code := execChainwatch(t, args...)
				if code == 77 {
					denied++
				}
			} else {
				args = []string{"exec", "--profile", "clawbot", "--audit-log", auditLog, "--", "echo", fmt.Sprintf("stress-%d", i)}
				_, _, code := execChainwatch(t, args...)
				if code == 0 {
					allowed++
				}
			}
		}

		// Verify all entries recorded.
		count := countEntries(t, auditLog)
		if count != total {
			t.Errorf("expected %d audit entries, got %d (lost %d)", total, count, total-count)
		}

		// Verify chain integrity under load.
		verifyChain(t, auditLog)

		t.Logf("PASS: %d commands, %d allowed, %d denied, chain intact", total, allowed, denied)
	})

	t.Run("chainwatch_nonzero_exit_propagates", func(t *testing.T) {
		_, auditLog := newArena(t)

		// Execute a command that exits nonzero — chainwatch should propagate.
		_, _, code := execChainwatch(t,
			"exec", "--profile", "clawbot", "--audit-log", auditLog, "--",
			"bash", "-c", "exit 42")

		if code == 0 {
			t.Error("FAIL: expected nonzero exit code from failing command, got 0")
		} else if code == 77 {
			t.Log("command was blocked by policy (acceptable)")
		} else {
			t.Logf("PASS: subprocess exit code propagated (got %d)", code)
		}
	})

	t.Run("no_fallback_to_direct_shell", func(t *testing.T) {
		// Verify that chainwatch exec with nonexistent binary doesn't fall back.
		_, auditLog := newArena(t)

		_, _, code := execChainwatch(t,
			"exec", "--profile", "clawbot", "--audit-log", auditLog, "--",
			"/nonexistent/binary/path")

		if code == 0 {
			t.Error("FAIL: nonexistent binary returned exit 0 — possible fallback")
		} else {
			t.Logf("PASS: nonexistent binary failed cleanly (exit %d)", code)
		}
	})
}
