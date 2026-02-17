//go:build fieldtest

package fieldtest

import (
	"fmt"
	"testing"
	"time"
)

func TestRound4_RapidSequential(t *testing.T) {
	_, auditLog := newArena(t)

	const totalCommands = 50

	start := time.Now()

	for i := 0; i < totalCommands; i++ {
		if i%3 == 0 {
			// Blocked: sudo command
			execExpectBlock(t, "clawbot", auditLog, "sudo", fmt.Sprintf("cmd-%d", i))
		} else {
			// Allowed: echo command
			execExpectAllow(t, "clawbot", auditLog, "echo", fmt.Sprintf("rapid-%d", i))
		}
	}

	elapsed := time.Since(start)

	t.Run("chain_valid", func(t *testing.T) {
		verifyChain(t, auditLog)
	})

	t.Run("no_lost_entries", func(t *testing.T) {
		count := countEntries(t, auditLog)
		if count != totalCommands {
			t.Errorf("expected %d entries, got %d (lost %d)", totalCommands, count, totalCommands-count)
		}
	})

	t.Run("correct_decision_counts", func(t *testing.T) {
		expectedDeny := 0
		expectedAllow := 0
		for i := 0; i < totalCommands; i++ {
			if i%3 == 0 {
				expectedDeny++
			} else {
				expectedAllow++
			}
		}
		denies := countDecisions(t, auditLog, "deny")
		allows := countDecisions(t, auditLog, "allow")
		if denies != expectedDeny {
			t.Errorf("deny count: expected %d, got %d", expectedDeny, denies)
		}
		if allows != expectedAllow {
			t.Errorf("allow count: expected %d, got %d", expectedAllow, allows)
		}
	})

	t.Run("performance", func(t *testing.T) {
		if elapsed > 60*time.Second {
			t.Errorf("%d commands took %v (expected < 60s)", totalCommands, elapsed)
		}
		t.Logf("%d commands completed in %v (%.0fms/cmd)", totalCommands, elapsed,
			float64(elapsed.Milliseconds())/float64(totalCommands))
	})
}
