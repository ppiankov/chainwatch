//go:build fieldtest

package fieldtest

import (
	"testing"
)

func TestRound5_ChainPersistence(t *testing.T) {
	_, auditLog := newArena(t)

	// Phase 1: initial commands
	for i := 0; i < 5; i++ {
		execExpectAllow(t, "clawbot", auditLog, "echo", "pre-reboot")
	}
	verifyChain(t, auditLog)
	phase1Count := countEntries(t, auditLog)

	// Phase 2: new process invocations append to existing log (simulates reboot)
	for i := 0; i < 5; i++ {
		execExpectAllow(t, "clawbot", auditLog, "echo", "post-reboot")
	}

	// Phase 3: blocked commands continue the same chain
	for i := 0; i < 3; i++ {
		execExpectBlock(t, "clawbot", auditLog, "sudo", "su")
	}

	t.Run("full_chain_valid", func(t *testing.T) {
		verifyChain(t, auditLog)
	})

	t.Run("total_entries", func(t *testing.T) {
		total := countEntries(t, auditLog)
		expected := phase1Count + 5 + 3
		if total != expected {
			t.Errorf("expected %d entries, got %d", expected, total)
		}
	})

	t.Run("chain_continuous_at_boundary", func(t *testing.T) {
		entries := parseEntries(t, auditLog)
		if len(entries) <= phase1Count {
			t.Fatal("not enough entries for boundary check")
		}
		// Post-reboot entry must NOT have genesis hash (sha256:000...)
		// If it did, that means a new chain started instead of continuing
		prevHash, _ := entries[phase1Count]["prev_hash"].(string)
		if prevHash == "" {
			t.Error("post-reboot entry missing prev_hash")
		}
		genesisHash := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		if prevHash == genesisHash {
			t.Error("post-reboot entry has genesis hash — chain restarted instead of continuing")
		}
	})

	t.Run("mixed_decisions_after_reboot", func(t *testing.T) {
		allows := countDecisions(t, auditLog, "allow")
		denies := countDecisions(t, auditLog, "deny")
		if allows != 10 {
			t.Errorf("expected 10 allows, got %d", allows)
		}
		if denies != 3 {
			t.Errorf("expected 3 denies, got %d", denies)
		}
	})
}
