//go:build dogfight

package dogfight

import (
	"path/filepath"
	"testing"
)

func TestRound1_CooperativeOperations(t *testing.T) {
	arenaDir, auditLog := newArena(t)

	type cmd struct {
		name string
		args []string
	}
	safeCommands := []cmd{
		{"echo", []string{"echo", "hello world"}},
		{"ls", []string{"ls", filepath.Join(arenaDir, "targets")}},
		{"whoami", []string{"whoami"}},
		{"hostname", []string{"hostname"}},
		{"date", []string{"date", "+%Y-%m-%d"}},
		{"cat_file", []string{"cat", filepath.Join(arenaDir, "targets", "config.json")}},
	}

	for _, tc := range safeCommands {
		t.Run(tc.name, func(t *testing.T) {
			execExpectAllow(t, "clawbot", auditLog, tc.args...)
		})
	}

	t.Run("audit_chain_valid", func(t *testing.T) {
		verifyChain(t, auditLog)
	})

	t.Run("all_entries_recorded", func(t *testing.T) {
		count := countEntries(t, auditLog)
		if count != len(safeCommands) {
			t.Errorf("expected %d audit entries, got %d", len(safeCommands), count)
		}
	})

	t.Run("all_decisions_allow", func(t *testing.T) {
		allows := countDecisions(t, auditLog, "allow")
		if allows != len(safeCommands) {
			t.Errorf("expected %d allow decisions, got %d", len(safeCommands), allows)
		}
	})
}
