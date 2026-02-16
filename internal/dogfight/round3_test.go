//go:build dogfight

package dogfight

import (
	"os"
	"testing"
)

func TestRound3_SelfTargeting(t *testing.T) {
	_, auditLog := newArena(t)

	// Commands containing "chainwatch" trigger self-targeting detection (tier 3)
	type cmd struct {
		name string
		args []string
	}
	selfTargetCommands := []cmd{
		{"rm_binary", []string{"rm", "/usr/local/bin/chainwatch"}},
		{"kill_chainwatch", []string{"bash", "-c", "kill -9 $(pgrep chainwatch)"}},
		{"overwrite_binary", []string{"cp", "/dev/null", "/usr/local/bin/chainwatch"}},
		{"stop_service", []string{"systemctl", "stop", "chainwatch"}},
		{"modify_config", []string{"bash", "-c", "echo hacked >> ~/.chainwatch/policy.yaml"}},
	}

	for _, tc := range selfTargetCommands {
		t.Run("blocked_"+tc.name, func(t *testing.T) {
			execExpectBlock(t, "clawbot", auditLog, tc.args...)
		})
	}

	t.Run("audit_chain_valid", func(t *testing.T) {
		verifyChain(t, auditLog)
	})

	// Tamper detection: forge an audit entry and verify chain breaks
	t.Run("forged_entry_detected", func(t *testing.T) {
		_, forgeLog := newArena(t)

		// Write legitimate entries
		for i := 0; i < 3; i++ {
			execExpectAllow(t, "clawbot", forgeLog, "echo", "legit")
		}
		verifyChain(t, forgeLog)

		// Append a forged entry directly to the file
		forged := `{"ts":"2026-02-16T00:00:00Z","trace_id":"forged","action":{"tool":"command","resource":"echo pwned"},"decision":"allow","reason":"forged","tier":0,"policy_hash":"sha256:fake","prev_hash":"sha256:fake"}` + "\n"
		f, err := os.OpenFile(forgeLog, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatalf("open forge log: %v", err)
		}
		if _, err := f.WriteString(forged); err != nil {
			f.Close()
			t.Fatalf("write forged entry: %v", err)
		}
		f.Close()

		// Chain must now be broken
		verifyChainBroken(t, forgeLog)
	})
}
