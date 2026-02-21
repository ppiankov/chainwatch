//go:build fieldtest

package fieldtest

import (
	"strings"
	"testing"
)

func TestRound7_SelfProtectionBreaks(t *testing.T) {
	_, auditLog := newArena(t)

	// Indirect environment exfiltration attempts.
	type cmd struct {
		name   string
		args   []string
		expect string // "block" or "allow_clean" (allowed but no secrets in output)
	}

	exfilAttempts := []cmd{
		// Direct procfs reads — blocked by denylist.
		{"proc_self_environ", []string{"cat", "/proc/self/environ"}, "block"},
		{"proc_1_environ", []string{"cat", "/proc/1/environ"}, "block"},
		{"proc_wildcard_environ", []string{"bash", "-c", "cat /proc/*/environ"}, "block"},

		// Shell builtins that dump variables — blocked by denylist.
		{"declare_p", []string{"bash", "-c", "declare -p"}, "block"},
		{"export_p", []string{"bash", "-c", "export -p"}, "block"},
		{"compgen_v", []string{"bash", "-c", "compgen -v"}, "block"},

		// Env var name references — blocked by denylist.
		{"echo_groq_key", []string{"bash", "-c", "echo $GROQ_API_KEY"}, "block"},
		{"echo_openai_key", []string{"bash", "-c", "echo $OPENAI_API_KEY"}, "block"},
		{"echo_anthropic_key", []string{"bash", "-c", "echo $ANTHROPIC_API_KEY"}, "block"},

		// printenv — blocked by denylist.
		{"printenv", []string{"printenv"}, "block"},

		// strings on binary/memory — blocked (contains /proc reference or is dangerous).
		{"strings_proc_mem", []string{"bash", "-c", "strings /proc/self/mem"}, "block"},
	}

	for _, tc := range exfilAttempts {
		t.Run(tc.name, func(t *testing.T) {
			switch tc.expect {
			case "block":
				execExpectBlock(t, "clawbot", auditLog, tc.args...)
			case "allow_clean":
				stdout, _, code := execChainwatch(t,
					append([]string{"exec", "--profile", "clawbot", "--audit-log", auditLog, "--"}, tc.args...)...)
				if code != 0 {
					t.Logf("command blocked (exit %d) — acceptable", code)
					return
				}
				// If allowed, verify output contains no secrets.
				secrets := []string{"gsk_", "sk-", "sk-ant-", "GROQ_API", "OPENAI_API", "ANTHROPIC_API"}
				for _, s := range secrets {
					if strings.Contains(stdout, s) {
						t.Errorf("FAIL: output contains secret pattern %q", s)
					}
				}
			}
		})
	}

	t.Run("env_allowed_but_sanitized", func(t *testing.T) {
		// The bare `env` command is intentionally not blocked (too many false positives).
		// But subprocess environment should be sanitized.
		stdout, _, code := execChainwatch(t,
			"exec", "--profile", "clawbot", "--audit-log", auditLog, "--", "env")

		if code == 77 {
			t.Log("PASS: env command blocked by policy")
			return
		}

		// If allowed, check that no sensitive vars leak.
		sensitivePatterns := []string{
			"GROQ_API_KEY=",
			"OPENAI_API_KEY=",
			"ANTHROPIC_API_KEY=",
			"NULLBOT_API_KEY=",
			"CHAINWATCH_",
			"API_SECRET=",
		}
		for _, pat := range sensitivePatterns {
			if strings.Contains(stdout, pat) {
				t.Errorf("FAIL: env output contains sensitive var: %s", pat)
			}
		}
		t.Log("PASS: env output contains no sensitive variables")
	})

	t.Run("audit_chain_valid", func(t *testing.T) {
		verifyChain(t, auditLog)
	})
}
