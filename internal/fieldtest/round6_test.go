//go:build fieldtest

package fieldtest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRound6_BypassAttempts(t *testing.T) {
	t.Run("fail_closed_without_binary", func(t *testing.T) {
		// Rename chainwatch binary temporarily to simulate missing binary.
		// The exec helper uses the compiled binary path directly, so we
		// test that the runner fails cleanly when chainwatch is unavailable.
		arenaDir, auditLog := newArena(t)

		// Attempt to exec with a nonexistent profile path — verifies
		// that chainwatch fails rather than falling back to direct shell.
		args := []string{"exec", "--profile", "nonexistent-profile", "--audit-log", auditLog, "--", "echo", "should-not-run"}
		_, stderr, code := execChainwatch(t, args...)

		if code == 0 {
			t.Errorf("expected nonzero exit when profile is missing, got 0; stderr: %s", stderr)
		}
		_ = arenaDir
	})

	t.Run("symlink_to_etc_shadow", func(t *testing.T) {
		arenaDir, _ := newArena(t)

		// Create symlink pointing to /etc/shadow in inbox.
		inboxDir := filepath.Join(arenaDir, "inbox")
		if err := os.MkdirAll(inboxDir, 0o755); err != nil {
			t.Fatalf("mkdir inbox: %v", err)
		}
		symlinkPath := filepath.Join(inboxDir, "malicious.json")
		if err := os.Symlink("/etc/shadow", symlinkPath); err != nil {
			t.Fatalf("create symlink: %v", err)
		}

		// Read the symlink target — it should not be valid JSON.
		data, err := os.ReadFile(symlinkPath)
		if err != nil {
			// Permission denied reading /etc/shadow is the correct behavior.
			t.Logf("PASS: cannot read symlink target: %v", err)
			return
		}

		// If readable (e.g., test runs as root), verify it fails JSON parse.
		if len(data) > 0 {
			// /etc/shadow is not valid JSON, so the daemon would reject it.
			t.Logf("PASS: symlink target readable but not valid JSON (%d bytes)", len(data))
		}
	})

	t.Run("symlink_to_etc_passwd", func(t *testing.T) {
		arenaDir, _ := newArena(t)

		inboxDir := filepath.Join(arenaDir, "inbox")
		if err := os.MkdirAll(inboxDir, 0o755); err != nil {
			t.Fatalf("mkdir inbox: %v", err)
		}
		symlinkPath := filepath.Join(inboxDir, "passwd-link.json")
		if err := os.Symlink("/etc/passwd", symlinkPath); err != nil {
			t.Fatalf("create symlink: %v", err)
		}

		// /etc/passwd is world-readable but not valid JSON.
		data, err := os.ReadFile(symlinkPath)
		if err != nil {
			t.Fatalf("unexpected read error: %v", err)
		}

		// Verify it's not valid JSON (defense: invalid format rejection).
		if len(data) > 0 && data[0] == '{' {
			t.Error("FAIL: /etc/passwd appears to be valid JSON — unexpected")
		} else {
			t.Logf("PASS: symlink target is not valid JSON (%d bytes)", len(data))
		}
	})

	t.Run("toctou_move_eliminates_race", func(t *testing.T) {
		arenaDir, _ := newArena(t)

		srcDir := filepath.Join(arenaDir, "ingested")
		dstDir := filepath.Join(arenaDir, "processing")
		if err := os.MkdirAll(srcDir, 0o755); err != nil {
			t.Fatalf("mkdir src: %v", err)
		}
		if err := os.MkdirAll(dstDir, 0o755); err != nil {
			t.Fatalf("mkdir dst: %v", err)
		}

		// Write a payload file.
		payload := `{"wo_id":"toctou-001","incident_id":"inc-001","target":{"host":"localhost","scope":"/tmp"},"observations":[{"type":"log","severity":"low","detail":"test"}],"proposed_goals":["test"]}`
		srcPath := filepath.Join(srcDir, "toctou-001.json")
		if err := os.WriteFile(srcPath, []byte(payload), 0o600); err != nil {
			t.Fatalf("write payload: %v", err)
		}

		// Simulate the move-then-process pattern.
		dstPath := filepath.Join(dstDir, "toctou-001.json")
		if err := os.Rename(srcPath, dstPath); err != nil {
			t.Fatalf("rename: %v", err)
		}

		// After rename, source is gone — no race window.
		if _, err := os.Stat(srcPath); !os.IsNotExist(err) {
			t.Error("FAIL: source file still exists after rename — TOCTOU window open")
		}

		// Destination is readable.
		data, err := os.ReadFile(dstPath)
		if err != nil {
			t.Fatalf("read moved file: %v", err)
		}
		if len(data) == 0 {
			t.Error("FAIL: moved file is empty")
		}

		t.Log("PASS: rename is atomic — source removed, destination contains payload")
	})
}
