//go:build fieldtest

package fieldtest

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// execChainwatch runs the compiled binary with the given args.
// Returns stdout, stderr, and exit code.
func execChainwatch(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return stdout.String(), stderr.String(), exitErr.ExitCode()
		}
		t.Fatalf("exec failed: %v", err)
	}
	return stdout.String(), stderr.String(), 0
}

// execExpectAllow runs chainwatch exec and asserts exit code 0.
func execExpectAllow(t *testing.T, profile, auditLog string, command ...string) {
	t.Helper()
	args := []string{"exec", "--profile", profile, "--audit-log", auditLog, "--"}
	args = append(args, command...)
	_, stderr, code := execChainwatch(t, args...)
	if code != 0 {
		t.Errorf("expected allow (exit 0) for %q, got exit %d: %s",
			strings.Join(command, " "), code, stderr)
	}
}

// execExpectBlock runs chainwatch exec and asserts exit code 77 (policy block).
func execExpectBlock(t *testing.T, profile, auditLog string, command ...string) {
	t.Helper()
	args := []string{"exec", "--profile", profile, "--audit-log", auditLog, "--"}
	args = append(args, command...)
	_, stderr, code := execChainwatch(t, args...)
	if code != 77 {
		t.Errorf("expected block (exit 77) for %q, got exit %d: %s",
			strings.Join(command, " "), code, stderr)
	}
}

// execDryRunExpectBlock runs chainwatch exec --dry-run and asserts exit code 77.
func execDryRunExpectBlock(t *testing.T, profile, auditLog string, command ...string) {
	t.Helper()
	args := []string{"exec", "--profile", profile, "--audit-log", auditLog, "--dry-run", "--"}
	args = append(args, command...)
	_, stderr, code := execChainwatch(t, args...)
	if code != 77 {
		t.Errorf("expected dry-run block (exit 77) for %q, got exit %d: %s",
			strings.Join(command, " "), code, stderr)
	}
}

// verifyChain runs `chainwatch audit verify` and asserts the chain is valid.
func verifyChain(t *testing.T, auditLogPath string) {
	t.Helper()
	_, stderr, code := execChainwatch(t, "audit", "verify", auditLogPath)
	if code != 0 {
		t.Fatalf("audit chain verification failed (exit %d): %s", code, stderr)
	}
}

// verifyChainBroken runs `chainwatch audit verify` and asserts the chain is broken.
func verifyChainBroken(t *testing.T, auditLogPath string) {
	t.Helper()
	_, _, code := execChainwatch(t, "audit", "verify", auditLogPath)
	if code == 0 {
		t.Fatal("expected audit chain verification to fail, but it passed")
	}
}

// countEntries counts the number of non-empty lines in the audit log.
func countEntries(t *testing.T, auditLogPath string) int {
	t.Helper()
	f, err := os.Open(auditLogPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit log: %v", err)
	}
	return count
}

// countDecisions counts audit entries with a specific decision value.
func countDecisions(t *testing.T, auditLogPath, decision string) int {
	t.Helper()
	entries := parseEntries(t, auditLogPath)
	count := 0
	for _, e := range entries {
		if d, ok := e["decision"].(string); ok && d == decision {
			count++
		}
	}
	return count
}

// parseEntries parses all JSON objects from the audit log.
func parseEntries(t *testing.T, auditLogPath string) []map[string]any {
	t.Helper()
	f, err := os.Open(auditLogPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()

	var entries []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse audit entry: %v\nline: %s", err, line)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit log: %v", err)
	}
	return entries
}

// newArena creates a temp directory with seed files and returns
// the arena directory and audit log path.
func newArena(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()

	// Create arena structure
	for _, sub := range []string{"targets", "protected", "logs"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}

	// Seed files
	seeds := map[string]string{
		"targets/config.json": `{"version": "1.0", "name": "test"}`,
		"targets/report.txt":  "Quarterly report data\n",
	}
	for name, content := range seeds {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write seed %s: %v", name, err)
		}
	}

	auditLog := filepath.Join(dir, "logs", "audit.jsonl")
	return dir, auditLog
}

// findRepoRoot walks up from the current directory to find go.mod.
func findRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		panic("getwd: " + err.Error())
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("could not find go.mod in any parent directory")
		}
		dir = parent
	}
}
