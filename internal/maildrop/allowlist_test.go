package maildrop

import (
	"os"
	"path/filepath"
	"testing"
)

func writeAllowlist(t *testing.T, dir string, lines string) string {
	t.Helper()
	path := filepath.Join(dir, "allowlist.txt")
	if err := os.WriteFile(path, []byte(lines), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAllowlistExactMatch(t *testing.T) {
	path := writeAllowlist(t, t.TempDir(), "admin@example.com\nops@corp.io\n")
	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if !al.IsAllowed("admin@example.com") {
		t.Error("admin@example.com should be allowed")
	}
	if !al.IsAllowed("ops@corp.io") {
		t.Error("ops@corp.io should be allowed")
	}
}

func TestAllowlistDomainWildcard(t *testing.T) {
	path := writeAllowlist(t, t.TempDir(), "@example.com\n")
	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if !al.IsAllowed("anyone@example.com") {
		t.Error("anyone@example.com should match @example.com wildcard")
	}
	if al.IsAllowed("user@other.com") {
		t.Error("user@other.com should not match @example.com")
	}
}

func TestAllowlistCaseInsensitive(t *testing.T) {
	path := writeAllowlist(t, t.TempDir(), "Admin@Example.COM\n")
	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if !al.IsAllowed("admin@example.com") {
		t.Error("should match case-insensitively")
	}
}

func TestAllowlistUnknownRejected(t *testing.T) {
	path := writeAllowlist(t, t.TempDir(), "admin@example.com\n")
	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if al.IsAllowed("hacker@evil.com") {
		t.Error("unknown sender should be rejected")
	}
}

func TestAllowlistCommentsIgnored(t *testing.T) {
	path := writeAllowlist(t, t.TempDir(), "# comment\nadmin@example.com\n# another comment\n\n")
	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(al.patterns) != 1 {
		t.Errorf("expected 1 pattern, got %d", len(al.patterns))
	}
}

func TestAllowlistEmptyFile(t *testing.T) {
	path := writeAllowlist(t, t.TempDir(), "# only comments\n\n")
	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if al.IsAllowed("anyone@example.com") {
		t.Error("empty allowlist should reject everyone")
	}
}

func TestAllowlistMissingFile(t *testing.T) {
	_, err := LoadAllowlist("/nonexistent/allowlist.txt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
