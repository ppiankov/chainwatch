package maildrop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupConvertTest(t *testing.T) (Config, string) {
	t.Helper()
	root := t.TempDir()
	inbox := filepath.Join(root, "inbox")
	_ = os.MkdirAll(inbox, 0750)

	alPath := filepath.Join(root, "allowlist.txt")
	_ = os.WriteFile(alPath, []byte("admin@example.com\n@trusted.io\n"), 0600)

	cfg := Config{
		InboxDir:      inbox,
		AllowlistFile: alPath,
		RateLimitDir:  filepath.Join(root, "ratelimit"),
		RateLimit:     10,
		RateWindow:    1 * time.Hour,
	}
	return cfg, inbox
}

func TestProcessEmailValid(t *testing.T) {
	cfg, inbox := setupConvertTest(t)
	raw := "From: admin@example.com\r\nSubject: Check web server\r\n\r\nThe site is slow."

	if err := ProcessEmail(cfg, []byte(raw)); err != nil {
		t.Fatalf("ProcessEmail: %v", err)
	}

	// Verify a job file was created in inbox.
	entries, _ := os.ReadDir(inbox)
	if len(entries) != 1 {
		t.Fatalf("expected 1 file in inbox, got %d", len(entries))
	}

	data, _ := os.ReadFile(filepath.Join(inbox, entries[0].Name()))
	var job map[string]interface{}
	if err := json.Unmarshal(data, &job); err != nil {
		t.Fatal(err)
	}

	if job["type"] != "investigate" {
		t.Errorf("type = %v, want investigate", job["type"])
	}
	if job["source"] != "maildrop" {
		t.Errorf("source = %v, want maildrop", job["source"])
	}
	if job["brief"] != "Check web server" {
		t.Errorf("brief = %v, want 'Check web server'", job["brief"])
	}
}

func TestProcessEmailBlockedSender(t *testing.T) {
	cfg, inbox := setupConvertTest(t)
	raw := "From: hacker@evil.com\r\nSubject: Do something bad\r\n\r\nbody"

	err := ProcessEmail(cfg, []byte(raw))
	if err == nil {
		t.Error("expected error for blocked sender")
	}

	// No file should be created.
	entries, _ := os.ReadDir(inbox)
	if len(entries) != 0 {
		t.Errorf("blocked sender should not create a file, got %d", len(entries))
	}
}

func TestProcessEmailRateLimited(t *testing.T) {
	cfg, inbox := setupConvertTest(t)
	cfg.RateLimit = 1

	raw := "From: admin@example.com\r\nSubject: First\r\n\r\nbody"
	if err := ProcessEmail(cfg, []byte(raw)); err != nil {
		t.Fatal(err)
	}

	// Second should be rate limited.
	raw2 := "From: admin@example.com\r\nSubject: Second\r\n\r\nbody"
	err := ProcessEmail(cfg, []byte(raw2))
	if err == nil {
		t.Error("expected rate limit error")
	}

	entries, _ := os.ReadDir(inbox)
	if len(entries) != 1 {
		t.Errorf("only first email should produce a job, got %d", len(entries))
	}
}

func TestProcessEmailDomainWildcard(t *testing.T) {
	cfg, _ := setupConvertTest(t)
	raw := "From: anyone@trusted.io\r\nSubject: Domain wildcard test\r\n\r\nbody"

	if err := ProcessEmail(cfg, []byte(raw)); err != nil {
		t.Errorf("domain wildcard sender should be allowed: %v", err)
	}
}

func TestProcessEmailInvalid(t *testing.T) {
	cfg, _ := setupConvertTest(t)

	if err := ProcessEmail(cfg, []byte("not an email")); err == nil {
		t.Error("expected error for invalid email")
	}
}

func TestProcessEmailForcedInvestigateType(t *testing.T) {
	cfg, inbox := setupConvertTest(t)
	raw := "From: admin@example.com\r\nSubject: Test type\r\n\r\nbody"

	_ = ProcessEmail(cfg, []byte(raw))

	entries, _ := os.ReadDir(inbox)
	if len(entries) == 0 {
		t.Fatal("expected a file")
	}
	data, _ := os.ReadFile(filepath.Join(inbox, entries[0].Name()))
	var job map[string]interface{}
	_ = json.Unmarshal(data, &job)

	if job["type"] != "investigate" {
		t.Errorf("maildrop jobs must always be type=investigate, got %v", job["type"])
	}
}
