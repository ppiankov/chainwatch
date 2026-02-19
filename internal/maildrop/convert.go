package maildrop

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config holds maildrop processing configuration.
type Config struct {
	InboxDir      string
	AllowlistFile string
	RateLimitDir  string
	RateLimit     int
	RateWindow    time.Duration
}

// jobJSON matches the daemon.Job schema without importing it to avoid cycles.
type jobJSON struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Target    jobTarget `json:"target"`
	Brief     string    `json:"brief"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

type jobTarget struct {
	Host  string `json:"host"`
	Scope string `json:"scope"`
}

// ProcessEmail parses a raw email, validates the sender, checks the rate limit,
// and writes a job file to the inbox directory.
// Job type is always forced to "investigate" — email cannot trigger remediation.
func ProcessEmail(cfg Config, raw []byte) error {
	email, err := ParseEmail(raw)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	// Validate sender.
	al, err := LoadAllowlist(cfg.AllowlistFile)
	if err != nil {
		return fmt.Errorf("allowlist: %w", err)
	}
	if !al.IsAllowed(email.From) {
		return fmt.Errorf("sender %s not in allowlist", email.From)
	}

	// Check rate limit.
	rl := NewRateLimiter(cfg.RateLimitDir, cfg.RateLimit, cfg.RateWindow)
	if err := rl.Check(email.From); err != nil {
		return fmt.Errorf("rate limit: %w", err)
	}

	// Generate job ID.
	id, err := generateJobID()
	if err != nil {
		return fmt.Errorf("generate ID: %w", err)
	}

	// Use subject as brief; fall back to body if subject is empty.
	brief := email.Subject
	if brief == "" {
		brief = email.Body
	}
	// Truncate to a reasonable length.
	if len(brief) > 500 {
		brief = brief[:500]
	}

	job := jobJSON{
		ID:   id,
		Type: "investigate", // Always forced to investigate.
		Target: jobTarget{
			Host: "", // Not known from email — daemon uses default.
		},
		Brief:     brief,
		Source:    "maildrop",
		CreatedAt: time.Now().UTC(),
	}

	// Write atomically to inbox.
	data, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	filename := id + ".json"
	tmpPath := filepath.Join(cfg.InboxDir, filename+".tmp")
	finalPath := filepath.Join(cfg.InboxDir, filename)

	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	return os.Rename(tmpPath, finalPath)
}

// generateJobID creates a random job ID like "mail-a1b2c3d4e5f6".
func generateJobID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "mail-" + hex.EncodeToString(b), nil
}
