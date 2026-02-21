// Package integrity verifies binary checksums at startup.
// The expected hash is embedded at build time via ldflags.
// If the running binary does not match, a tamper event is
// recorded and the process refuses to start.
package integrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ExpectedHash is set at build time via:
//
//	-ldflags "-X github.com/ppiankov/chainwatch/internal/integrity.ExpectedHash=<sha256hex>"
//
// When empty (dev builds), verification falls back to checksum file.
var ExpectedHash string

// TamperLogDir is the directory where tamper events are written.
// Defaults to /var/log/chainwatch. Override for testing.
var TamperLogDir = "/var/log/chainwatch"

// ChecksumPaths are the paths checked (in order) for a sha256 checksum file.
// The file should contain a single hex-encoded SHA-256 hash.
// Override for testing.
var ChecksumPaths = []string{
	"/etc/chainwatch/binary.sha256",
	"$HOME/.chainwatch/binary.sha256",
}

// TamperEvent records a binary integrity violation.
type TamperEvent struct {
	Timestamp    string `json:"timestamp"`
	Binary       string `json:"binary"`
	ExpectedHash string `json:"expected_hash"`
	ActualHash   string `json:"actual_hash"`
	Hostname     string `json:"hostname"`
	Type         string `json:"type"`
}

// Verify checks that the running binary matches ExpectedHash.
// If ExpectedHash is empty, falls back to checksum file at ChecksumPaths.
// Returns nil if verification passes or if no expected hash is available (dev mode).
// On mismatch, writes a tamper event to the tamper log before returning error.
func Verify() error {
	expected := ExpectedHash
	if expected == "" {
		expected = loadChecksumFile()
	}
	if expected == "" {
		fmt.Fprintf(os.Stderr, "integrity: WARNING no build-time hash or checksum file found (dev build, integrity check skipped)\n")
		return nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("integrity: cannot resolve executable path: %w", err)
	}

	actual, err := hashFile(exePath)
	if err != nil {
		return fmt.Errorf("integrity: cannot hash binary: %w", err)
	}

	if actual == expected {
		fmt.Fprintf(os.Stderr, "integrity: binary checksum verified (%s...%s)\n",
			actual[:8], actual[len(actual)-8:])
		return nil
	}

	event := TamperEvent{
		Timestamp:    time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Binary:       exePath,
		ExpectedHash: expected,
		ActualHash:   actual,
		Type:         "binary_tamper",
	}
	event.Hostname, _ = os.Hostname()

	writeTamperEvent(event)

	return fmt.Errorf("integrity: binary checksum mismatch (expected %s, got %s)", expected, actual)
}

// HashSelf returns the SHA-256 hex digest of the running binary.
// Useful for writing the checksum file after install.
func HashSelf() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("integrity: cannot resolve executable path: %w", err)
	}
	return hashFile(exePath)
}

// loadChecksumFile reads the expected hash from a checksum file.
// Returns empty string if no file is found or readable.
func loadChecksumFile() string {
	for _, p := range ChecksumPaths {
		path := os.ExpandEnv(p)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		hash := strings.TrimSpace(string(data))
		// Validate it looks like a SHA-256 hex digest.
		if len(hash) == 64 && isHex(hash) {
			return hash
		}
	}
	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeTamperEvent appends a tamper event to the tamper log,
// prints to stderr for systemd journal, and fires webhook alerts.
func writeTamperEvent(event TamperEvent) {
	line, err := json.Marshal(event)
	if err != nil {
		return
	}

	// 1. Persistent file log
	logPath := filepath.Join(TamperLogDir, "tamper.jsonl")
	if err := os.MkdirAll(TamperLogDir, 0700); err == nil {
		if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
			f.Write(append(line, '\n'))
			f.Sync()
			f.Close()
		}
	}

	// 2. stderr for systemd journal
	fmt.Fprintf(os.Stderr, "TAMPER ALERT: %s\n", string(line))

	// 3. Webhook alerts via policy config (best-effort)
	dispatchTamperAlert(event)
}

// dispatchTamperAlert loads alert configs from policy.yaml and fires
// the tamper event to all webhooks matching "binary_tamper" or "deny".
// This runs before full policy init — it only parses the alerts section.
func dispatchTamperAlert(event TamperEvent) {
	configs := loadAlertConfigs()
	if len(configs) == 0 {
		return
	}

	alertEvent := alertEventFromTamper(event)
	for _, cfg := range configs {
		for _, e := range cfg.Events {
			if e == "binary_tamper" || e == "deny" {
				// Synchronous — we're about to exit anyway
				sendWebhook(cfg, alertEvent)
				break
			}
		}
	}
}

// alertConfig is a minimal struct for parsing just the alerts section.
type alertConfig struct {
	URL     string            `yaml:"url"`
	Format  string            `yaml:"format"`
	Events  []string          `yaml:"events"`
	Headers map[string]string `yaml:"headers"`
}

type policyAlerts struct {
	Alerts []alertConfig `yaml:"alerts"`
}

// loadAlertConfigs reads just the alerts section from policy.yaml.
func loadAlertConfigs() []alertConfig {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	path := filepath.Join(home, ".chainwatch", "policy.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var pa policyAlerts
	if err := yaml.Unmarshal(data, &pa); err != nil {
		return nil
	}
	return pa.Alerts
}

// tamperAlertPayload is the webhook payload for tamper events.
type tamperAlertPayload struct {
	Timestamp    string `json:"timestamp"`
	Type         string `json:"type"`
	Binary       string `json:"binary"`
	ExpectedHash string `json:"expected_hash"`
	ActualHash   string `json:"actual_hash"`
	Hostname     string `json:"hostname"`
	Decision     string `json:"decision"`
	Tier         int    `json:"tier"`
	Reason       string `json:"reason"`
}

func alertEventFromTamper(event TamperEvent) tamperAlertPayload {
	return tamperAlertPayload{
		Timestamp:    event.Timestamp,
		Type:         "binary_tamper",
		Binary:       event.Binary,
		ExpectedHash: event.ExpectedHash,
		ActualHash:   event.ActualHash,
		Hostname:     event.Hostname,
		Decision:     "deny",
		Tier:         3,
		Reason:       fmt.Sprintf("binary checksum mismatch: expected %s, got %s", event.ExpectedHash, event.ActualHash),
	}
}

// sendWebhook posts the tamper alert to a single webhook.
func sendWebhook(cfg alertConfig, payload tamperAlertPayload) {
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TAMPER ALERT webhook failed: %v\n", err)
		return
	}
	resp.Body.Close()
}
