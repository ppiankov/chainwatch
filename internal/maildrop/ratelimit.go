package maildrop

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// defaultRateLimit is the maximum jobs per sender per window.
const defaultRateLimit = 10

// defaultRateWindow is the time window for rate limiting.
const defaultRateWindow = 1 * time.Hour

// RateLimiter enforces per-sender rate limits using state files.
type RateLimiter struct {
	stateDir string
	limit    int
	window   time.Duration
}

// rateState tracks timestamps of recent requests from a sender.
type rateState struct {
	Timestamps []time.Time `json:"timestamps"`
}

// NewRateLimiter creates a rate limiter with per-sender state tracking.
func NewRateLimiter(stateDir string, limit int, window time.Duration) *RateLimiter {
	if limit <= 0 {
		limit = defaultRateLimit
	}
	if window <= 0 {
		window = defaultRateWindow
	}
	return &RateLimiter{
		stateDir: stateDir,
		limit:    limit,
		window:   window,
	}
}

// Check returns nil if the sender is within rate limits.
// Records the current attempt in the state file.
func (r *RateLimiter) Check(sender string) error {
	if err := os.MkdirAll(r.stateDir, 0750); err != nil {
		return fmt.Errorf("create rate limit dir: %w", err)
	}

	path := r.statePath(sender)
	state := r.loadState(path)

	// Prune timestamps outside the window.
	cutoff := time.Now().Add(-r.window)
	var recent []time.Time
	for _, ts := range state.Timestamps {
		if ts.After(cutoff) {
			recent = append(recent, ts)
		}
	}

	if len(recent) >= r.limit {
		return fmt.Errorf("rate limit exceeded: %d jobs in the last %s for %s",
			len(recent), r.window, sender)
	}

	// Record this attempt.
	recent = append(recent, time.Now().UTC())
	state.Timestamps = recent

	return r.saveState(path, state)
}

// statePath returns the state file path for a sender (hashed to avoid FS issues).
func (r *RateLimiter) statePath(sender string) string {
	h := sha256.Sum256([]byte(sender))
	return filepath.Join(r.stateDir, hex.EncodeToString(h[:8])+".json")
}

func (r *RateLimiter) loadState(path string) *rateState {
	data, err := os.ReadFile(path)
	if err != nil {
		return &rateState{}
	}
	var s rateState
	if err := json.Unmarshal(data, &s); err != nil {
		return &rateState{}
	}
	return &s
}

func (r *RateLimiter) saveState(path string, state *rateState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
