package maildrop

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRateLimiterFirstAllowed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ratelimit")
	rl := NewRateLimiter(dir, 10, 1*time.Hour)

	if err := rl.Check("admin@example.com"); err != nil {
		t.Errorf("first request should be allowed: %v", err)
	}
}

func TestRateLimiterWithinLimit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ratelimit")
	rl := NewRateLimiter(dir, 3, 1*time.Hour)

	for i := 0; i < 3; i++ {
		if err := rl.Check("admin@example.com"); err != nil {
			t.Fatalf("request %d should be allowed: %v", i+1, err)
		}
	}
}

func TestRateLimiterExceedsLimit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ratelimit")
	rl := NewRateLimiter(dir, 3, 1*time.Hour)

	for i := 0; i < 3; i++ {
		if err := rl.Check("admin@example.com"); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}

	if err := rl.Check("admin@example.com"); err == nil {
		t.Error("4th request should be rate-limited")
	}
}

func TestRateLimiterWindowExpiration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ratelimit")
	// Use a very short window.
	rl := NewRateLimiter(dir, 1, 10*time.Millisecond)

	if err := rl.Check("admin@example.com"); err != nil {
		t.Fatal(err)
	}

	// Wait for window to expire.
	time.Sleep(20 * time.Millisecond)

	if err := rl.Check("admin@example.com"); err != nil {
		t.Errorf("request after window should be allowed: %v", err)
	}
}

func TestRateLimiterPerSender(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ratelimit")
	rl := NewRateLimiter(dir, 1, 1*time.Hour)

	if err := rl.Check("a@example.com"); err != nil {
		t.Fatal(err)
	}

	// Different sender should have its own limit.
	if err := rl.Check("b@example.com"); err != nil {
		t.Errorf("different sender should have separate limit: %v", err)
	}
}

func TestRateLimiterDefaults(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ratelimit")
	rl := NewRateLimiter(dir, 0, 0)

	if rl.limit != defaultRateLimit {
		t.Errorf("default limit = %d, want %d", rl.limit, defaultRateLimit)
	}
	if rl.window != defaultRateWindow {
		t.Errorf("default window = %v, want %v", rl.window, defaultRateWindow)
	}
}
