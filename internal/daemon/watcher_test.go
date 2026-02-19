package daemon

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestInboxWatcherDetectsNewFile(t *testing.T) {
	inbox := t.TempDir()

	var mu sync.Mutex
	var received []string

	w := NewInboxWatcher(inbox, func(path string) {
		mu.Lock()
		received = append(received, path)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = w.Run(ctx) }()

	// Give watcher time to start.
	time.Sleep(100 * time.Millisecond)

	// Write a job file atomically.
	jobPath := filepath.Join(inbox, "test-001.json")
	tmpPath := jobPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(`{"id":"test-001"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmpPath, jobPath); err != nil {
		t.Fatal(err)
	}

	// Wait for debounce + processing.
	time.Sleep(500 * time.Millisecond)
	cancel()

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 file, got %d", len(received))
	}
	if received[0] != jobPath {
		t.Errorf("got path %q, want %q", received[0], jobPath)
	}
}

func TestInboxWatcherIgnoresTmpFiles(t *testing.T) {
	inbox := t.TempDir()

	var mu sync.Mutex
	var received []string

	w := NewInboxWatcher(inbox, func(path string) {
		mu.Lock()
		received = append(received, path)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = w.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// Write only a .tmp file (should be ignored).
	tmpPath := filepath.Join(inbox, "test-002.json.tmp")
	if err := os.WriteFile(tmpPath, []byte(`{"id":"test-002"}`), 0600); err != nil {
		t.Fatal(err)
	}

	time.Sleep(500 * time.Millisecond)
	cancel()

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 0 {
		t.Errorf("expected 0 files for .tmp, got %d", len(received))
	}
}

func TestInboxWatcherContextCancellation(t *testing.T) {
	inbox := t.TempDir()

	w := NewInboxWatcher(inbox, func(path string) {})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error on cancel, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not stop after context cancellation")
	}
}

func TestPollWatcherDetectsNewFile(t *testing.T) {
	inbox := t.TempDir()

	var mu sync.Mutex
	var received []string

	w := NewPollWatcher(inbox, func(path string) {
		mu.Lock()
		received = append(received, path)
		mu.Unlock()
	}, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = w.Run(ctx) }()

	// Write a job file.
	jobPath := filepath.Join(inbox, "poll-001.json")
	if err := os.WriteFile(jobPath, []byte(`{"id":"poll-001"}`), 0600); err != nil {
		t.Fatal(err)
	}

	// Wait for poll cycle.
	time.Sleep(200 * time.Millisecond)
	cancel()

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 file, got %d", len(received))
	}
}

func TestPollWatcherDoesNotDuplicate(t *testing.T) {
	inbox := t.TempDir()

	var mu sync.Mutex
	var count int

	w := NewPollWatcher(inbox, func(path string) {
		mu.Lock()
		count++
		mu.Unlock()
	}, 50*time.Millisecond)

	// Pre-create a file.
	if err := os.WriteFile(filepath.Join(inbox, "dup-001.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = w.Run(ctx) }()

	// Wait for multiple poll cycles.
	time.Sleep(300 * time.Millisecond)
	cancel()

	mu.Lock()
	defer mu.Unlock()
	if count != 1 {
		t.Errorf("file should be processed exactly once, got %d", count)
	}
}

func TestScanExisting(t *testing.T) {
	inbox := t.TempDir()

	// Create some files.
	for _, name := range []string{"a.json", "b.json", "c.tmp", "d.txt"} {
		if err := os.WriteFile(filepath.Join(inbox, name), []byte(`{}`), 0600); err != nil {
			t.Fatal(err)
		}
	}

	var received []string
	if err := ScanExisting(inbox, func(path string) {
		received = append(received, filepath.Base(path))
	}); err != nil {
		t.Fatal(err)
	}

	if len(received) != 2 {
		t.Fatalf("expected 2 .json files, got %d: %v", len(received), received)
	}
}

func TestScanExistingEmptyDir(t *testing.T) {
	inbox := t.TempDir()
	var count int
	if err := ScanExisting(inbox, func(path string) { count++ }); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestScanExistingMissingDir(t *testing.T) {
	var count int
	if err := ScanExisting("/nonexistent/path", func(path string) { count++ }); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestIsJobFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"job-001.json", true},
		{"test.json", true},
		{"job.json.tmp", false},
		{"readme.txt", false},
		{"data.csv", false},
		{".hidden.json", true},
	}
	for _, tt := range tests {
		if got := isJobFile(tt.path); got != tt.want {
			t.Errorf("isJobFile(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
