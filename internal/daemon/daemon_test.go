package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testDaemonConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	return Config{
		Dirs: DirConfig{
			Inbox:  filepath.Join(root, "inbox"),
			Outbox: filepath.Join(root, "outbox"),
			State:  filepath.Join(root, "state"),
		},
		Chainwatch:   "/nonexistent/chainwatch",
		PollMode:     true,
		PollInterval: 50 * time.Millisecond,
	}
}

func TestNewDaemonValidation(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestNewDaemonValid(t *testing.T) {
	cfg := testDaemonConfig(t)
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d.processor == nil {
		t.Error("processor should not be nil")
	}
}

func TestDaemonProcessesExistingFiles(t *testing.T) {
	cfg := testDaemonConfig(t)
	if err := EnsureDirs(cfg.Dirs); err != nil {
		t.Fatal(err)
	}

	// Pre-create a job in inbox.
	job := &Job{
		ID:        "existing-001",
		Type:      JobTypeObserve,
		Target:    JobTarget{Scope: "/tmp"},
		Brief:     "pre-existing job",
		Source:    "manual",
		CreatedAt: time.Now().UTC(),
	}
	data, _ := json.MarshalIndent(job, "", "  ")
	if err := os.WriteFile(filepath.Join(cfg.Dirs.Inbox, "existing-001.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_ = d.Run(ctx)

	// Check result in outbox.
	resultPath := filepath.Join(cfg.Dirs.Outbox, "existing-001.json")
	if _, err := os.Stat(resultPath); err != nil {
		t.Error("expected result file in outbox for pre-existing job")
	}
}

func TestDaemonRecoverOrphans(t *testing.T) {
	cfg := testDaemonConfig(t)
	if err := EnsureDirs(cfg.Dirs); err != nil {
		t.Fatal(err)
	}

	// Simulate an orphaned file in processing.
	orphanPath := filepath.Join(cfg.Dirs.ProcessingDir(), "orphan-001.json")
	if err := os.WriteFile(orphanPath, []byte(`{"id":"orphan-001"}`), 0600); err != nil {
		t.Fatal(err)
	}

	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_ = d.Run(ctx)

	// Orphan should be cleaned from processing.
	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Error("orphan should be removed from processing")
	}

	// Failed result should be in outbox.
	resultPath := filepath.Join(cfg.Dirs.Outbox, "orphan-001.json")
	data, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal("expected failed result in outbox")
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != ResultFailed {
		t.Errorf("orphan result status = %q, want %q", result.Status, ResultFailed)
	}
}

func TestDaemonGracefulShutdown(t *testing.T) {
	cfg := testDaemonConfig(t)
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil on graceful shutdown, got: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not stop after context cancellation")
	}
}

func TestDaemonPIDLock(t *testing.T) {
	cfg := testDaemonConfig(t)
	if err := EnsureDirs(cfg.Dirs); err != nil {
		t.Fatal(err)
	}

	pidPath := filepath.Join(cfg.Dirs.State, "daemon.pid")

	// First lock should succeed.
	if err := acquirePIDLock(pidPath); err != nil {
		t.Fatalf("first lock: %v", err)
	}

	// Second lock should fail (our process is still running).
	if err := acquirePIDLock(pidPath); err == nil {
		t.Error("expected error for duplicate PID lock")
	}

	// Clean up.
	_ = os.Remove(pidPath)
}

func TestDaemonPIDLockStaleCleanup(t *testing.T) {
	cfg := testDaemonConfig(t)
	if err := EnsureDirs(cfg.Dirs); err != nil {
		t.Fatal(err)
	}

	pidPath := filepath.Join(cfg.Dirs.State, "daemon.pid")

	// Write a stale PID (very high PID unlikely to be running).
	if err := os.WriteFile(pidPath, []byte("9999999"), 0600); err != nil {
		t.Fatal(err)
	}

	// Lock should succeed after cleaning stale PID.
	if err := acquirePIDLock(pidPath); err != nil {
		t.Fatalf("stale PID cleanup failed: %v", err)
	}

	_ = os.Remove(pidPath)
}
