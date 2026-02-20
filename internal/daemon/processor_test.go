package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupProcessorDirs(t *testing.T) DirConfig {
	t.Helper()
	root := t.TempDir()
	cfg := DirConfig{
		Inbox:  filepath.Join(root, "inbox"),
		Outbox: filepath.Join(root, "outbox"),
		State:  filepath.Join(root, "state"),
	}
	if err := EnsureDirs(cfg); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	return cfg
}

func writeJobFile(t *testing.T, dir string, job *Job) string {
	t.Helper()
	data, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		t.Fatalf("marshal job: %v", err)
	}
	path := filepath.Join(dir, job.ID+".json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write job: %v", err)
	}
	return path
}

func TestProcessorInvalidJSON(t *testing.T) {
	dirs := setupProcessorDirs(t)
	p := NewProcessor(ProcessorConfig{Dirs: dirs})

	// Write invalid JSON.
	path := filepath.Join(dirs.Inbox, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}

	// Processing should write a failed result, not return error.
	if err := p.Process(context.Background(), path); err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	// Check that a failed result was written.
	entries, _ := os.ReadDir(dirs.Outbox)
	if len(entries) == 0 {
		t.Fatal("expected a result file in outbox")
	}
	data, _ := os.ReadFile(filepath.Join(dirs.Outbox, entries[0].Name()))
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.Status != ResultFailed {
		t.Errorf("status = %q, want %q", result.Status, ResultFailed)
	}
}

func TestProcessorInvalidJobValidation(t *testing.T) {
	dirs := setupProcessorDirs(t)
	p := NewProcessor(ProcessorConfig{Dirs: dirs})

	// Write a job with missing required fields.
	job := &Job{
		ID:        "val-001",
		Type:      "unknown_type",
		Target:    JobTarget{Scope: "/tmp"},
		Brief:     "test",
		CreatedAt: time.Now().UTC(),
	}
	path := writeJobFile(t, dirs.Inbox, job)

	if err := p.Process(context.Background(), path); err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	// Check failed result.
	data, err := os.ReadFile(filepath.Join(dirs.Outbox, "val-001.json"))
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Status != ResultFailed {
		t.Errorf("status = %q, want %q", result.Status, ResultFailed)
	}
	if result.Error == "" {
		t.Error("expected error message in result")
	}
}

func TestProcessorStateTransition(t *testing.T) {
	dirs := setupProcessorDirs(t)
	// Use a non-existent chainwatch binary so observe.Run will fail,
	// but we can still test the state transitions.
	p := NewProcessor(ProcessorConfig{
		Dirs:       dirs,
		Chainwatch: "/nonexistent/chainwatch",
	})

	job := &Job{
		ID:        "state-001",
		Type:      JobTypeObserve,
		Target:    JobTarget{Scope: "/tmp"},
		Brief:     "test state transitions",
		Source:    "manual",
		CreatedAt: time.Now().UTC(),
	}
	path := writeJobFile(t, dirs.Inbox, job)

	_ = p.Process(context.Background(), path)

	// Job file should be removed from inbox.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("job file should be removed from inbox after processing")
	}

	// Processing dir should be clean.
	procEntries, _ := os.ReadDir(dirs.ProcessingDir())
	if len(procEntries) != 0 {
		t.Errorf("processing dir should be empty, has %d files", len(procEntries))
	}

	// Result should be in outbox.
	resultPath := filepath.Join(dirs.Outbox, "state-001.json")
	if _, err := os.Stat(resultPath); err != nil {
		t.Error("result file should be in outbox")
	}
}

func TestProcessorResultJSON(t *testing.T) {
	dirs := setupProcessorDirs(t)
	p := NewProcessor(ProcessorConfig{
		Dirs:       dirs,
		Chainwatch: "/nonexistent/chainwatch",
	})

	job := &Job{
		ID:        "json-001",
		Type:      JobTypeObserve,
		Target:    JobTarget{Host: "example.com", Scope: "/tmp"},
		Brief:     "test JSON output",
		Source:    "manual",
		CreatedAt: time.Now().UTC(),
	}
	path := writeJobFile(t, dirs.Inbox, job)
	_ = p.Process(context.Background(), path)

	data, err := os.ReadFile(filepath.Join(dirs.Outbox, "json-001.json"))
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.ID != "json-001" {
		t.Errorf("result ID = %q, want json-001", result.ID)
	}
	if result.CompletedAt.IsZero() {
		t.Error("CompletedAt should be set")
	}
}

func TestNewProcessorDefaults(t *testing.T) {
	p := NewProcessor(ProcessorConfig{})
	if p.cfg.Chainwatch != "chainwatch" {
		t.Errorf("default chainwatch = %q", p.cfg.Chainwatch)
	}
	if p.cfg.AuditLog != "/tmp/nullbot-daemon.jsonl" {
		t.Errorf("default audit log = %q", p.cfg.AuditLog)
	}
}
