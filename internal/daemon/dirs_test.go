package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureDirs(t *testing.T) {
	root := t.TempDir()
	cfg := DirConfig{
		Inbox:  filepath.Join(root, "inbox"),
		Outbox: filepath.Join(root, "outbox"),
		State:  filepath.Join(root, "state"),
	}

	if err := EnsureDirs(cfg); err != nil {
		t.Fatalf("EnsureDirs failed: %v", err)
	}

	expected := []string{
		cfg.Inbox,
		cfg.Outbox,
		cfg.ProcessingDir(),
		cfg.ApprovedDir(),
		cfg.RejectedDir(),
		cfg.IngestedDir(),
		cfg.CacheDir(),
	}
	for _, dir := range expected {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("directory %s not created: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", dir)
		}
	}
}

func TestEnsureDirsIdempotent(t *testing.T) {
	root := t.TempDir()
	cfg := DirConfig{
		Inbox:  filepath.Join(root, "inbox"),
		Outbox: filepath.Join(root, "outbox"),
		State:  filepath.Join(root, "state"),
	}

	if err := EnsureDirs(cfg); err != nil {
		t.Fatalf("first EnsureDirs: %v", err)
	}
	if err := EnsureDirs(cfg); err != nil {
		t.Fatalf("second EnsureDirs should be idempotent: %v", err)
	}
}

func TestDirConfigSubdirectories(t *testing.T) {
	cfg := DirConfig{State: "/home/nullbot/state"}

	if got := cfg.ProcessingDir(); got != "/home/nullbot/state/processing" {
		t.Errorf("ProcessingDir = %q", got)
	}
	if got := cfg.ApprovedDir(); got != "/home/nullbot/state/approved" {
		t.Errorf("ApprovedDir = %q", got)
	}
	if got := cfg.RejectedDir(); got != "/home/nullbot/state/rejected" {
		t.Errorf("RejectedDir = %q", got)
	}
	if got := cfg.IngestedDir(); got != "/home/nullbot/state/ingested" {
		t.Errorf("IngestedDir = %q", got)
	}
	if got := cfg.CacheDir(); got != "/home/nullbot/state/cache" {
		t.Errorf("CacheDir = %q", got)
	}
}

func TestValidateSameFilesystem(t *testing.T) {
	root := t.TempDir()
	cfg := DirConfig{
		Inbox:  filepath.Join(root, "inbox"),
		Outbox: filepath.Join(root, "outbox"),
		State:  filepath.Join(root, "state"),
	}

	if err := ValidateSameFilesystem(cfg); err != nil {
		t.Errorf("same tempdir should be same filesystem: %v", err)
	}
}
