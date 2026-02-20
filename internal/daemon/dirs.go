package daemon

import (
	"fmt"
	"os"
	"path/filepath"
)

// dirPerm is the permission for daemon-managed directories.
const dirPerm = 0750

// DirConfig holds the daemon directory layout.
type DirConfig struct {
	Inbox  string // incoming job files
	Outbox string // completed results
	State  string // state/{processing,approved,rejected,ingested}
}

// DefaultDirConfig returns reasonable defaults for local development.
func DefaultDirConfig() DirConfig {
	return DirConfig{
		Inbox:  "/home/nullbot/inbox",
		Outbox: "/home/nullbot/outbox",
		State:  "/home/nullbot/state",
	}
}

// ProcessingDir returns the path to the processing subdirectory.
func (d DirConfig) ProcessingDir() string {
	return filepath.Join(d.State, "processing")
}

// ApprovedDir returns the path to the approved subdirectory.
func (d DirConfig) ApprovedDir() string {
	return filepath.Join(d.State, "approved")
}

// RejectedDir returns the path to the rejected subdirectory.
func (d DirConfig) RejectedDir() string {
	return filepath.Join(d.State, "rejected")
}

// IngestedDir returns the path to the ingested subdirectory.
func (d DirConfig) IngestedDir() string {
	return filepath.Join(d.State, "ingested")
}

// CacheDir returns the path to the observation cache subdirectory.
func (d DirConfig) CacheDir() string {
	return filepath.Join(d.State, "cache")
}

// EnsureDirs creates all required directories. Idempotent.
func EnsureDirs(cfg DirConfig) error {
	dirs := []string{
		cfg.Inbox,
		cfg.Outbox,
		cfg.ProcessingDir(),
		cfg.ApprovedDir(),
		cfg.RejectedDir(),
		cfg.IngestedDir(),
		cfg.CacheDir(),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, dirPerm); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	return nil
}

// ValidateSameFilesystem checks that inbox, outbox, and state directories
// are on the same filesystem. This is required for atomic rename operations.
func ValidateSameFilesystem(cfg DirConfig) error {
	if err := EnsureDirs(cfg); err != nil {
		return err
	}

	inboxDev, err := deviceID(cfg.Inbox)
	if err != nil {
		return fmt.Errorf("stat inbox: %w", err)
	}
	outboxDev, err := deviceID(cfg.Outbox)
	if err != nil {
		return fmt.Errorf("stat outbox: %w", err)
	}
	stateDev, err := deviceID(cfg.State)
	if err != nil {
		return fmt.Errorf("stat state: %w", err)
	}

	if inboxDev != outboxDev || inboxDev != stateDev {
		return fmt.Errorf("inbox, outbox, and state must be on the same filesystem for atomic renames")
	}
	return nil
}
