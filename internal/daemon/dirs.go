package daemon

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
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

// moveFile moves src to dst using os.Rename. If rename fails with EXDEV
// (cross-device link, common with systemd ReadWritePaths bind mounts),
// it falls back to copy + remove.
func moveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	// Check for EXDEV (cross-device link).
	var errno syscall.Errno
	if !errors.As(err, &errno) || errno != syscall.EXDEV {
		return err
	}
	// Fallback: copy then remove.
	if err := copyFile(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

// copyFile copies src to dst preserving permissions.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}
