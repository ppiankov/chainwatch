package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// Config holds full daemon configuration.
type Config struct {
	Dirs         DirConfig
	Profile      string
	Chainwatch   string
	AuditLog     string
	APIURL       string
	APIKey       string
	Model        string
	PollMode     bool
	PollInterval time.Duration
}

// Daemon watches the inbox directory and processes jobs.
type Daemon struct {
	cfg       Config
	processor *Processor
}

// New creates a daemon with validated configuration.
func New(cfg Config) (*Daemon, error) {
	if cfg.Dirs.Inbox == "" || cfg.Dirs.Outbox == "" || cfg.Dirs.State == "" {
		return nil, fmt.Errorf("inbox, outbox, and state directories are required")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = pollDefault
	}

	processor := NewProcessor(ProcessorConfig{
		Dirs:       cfg.Dirs,
		Profile:    cfg.Profile,
		Chainwatch: cfg.Chainwatch,
		AuditLog:   cfg.AuditLog,
		APIURL:     cfg.APIURL,
		APIKey:     cfg.APIKey,
		Model:      cfg.Model,
	})

	return &Daemon{
		cfg:       cfg,
		processor: processor,
	}, nil
}

// Run starts the daemon. Blocks until ctx is cancelled.
// On startup, processes any existing inbox files and orphaned processing files.
func (d *Daemon) Run(ctx context.Context) error {
	// Create directory structure.
	if err := EnsureDirs(d.cfg.Dirs); err != nil {
		return fmt.Errorf("ensure directories: %w", err)
	}

	// Acquire PID file lock to prevent duplicate instances.
	pidPath := filepath.Join(d.cfg.Dirs.State, "daemon.pid")
	if err := acquirePIDLock(pidPath); err != nil {
		return fmt.Errorf("acquire PID lock: %w", err)
	}
	defer func() { _ = os.Remove(pidPath) }()

	// Recovery: move orphaned processing files to failed.
	if err := d.recoverOrphans(); err != nil {
		return fmt.Errorf("recover orphans: %w", err)
	}

	// Process any existing inbox files.
	if err := ScanExisting(d.cfg.Dirs.Inbox, func(path string) {
		if err := d.processor.Process(ctx, path); err != nil {
			fmt.Fprintf(os.Stderr, "daemon: process %s: %v\n", filepath.Base(path), err)
		}
	}); err != nil {
		return fmt.Errorf("scan existing: %w", err)
	}

	// Start expiration sweeper in background.
	gateway := NewGateway(d.cfg.Dirs.Outbox, d.cfg.Dirs.State, defaultTTL)
	go d.runExpirationSweeper(ctx, gateway)

	// Start watching for new files.
	handler := func(path string) {
		if err := d.processor.Process(ctx, path); err != nil {
			fmt.Fprintf(os.Stderr, "daemon: process %s: %v\n", filepath.Base(path), err)
		}
	}

	if d.cfg.PollMode {
		pw := NewPollWatcher(d.cfg.Dirs.Inbox, handler, d.cfg.PollInterval)
		return pw.Run(ctx)
	}

	w := NewInboxWatcher(d.cfg.Dirs.Inbox, handler)
	return w.Run(ctx)
}

// expirationInterval is how often the sweeper checks for expired WOs.
const expirationInterval = 5 * time.Minute

// runExpirationSweeper periodically checks for expired pending WOs.
func (d *Daemon) runExpirationSweeper(ctx context.Context, gateway *Gateway) {
	ticker := time.NewTicker(expirationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := gateway.CheckExpired()
			if err != nil {
				fmt.Fprintf(os.Stderr, "daemon: expiration sweep: %v\n", err)
			} else if n > 0 {
				fmt.Fprintf(os.Stderr, "daemon: expired %d pending WOs\n", n)
			}
		}
	}
}

// recoverOrphans moves files left in state/processing/ to failed results.
// These are jobs that were interrupted by a crash or restart.
func (d *Daemon) recoverOrphans() error {
	procDir := d.cfg.Dirs.ProcessingDir()
	entries, err := os.ReadDir(procDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, e := range entries {
		if e.IsDir() || !isJobFile(e.Name()) {
			continue
		}
		id := e.Name()[:len(e.Name())-5] // strip .json
		result := &Result{
			ID:          id,
			Status:      ResultFailed,
			Error:       "interrupted: job was processing when daemon stopped",
			CompletedAt: time.Now().UTC(),
		}
		if err := d.processor.writeResult(result); err != nil {
			fmt.Fprintf(os.Stderr, "daemon: recover orphan %s: %v\n", id, err)
		}
		_ = os.Remove(filepath.Join(procDir, e.Name()))
	}
	return nil
}

// acquirePIDLock writes the current PID to the file and checks for stale locks.
func acquirePIDLock(path string) error {
	// Check for existing PID file.
	if data, err := os.ReadFile(path); err == nil {
		pid, err := strconv.Atoi(string(data))
		if err == nil {
			// Check if the process is still running.
			if process, err := os.FindProcess(pid); err == nil {
				if err := process.Signal(syscall.Signal(0)); err == nil {
					return fmt.Errorf("another daemon is running (PID %d)", pid)
				}
			}
		}
		// Stale PID file — remove it.
		_ = os.Remove(path)
	}

	// Write our PID.
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600)
}
