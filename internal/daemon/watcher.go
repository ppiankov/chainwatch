package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// debounceDefault is the default debounce interval for file events.
const debounceDefault = 200 * time.Millisecond

// maxConcurrentJobs limits how many inbox files are processed simultaneously.
// Prevents resource exhaustion under burst load (e.g., 100 files at once).
const maxConcurrentJobs = 5

// pollDefault is the default polling interval when fsnotify is unavailable.
const pollDefault = 5 * time.Second

// InboxWatcher watches a directory for new .json files using fsnotify.
type InboxWatcher struct {
	inbox    string
	handler  func(path string)
	debounce time.Duration
}

// NewInboxWatcher creates a watcher for the inbox directory.
func NewInboxWatcher(inbox string, handler func(path string)) *InboxWatcher {
	return &InboxWatcher{
		inbox:    inbox,
		handler:  handler,
		debounce: debounceDefault,
	}
}

// Run watches the inbox for new .json files. Blocks until ctx is cancelled.
func (w *InboxWatcher) Run(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer func() { _ = watcher.Close() }()

	if err := watcher.Add(w.inbox); err != nil {
		return err
	}

	// pending tracks files that were recently created but haven't been
	// dispatched yet (debounce window). Guarded by mu because AfterFunc
	// callbacks run in separate goroutines.
	var mu sync.Mutex
	pending := make(map[string]*time.Timer)

	// sem limits concurrent handler goroutines to prevent resource
	// exhaustion when many files arrive simultaneously.
	sem := make(chan struct{}, maxConcurrentJobs)

	for {
		select {
		case <-ctx.Done():
			mu.Lock()
			for _, t := range pending {
				t.Stop()
			}
			mu.Unlock()
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if !event.Has(fsnotify.Create) {
				continue
			}
			if !isJobFile(event.Name) {
				continue
			}

			path := event.Name
			mu.Lock()
			if t, exists := pending[path]; exists {
				t.Stop()
			}
			pending[path] = time.AfterFunc(w.debounce, func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				defer func() {
					if r := recover(); r != nil {
						// Log panic but don't crash the daemon.
						// The file stays unprocessed; operator can retry.
						_ = r
					}
				}()
				w.handler(path)
				mu.Lock()
				delete(pending, path)
				mu.Unlock()
			})
			mu.Unlock()

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			// Log error but continue watching.
			_ = err
		}
	}
}

// PollWatcher watches a directory for new .json files using polling.
// Used as a fallback when fsnotify is unavailable (e.g., NFS).
type PollWatcher struct {
	inbox    string
	handler  func(path string)
	interval time.Duration
	seen     map[string]bool
}

// NewPollWatcher creates a polling-based watcher.
func NewPollWatcher(inbox string, handler func(path string), interval time.Duration) *PollWatcher {
	if interval == 0 {
		interval = pollDefault
	}
	return &PollWatcher{
		inbox:    inbox,
		handler:  handler,
		interval: interval,
		seen:     make(map[string]bool),
	}
}

// Run polls the inbox directory. Blocks until ctx is cancelled.
func (w *PollWatcher) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w.scan()
		}
	}
}

// scan checks for new .json files in the inbox.
func (w *PollWatcher) scan() {
	entries, err := os.ReadDir(w.inbox)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(w.inbox, e.Name())
		if !isJobFile(path) {
			continue
		}
		if w.seen[path] {
			continue
		}
		w.seen[path] = true
		w.handler(path)
	}
}

// ScanExisting processes any .json files already present in the inbox.
// Called at startup to handle files that arrived while the daemon was down.
func ScanExisting(inbox string, handler func(path string)) error {
	entries, err := os.ReadDir(inbox)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(inbox, e.Name())
		if isJobFile(path) {
			handler(path)
		}
	}
	return nil
}

// isJobFile returns true if the file is a .json file (not a .tmp partial write).
func isJobFile(path string) bool {
	name := filepath.Base(path)
	return strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".tmp")
}
