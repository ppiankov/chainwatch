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

// maxQueueSize is the buffer size for the work queue channel.
// Must be larger than maxConcurrentJobs to absorb bursts without
// blocking the debounce flush. 200 handles worst-case burst while
// bounding memory.
const maxQueueSize = 200

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

	// ready collects file paths that passed debounce. A single timer
	// resets on each event; when it fires, all accumulated paths flush
	// to the work queue. This creates zero per-file goroutines —
	// preventing the fatal thread exhaustion (newosproc) that occurred
	// when 100 time.AfterFunc goroutines spawned simultaneously.
	var mu sync.Mutex
	ready := make(map[string]bool)

	// Work queue consumed by a fixed pool of workers.
	queue := make(chan string, maxQueueSize)

	// Fixed worker pool — the only goroutines besides the main loop.
	var wg sync.WaitGroup
	for i := 0; i < maxConcurrentJobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range queue {
				func() {
					defer func() {
						if r := recover(); r != nil {
							_ = r
						}
					}()
					w.handler(path)
				}()
			}
		}()
	}

	// flush moves all ready paths into the work queue.
	flush := func() {
		mu.Lock()
		batch := make([]string, 0, len(ready))
		for p := range ready {
			batch = append(batch, p)
		}
		ready = make(map[string]bool)
		mu.Unlock()

		for _, p := range batch {
			select {
			case queue <- p:
			case <-ctx.Done():
				return
			}
		}
	}

	// Single debounce timer — reset on each event, no goroutines.
	// Initialized as stopped; first event starts it.
	debounceTimer := time.NewTimer(w.debounce)
	debounceTimer.Stop()

	defer func() {
		debounceTimer.Stop()
		flush()
		close(queue)
		wg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-debounceTimer.C:
			flush()

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

			mu.Lock()
			ready[event.Name] = true
			mu.Unlock()

			// Reset the single debounce timer. No goroutines created.
			if !debounceTimer.Stop() {
				select {
				case <-debounceTimer.C:
				default:
				}
			}
			debounceTimer.Reset(w.debounce)

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
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
