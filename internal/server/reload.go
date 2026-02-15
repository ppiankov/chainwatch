package server

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Reloader watches policy and denylist files for changes and triggers hot-reload.
type Reloader struct {
	watcher *fsnotify.Watcher
	server  *Server
	paths   []string
}

// NewReloader creates a file watcher for the given paths.
func NewReloader(server *Server, paths []string) (*Reloader, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	var watched []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := watcher.Add(p); err != nil {
			watcher.Close()
			return nil, fmt.Errorf("failed to watch %q: %w", p, err)
		}
		watched = append(watched, p)
	}

	return &Reloader{
		watcher: watcher,
		server:  server,
		paths:   watched,
	}, nil
}

// Run watches for file changes and reloads policy. Blocks until ctx is cancelled.
func (r *Reloader) Run(ctx context.Context) error {
	defer r.watcher.Close()

	// Debounce: wait 500ms after last write before reloading
	var debounce *time.Timer

	for {
		select {
		case <-ctx.Done():
			if debounce != nil {
				debounce.Stop()
			}
			return nil

		case event, ok := <-r.watcher.Events:
			if !ok {
				return nil
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				if debounce != nil {
					debounce.Stop()
				}
				debounce = time.AfterFunc(500*time.Millisecond, func() {
					if err := r.server.ReloadPolicy(); err != nil {
						fmt.Fprintf(os.Stderr, "hot-reload failed: %v\n", err)
					} else {
						fmt.Fprintf(os.Stderr, "hot-reload: policy reloaded\n")
					}
				})
			}

		case err, ok := <-r.watcher.Errors:
			if !ok {
				return nil
			}
			fmt.Fprintf(os.Stderr, "file watcher error: %v\n", err)
		}
	}
}
