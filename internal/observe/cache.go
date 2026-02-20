package observe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CachedObservation holds raw evidence when LLM classification is unavailable.
// Written to state/cache/ by the daemon processor, retried by the cache sweeper.
type CachedObservation struct {
	ID         string    `json:"id"`
	JobID      string    `json:"job_id"`
	Scope      string    `json:"scope"`
	Type       string    `json:"type"`
	Evidence   string    `json:"evidence"`
	CachedAt   time.Time `json:"cached_at"`
	RetryCount int       `json:"retry_count"`
}

// CacheDir returns the standard cache directory path within a state dir.
func CacheDir(stateDir string) string {
	return filepath.Join(stateDir, "cache")
}

// WriteCache persists a raw observation to the cache directory.
// Uses atomic write (tmp + rename) to prevent partial reads.
func WriteCache(cacheDir string, entry *CachedObservation) error {
	if err := os.MkdirAll(cacheDir, 0750); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cache entry: %w", err)
	}

	filename := entry.ID + ".json"
	tmpPath := filepath.Join(cacheDir, filename+".tmp")
	finalPath := filepath.Join(cacheDir, filename)

	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	return os.Rename(tmpPath, finalPath)
}

// ReadCache reads all cached observations from the cache directory.
// Returns nil (not error) if the directory does not exist.
func ReadCache(cacheDir string) ([]*CachedObservation, error) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var cached []*CachedObservation
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".tmp") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(cacheDir, name))
		if err != nil {
			continue
		}
		var entry CachedObservation
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		cached = append(cached, &entry)
	}
	return cached, nil
}

// RemoveCached removes a processed cache entry.
func RemoveCached(cacheDir, id string) error {
	return os.Remove(filepath.Join(cacheDir, id+".json"))
}
