package observe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWriteCacheRoundTrip(t *testing.T) {
	stateDir := t.TempDir()
	cachePath := CacheDir(stateDir)

	entry := &CachedObservation{
		ID:          "job-001",
		JobID:       "job-001",
		Scope:       "/var/www/site",
		Type:        "wordpress",
		Sensitivity: "local",
		Evidence:    "=== check redirects ===\n$ curl -sI http://example.com\nHTTP/1.1 200 OK\n",
		CachedAt:    time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		RetryCount:  0,
	}

	if err := WriteCache(cachePath, entry); err != nil {
		t.Fatalf("WriteCache: %v", err)
	}

	entries, err := ReadCache(cachePath)
	if err != nil {
		t.Fatalf("ReadCache: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	got := entries[0]
	if got.ID != "job-001" {
		t.Errorf("ID = %q", got.ID)
	}
	if got.Scope != "/var/www/site" {
		t.Errorf("Scope = %q", got.Scope)
	}
	if got.Type != "wordpress" {
		t.Errorf("Type = %q", got.Type)
	}
	if got.Sensitivity != "local" {
		t.Errorf("Sensitivity = %q, want \"local\"", got.Sensitivity)
	}
	if got.Evidence == "" {
		t.Error("Evidence is empty")
	}
	if got.RetryCount != 0 {
		t.Errorf("RetryCount = %d", got.RetryCount)
	}
}

func TestReadCacheMissingDB(t *testing.T) {
	entries, err := ReadCache(filepath.Join(t.TempDir(), "missing", "cache.db"))
	if err != nil {
		t.Fatalf("expected nil error for missing db path, got %v", err)
	}
	if entries != nil {
		t.Errorf("expected nil entries, got %d", len(entries))
	}
}

func TestRemoveCached(t *testing.T) {
	stateDir := t.TempDir()
	cachePath := CacheDir(stateDir)

	entry := &CachedObservation{
		ID:       "job-002",
		JobID:    "job-002",
		Scope:    "/tmp",
		Type:     "linux",
		Evidence: "test evidence",
		CachedAt: time.Now().UTC(),
	}

	if err := WriteCache(cachePath, entry); err != nil {
		t.Fatalf("WriteCache: %v", err)
	}

	if err := RemoveCached(cachePath, "job-002"); err != nil {
		t.Fatalf("RemoveCached: %v", err)
	}

	entries, err := ReadCache(cachePath)
	if err != nil {
		t.Fatalf("ReadCache: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries after remove, got %d", len(entries))
	}
}

func TestWriteCacheRetryCountUpdate(t *testing.T) {
	stateDir := t.TempDir()
	cachePath := CacheDir(stateDir)

	entry := &CachedObservation{
		ID:         "job-004",
		JobID:      "job-004",
		Evidence:   "test",
		CachedAt:   time.Now().UTC(),
		RetryCount: 0,
	}

	if err := WriteCache(cachePath, entry); err != nil {
		t.Fatal(err)
	}

	// Simulate retry: increment and overwrite.
	entry.RetryCount = 3
	if err := WriteCache(cachePath, entry); err != nil {
		t.Fatal(err)
	}

	entries, err := ReadCache(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].RetryCount != 3 {
		t.Errorf("RetryCount = %d, want 3", entries[0].RetryCount)
	}
}

func TestSearchCache(t *testing.T) {
	stateDir := t.TempDir()
	cachePath := CacheDir(stateDir)

	entries := []*CachedObservation{
		{
			ID:       "job-005",
			JobID:    "job-005",
			Type:     "wordpress",
			Evidence: "found suspicious code and redirect chain",
			CachedAt: time.Now().UTC(),
		},
		{
			ID:       "job-006",
			JobID:    "job-006",
			Type:     "linux",
			Evidence: "normal package listing",
			CachedAt: time.Now().UTC(),
		},
	}
	for _, entry := range entries {
		if err := WriteCache(cachePath, entry); err != nil {
			t.Fatalf("WriteCache(%s): %v", entry.ID, err)
		}
	}

	got, err := SearchCache(cachePath, "suspicious")
	if err != nil {
		t.Fatalf("SearchCache: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 search result, got %d", len(got))
	}
	if got[0].ID != "job-005" {
		t.Fatalf("result ID = %s, want job-005", got[0].ID)
	}
}

func TestListByType(t *testing.T) {
	stateDir := t.TempDir()
	cachePath := CacheDir(stateDir)

	write := func(id, obsType string) {
		t.Helper()
		err := WriteCache(cachePath, &CachedObservation{
			ID:       id,
			JobID:    id,
			Type:     obsType,
			Evidence: "evidence",
			CachedAt: time.Now().UTC(),
		})
		if err != nil {
			t.Fatalf("WriteCache(%s): %v", id, err)
		}
	}

	write("job-007", "wordpress")
	write("job-008", "linux")
	write("job-009", "wordpress")

	got, err := ListByType(cachePath, "wordpress")
	if err != nil {
		t.Fatalf("ListByType: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 wordpress entries, got %d", len(got))
	}
	for _, entry := range got {
		if entry.Type != "wordpress" {
			t.Fatalf("unexpected type %q", entry.Type)
		}
	}
}

func TestListRecent(t *testing.T) {
	stateDir := t.TempDir()
	cachePath := CacheDir(stateDir)

	oldTime := time.Now().UTC().Add(-2 * time.Hour)
	newTime := time.Now().UTC().Add(-30 * time.Minute)

	if err := WriteCache(cachePath, &CachedObservation{
		ID:       "job-010",
		JobID:    "job-010",
		Type:     "linux",
		Evidence: "old",
		CachedAt: oldTime,
	}); err != nil {
		t.Fatalf("WriteCache old: %v", err)
	}
	if err := WriteCache(cachePath, &CachedObservation{
		ID:       "job-011",
		JobID:    "job-011",
		Type:     "linux",
		Evidence: "new",
		CachedAt: newTime,
	}); err != nil {
		t.Fatalf("WriteCache new: %v", err)
	}

	got, err := ListRecent(cachePath, time.Now().UTC().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("ListRecent: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 recent entry, got %d", len(got))
	}
	if got[0].ID != "job-011" {
		t.Fatalf("recent ID = %q, want job-011", got[0].ID)
	}
}

func TestCacheDir(t *testing.T) {
	got := CacheDir("/home/nullbot/state")
	want := "/home/nullbot/state/cache.db"
	if got != want {
		t.Errorf("CacheDir = %q, want %q", got, want)
	}
}

func TestMigrateLegacyJSONCache(t *testing.T) {
	stateDir := t.TempDir()
	cachePath := CacheDir(stateDir)
	legacyDir := filepath.Join(stateDir, "cache")

	if err := os.MkdirAll(legacyDir, 0750); err != nil {
		t.Fatalf("mkdir legacy cache dir: %v", err)
	}

	legacyEntry := &CachedObservation{
		ID:          "job-012",
		JobID:       "job-012",
		Scope:       "/var/www/site",
		Type:        "wordpress",
		Sensitivity: "local",
		Evidence:    "legacy suspicious code",
		CachedAt:    time.Date(2025, 1, 1, 11, 0, 0, 0, time.UTC),
		RetryCount:  2,
	}
	data, err := json.MarshalIndent(legacyEntry, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy entry: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, legacyEntry.ID+".json"), data, 0600); err != nil {
		t.Fatalf("write legacy entry: %v", err)
	}

	got, err := ReadCache(cachePath)
	if err != nil {
		t.Fatalf("ReadCache migrate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 migrated entry, got %d", len(got))
	}
	if got[0].ID != legacyEntry.ID {
		t.Fatalf("migrated ID = %q, want %q", got[0].ID, legacyEntry.ID)
	}

	if _, err := os.Stat(legacyDir); !os.IsNotExist(err) {
		t.Fatalf("legacy cache dir should be removed after migration, err=%v", err)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache.db should exist after migration: %v", err)
	}
}

func TestWriteCacheConcurrentAccess(t *testing.T) {
	stateDir := t.TempDir()
	cachePath := CacheDir(stateDir)

	const workers = 6
	const perWorker = 15

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		workerID := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				id := fmt.Sprintf("job-%d-%d", workerID, j)
				entry := &CachedObservation{
					ID:       id,
					JobID:    id,
					Type:     "linux",
					Evidence: "concurrent write",
					CachedAt: time.Now().UTC(),
				}
				if err := WriteCache(cachePath, entry); err != nil {
					t.Errorf("WriteCache: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	entries, err := ReadCache(cachePath)
	if err != nil {
		t.Fatalf("ReadCache: %v", err)
	}
	if len(entries) != workers*perWorker {
		t.Fatalf("expected %d entries, got %d", workers*perWorker, len(entries))
	}
}
