package observe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")

	entry := &CachedObservation{
		ID:         "job-001",
		JobID:      "job-001",
		Scope:      "/var/www/site",
		Type:       "wordpress",
		Evidence:   "=== check redirects ===\n$ curl -sI http://example.com\nHTTP/1.1 200 OK\n",
		CachedAt:   time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		RetryCount: 0,
	}

	if err := WriteCache(cacheDir, entry); err != nil {
		t.Fatalf("WriteCache: %v", err)
	}

	entries, err := ReadCache(cacheDir)
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
	if got.Evidence == "" {
		t.Error("Evidence is empty")
	}
	if got.RetryCount != 0 {
		t.Errorf("RetryCount = %d", got.RetryCount)
	}
}

func TestReadCacheMissingDir(t *testing.T) {
	entries, err := ReadCache("/nonexistent/path/cache")
	if err != nil {
		t.Fatalf("expected nil error for missing dir, got %v", err)
	}
	if entries != nil {
		t.Errorf("expected nil entries, got %d", len(entries))
	}
}

func TestRemoveCached(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")

	entry := &CachedObservation{
		ID:       "job-002",
		JobID:    "job-002",
		Scope:    "/tmp",
		Type:     "linux",
		Evidence: "test evidence",
		CachedAt: time.Now().UTC(),
	}

	if err := WriteCache(cacheDir, entry); err != nil {
		t.Fatalf("WriteCache: %v", err)
	}

	if err := RemoveCached(cacheDir, "job-002"); err != nil {
		t.Fatalf("RemoveCached: %v", err)
	}

	entries, err := ReadCache(cacheDir)
	if err != nil {
		t.Fatalf("ReadCache: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries after remove, got %d", len(entries))
	}
}

func TestWriteCacheNoTmpLeftover(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")

	entry := &CachedObservation{
		ID:       "job-003",
		JobID:    "job-003",
		Evidence: "test",
		CachedAt: time.Now().UTC(),
	}

	if err := WriteCache(cacheDir, entry); err != nil {
		t.Fatalf("WriteCache: %v", err)
	}

	files, _ := os.ReadDir(cacheDir)
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".json" {
			t.Errorf("unexpected file in cache dir: %s", f.Name())
		}
	}
}

func TestWriteCacheRetryCountUpdate(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")

	entry := &CachedObservation{
		ID:         "job-004",
		JobID:      "job-004",
		Evidence:   "test",
		CachedAt:   time.Now().UTC(),
		RetryCount: 0,
	}

	if err := WriteCache(cacheDir, entry); err != nil {
		t.Fatal(err)
	}

	// Simulate retry: increment and overwrite.
	entry.RetryCount = 3
	if err := WriteCache(cacheDir, entry); err != nil {
		t.Fatal(err)
	}

	entries, err := ReadCache(cacheDir)
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

func TestCacheDir(t *testing.T) {
	got := CacheDir("/home/nullbot/state")
	want := "/home/nullbot/state/cache"
	if got != want {
		t.Errorf("CacheDir = %q, want %q", got, want)
	}
}
