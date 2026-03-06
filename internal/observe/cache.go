package observe

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// CachedObservation holds raw evidence when LLM classification is unavailable.
// Written to state/cache.db by the daemon processor, retried by the cache sweeper.
type CachedObservation struct {
	ID          string    `json:"id"`
	JobID       string    `json:"job_id"`
	Scope       string    `json:"scope"`
	Type        string    `json:"type"`
	Sensitivity string    `json:"sensitivity,omitempty"`
	Evidence    string    `json:"evidence"`
	CachedAt    time.Time `json:"cached_at"`
	RetryCount  int       `json:"retry_count"`
}

const (
	cacheDBName      = "cache.db"
	legacyCacheDir   = "cache"
	cacheParentPerm  = 0750
	sqliteBusyMillis = 5000
)

// CacheDir returns the standard cache database path within a state dir.
func CacheDir(stateDir string) string {
	return filepath.Join(stateDir, cacheDBName)
}

// WriteCache persists a raw observation to the cache database.
func WriteCache(cachePath string, entry *CachedObservation) error {
	if entry == nil {
		return fmt.Errorf("cache entry is nil")
	}
	if strings.TrimSpace(entry.ID) == "" {
		return fmt.Errorf("cache entry id is required")
	}
	db, err := openCacheDB(cachePath, true)
	if err != nil {
		return err
	}
	defer func() {
		_ = db.Close()
	}()

	return upsertObservation(db, entry)
}

// ReadCache reads all cached observations from the cache database.
// Returns nil (not error) if the database and legacy cache dir do not exist.
func ReadCache(cachePath string) ([]*CachedObservation, error) {
	db, err := openCacheDB(cachePath, false)
	if err != nil {
		return nil, err
	}
	if db == nil {
		return nil, nil
	}
	defer func() {
		_ = db.Close()
	}()

	rows, err := db.Query(`
		SELECT id, job_id, scope, type, sensitivity, evidence, cached_at, retry_count
		FROM observations
		ORDER BY cached_at ASC, id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query cache: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	return scanObservations(rows)
}

// SearchCache returns cached observations where evidence matches an FTS5 query.
func SearchCache(cachePath, query string) ([]*CachedObservation, error) {
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return ReadCache(cachePath)
	}

	db, err := openCacheDB(cachePath, false)
	if err != nil {
		return nil, err
	}
	if db == nil {
		return nil, nil
	}
	defer func() {
		_ = db.Close()
	}()

	result, err := queryFTS(db, trimmed)
	if err == nil {
		return result, nil
	}

	quoted := quoteFTSQuery(trimmed)
	if quoted == trimmed {
		return nil, err
	}
	return queryFTS(db, quoted)
}

// ListByType returns cached observations filtered by observation type.
func ListByType(cachePath, obsType string) ([]*CachedObservation, error) {
	trimmed := strings.TrimSpace(obsType)
	if trimmed == "" {
		return ReadCache(cachePath)
	}

	db, err := openCacheDB(cachePath, false)
	if err != nil {
		return nil, err
	}
	if db == nil {
		return nil, nil
	}
	defer func() {
		_ = db.Close()
	}()

	rows, err := db.Query(`
		SELECT id, job_id, scope, type, sensitivity, evidence, cached_at, retry_count
		FROM observations
		WHERE type = ?
		ORDER BY cached_at DESC, id ASC
	`, trimmed)
	if err != nil {
		return nil, fmt.Errorf("list cache by type: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	return scanObservations(rows)
}

// ListRecent returns cached observations at or after the supplied timestamp.
func ListRecent(cachePath string, since time.Time) ([]*CachedObservation, error) {
	db, err := openCacheDB(cachePath, false)
	if err != nil {
		return nil, err
	}
	if db == nil {
		return nil, nil
	}
	defer func() {
		_ = db.Close()
	}()

	rows, err := db.Query(`
		SELECT id, job_id, scope, type, sensitivity, evidence, cached_at, retry_count
		FROM observations
		WHERE cached_at >= ?
		ORDER BY cached_at DESC, id ASC
	`, since.UTC().UnixNano())
	if err != nil {
		return nil, fmt.Errorf("list recent cache: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	return scanObservations(rows)
}

// RemoveCached removes a processed cache entry.
func RemoveCached(cachePath, id string) error {
	db, err := openCacheDB(cachePath, true)
	if err != nil {
		return err
	}
	defer func() {
		_ = db.Close()
	}()

	if _, err := db.Exec(`DELETE FROM observations WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete cache entry %q: %w", id, err)
	}
	return nil
}

func openCacheDB(cachePath string, create bool) (*sql.DB, error) {
	dbPath, legacyDirPath := resolveCachePaths(cachePath)
	if !create {
		dbExists, err := fileExists(dbPath)
		if err != nil {
			return nil, fmt.Errorf("stat cache db: %w", err)
		}
		legacyExists, err := dirExists(legacyDirPath)
		if err != nil {
			return nil, fmt.Errorf("stat legacy cache dir: %w", err)
		}
		if !dbExists && !legacyExists {
			return nil, nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), cacheParentPerm); err != nil {
		return nil, fmt.Errorf("create cache db parent: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open cache db: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := configureSQLite(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := migrateLegacyCache(db, legacyDirPath); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func resolveCachePaths(cachePath string) (dbPath string, legacyDirPath string) {
	cleanPath := filepath.Clean(cachePath)
	if strings.EqualFold(filepath.Ext(cleanPath), ".db") {
		return cleanPath, filepath.Join(filepath.Dir(cleanPath), legacyCacheDir)
	}
	return filepath.Join(filepath.Dir(cleanPath), cacheDBName), cleanPath
}

func configureSQLite(db *sql.DB) error {
	pragmas := []string{
		fmt.Sprintf("PRAGMA busy_timeout = %d", sqliteBusyMillis),
		"PRAGMA synchronous = NORMAL",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			return fmt.Errorf("configure sqlite %q: %w", pragma, err)
		}
	}

	// journal_mode can briefly contend when many writers open the DB at once.
	// If another writer already flipped the DB into WAL mode, SQLITE_BUSY here
	// is safe to ignore.
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		if !strings.Contains(err.Error(), "SQLITE_BUSY") {
			return fmt.Errorf("configure sqlite %q: %w", "PRAGMA journal_mode = WAL", err)
		}
	}
	return nil
}

func ensureSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS observations (
			id TEXT PRIMARY KEY,
			job_id TEXT NOT NULL DEFAULT '',
			scope TEXT NOT NULL DEFAULT '',
			type TEXT NOT NULL DEFAULT '',
			sensitivity TEXT,
			evidence TEXT NOT NULL DEFAULT '',
			cached_at INTEGER NOT NULL,
			retry_count INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_observations_type ON observations(type)`,
		`CREATE INDEX IF NOT EXISTS idx_observations_cached_at ON observations(cached_at DESC)`,
		`CREATE TABLE IF NOT EXISTS finding_hashes (
			hash TEXT PRIMARY KEY,
			first_seen INTEGER NOT NULL,
			last_seen INTEGER NOT NULL,
			wo_id TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'open'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_finding_hashes_status ON finding_hashes(status)`,
		`CREATE INDEX IF NOT EXISTS idx_finding_hashes_last_seen ON finding_hashes(last_seen DESC)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS observations_fts USING fts5(
			evidence,
			content='observations',
			content_rowid='rowid'
		)`,
		`CREATE TRIGGER IF NOT EXISTS observations_ai AFTER INSERT ON observations BEGIN
			INSERT INTO observations_fts(rowid, evidence) VALUES (new.rowid, new.evidence);
		END`,
		`CREATE TRIGGER IF NOT EXISTS observations_ad AFTER DELETE ON observations BEGIN
			INSERT INTO observations_fts(observations_fts, rowid, evidence)
			VALUES ('delete', old.rowid, old.evidence);
		END`,
		`CREATE TRIGGER IF NOT EXISTS observations_au AFTER UPDATE ON observations BEGIN
			INSERT INTO observations_fts(observations_fts, rowid, evidence)
			VALUES ('delete', old.rowid, old.evidence);
			INSERT INTO observations_fts(rowid, evidence) VALUES (new.rowid, new.evidence);
		END`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("create cache schema: %w", err)
		}
	}

	var observationCount int
	if err := db.QueryRow(`SELECT COUNT(1) FROM observations`).Scan(&observationCount); err != nil {
		return fmt.Errorf("count observations: %w", err)
	}
	if observationCount == 0 {
		return nil
	}

	var ftsCount int
	if err := db.QueryRow(`SELECT COUNT(1) FROM observations_fts`).Scan(&ftsCount); err != nil {
		return fmt.Errorf("count fts rows: %w", err)
	}
	if ftsCount > 0 {
		return nil
	}

	if _, err := db.Exec(`INSERT INTO observations_fts(observations_fts) VALUES ('rebuild')`); err != nil {
		return fmt.Errorf("rebuild fts index: %w", err)
	}
	return nil
}

func migrateLegacyCache(db *sql.DB, legacyDirPath string) error {
	entries, err := os.ReadDir(legacyDirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read legacy cache dir: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin legacy cache migration: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	migratedFiles := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".tmp") {
			continue
		}

		path := filepath.Join(legacyDirPath, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var entry CachedObservation
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		if strings.TrimSpace(entry.ID) == "" {
			continue
		}

		if err := upsertObservation(tx, &entry); err != nil {
			return fmt.Errorf("migrate cache entry %s: %w", path, err)
		}
		migratedFiles = append(migratedFiles, path)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit legacy cache migration: %w", err)
	}
	committed = true

	for _, path := range migratedFiles {
		_ = os.Remove(path)
	}
	_ = os.Remove(legacyDirPath)

	return nil
}

type sqlExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func upsertObservation(execer sqlExecer, entry *CachedObservation) error {
	if strings.TrimSpace(entry.ID) == "" {
		return fmt.Errorf("cache entry id is required")
	}
	if entry.JobID == "" {
		entry.JobID = entry.ID
	}
	if entry.CachedAt.IsZero() {
		entry.CachedAt = time.Now().UTC()
	}

	_, err := execer.Exec(`
		INSERT INTO observations (
			id, job_id, scope, type, sensitivity, evidence, cached_at, retry_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			job_id = excluded.job_id,
			scope = excluded.scope,
			type = excluded.type,
			sensitivity = excluded.sensitivity,
			evidence = excluded.evidence,
			cached_at = excluded.cached_at,
			retry_count = excluded.retry_count
	`,
		entry.ID,
		entry.JobID,
		entry.Scope,
		entry.Type,
		entry.Sensitivity,
		entry.Evidence,
		entry.CachedAt.UTC().UnixNano(),
		entry.RetryCount,
	)
	if err != nil {
		return fmt.Errorf("upsert cache entry %q: %w", entry.ID, err)
	}
	return nil
}

func queryFTS(db *sql.DB, query string) ([]*CachedObservation, error) {
	rows, err := db.Query(`
		SELECT o.id, o.job_id, o.scope, o.type, o.sensitivity, o.evidence, o.cached_at, o.retry_count
		FROM observations o
		JOIN observations_fts ON observations_fts.rowid = o.rowid
		WHERE observations_fts MATCH ?
		ORDER BY bm25(observations_fts), o.cached_at DESC, o.id ASC
	`, query)
	if err != nil {
		return nil, fmt.Errorf("search cache: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()
	return scanObservations(rows)
}

func quoteFTSQuery(query string) string {
	if strings.HasPrefix(query, "\"") && strings.HasSuffix(query, "\"") {
		return query
	}
	escaped := strings.ReplaceAll(query, "\"", "\"\"")
	return `"` + escaped + `"`
}

func scanObservations(rows *sql.Rows) ([]*CachedObservation, error) {
	var cached []*CachedObservation
	for rows.Next() {
		var (
			entry       CachedObservation
			sensitivity sql.NullString
			cachedAt    int64
		)

		if err := rows.Scan(
			&entry.ID,
			&entry.JobID,
			&entry.Scope,
			&entry.Type,
			&sensitivity,
			&entry.Evidence,
			&cachedAt,
			&entry.RetryCount,
		); err != nil {
			return nil, fmt.Errorf("scan cache row: %w", err)
		}
		if sensitivity.Valid {
			entry.Sensitivity = sensitivity.String
		}
		entry.CachedAt = time.Unix(0, cachedAt).UTC()
		cached = append(cached, &entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cache rows: %w", err)
	}
	return cached, nil
}

func fileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return !info.IsDir(), nil
}

func dirExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return info.IsDir(), nil
}
