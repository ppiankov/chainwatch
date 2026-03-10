package incident

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS incidents (
	id TEXT PRIMARY KEY,
	finding_hash TEXT NOT NULL,
	source TEXT NOT NULL,
	key TEXT NOT NULL,
	url TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'open',
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_finding_hash ON incidents(finding_hash);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
`

// Store persists incidents for deduplication.
type Store struct {
	db *sql.DB
}

// Open creates or opens the SQLite incident store at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open incident store: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	for _, pragma := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA synchronous = NORMAL",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("pragma %s: %w", pragma, err)
		}
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	return &Store{db: db}, nil
}

// FindByHash returns the most recent open incident for a finding hash, or nil if none exists.
func (s *Store) FindByHash(hash string) (*Incident, error) {
	row := s.db.QueryRow(
		`SELECT id, finding_hash, source, key, url, status, created_at
		 FROM incidents WHERE finding_hash = ? AND status = 'open'
		 ORDER BY created_at DESC LIMIT 1`,
		hash,
	)

	var inc Incident
	var createdNano int64
	err := row.Scan(&inc.ID, &inc.FindingHash, &inc.Source, &inc.Key, &inc.URL, &inc.Status, &createdNano)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find by hash: %w", err)
	}
	inc.CreatedAt = time.Unix(0, createdNano)
	return &inc, nil
}

// Save persists an incident record.
func (s *Store) Save(inc *Incident) error {
	_, err := s.db.Exec(
		`INSERT INTO incidents (id, finding_hash, source, key, url, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET status = excluded.status`,
		inc.ID, inc.FindingHash, inc.Source, inc.Key, inc.URL, inc.Status, inc.CreatedAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("save incident: %w", err)
	}
	return nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}
