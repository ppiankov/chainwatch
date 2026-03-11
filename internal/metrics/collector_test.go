package metrics

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func createObservationDB(t *testing.T, dir string) string {
	t.Helper()
	dbPath := filepath.Join(dir, "observations.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open observation db: %v", err)
	}
	defer func() { _ = db.Close() }()

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
		`CREATE TABLE IF NOT EXISTS finding_hashes (
			hash TEXT PRIMARY KEY,
			first_seen INTEGER NOT NULL,
			last_seen INTEGER NOT NULL,
			wo_id TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'open'
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}
	return dbPath
}

func createLifecycleDB(t *testing.T, dir string) string {
	t.Helper()
	dbPath := filepath.Join(dir, "lifecycle.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open lifecycle db: %v", err)
	}
	defer func() { _ = db.Close() }()

	stmt := `CREATE TABLE IF NOT EXISTS wo_lifecycle (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		wo_id TEXT NOT NULL,
		from_state TEXT NOT NULL DEFAULT '',
		to_state TEXT NOT NULL,
		transitioned_at INTEGER NOT NULL,
		finding TEXT NOT NULL DEFAULT '',
		pr_url TEXT NOT NULL DEFAULT ''
	)`
	if _, err := db.Exec(stmt); err != nil {
		t.Fatalf("create lifecycle schema: %v", err)
	}
	return dbPath
}

func insertObservation(t *testing.T, dbPath, id, obsType string, cachedAt time.Time) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	_, err = db.Exec(`
		INSERT INTO observations (id, job_id, scope, type, evidence, cached_at)
		VALUES (?, ?, 'test-scope', ?, 'evidence', ?)
	`, id, id, obsType, cachedAt.UnixNano())
	if err != nil {
		t.Fatalf("insert observation: %v", err)
	}
}

func insertFindingHash(t *testing.T, dbPath, hash, woID, status string, firstSeen, lastSeen time.Time) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	_, err = db.Exec(`
		INSERT INTO finding_hashes (hash, first_seen, last_seen, wo_id, status)
		VALUES (?, ?, ?, ?, ?)
	`, hash, firstSeen.UnixNano(), lastSeen.UnixNano(), woID, status)
	if err != nil {
		t.Fatalf("insert finding hash: %v", err)
	}
}

func insertLifecycleTransition(t *testing.T, dbPath, woID, fromState, toState string, at time.Time) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	_, err = db.Exec(`
		INSERT INTO wo_lifecycle (wo_id, from_state, to_state, transitioned_at)
		VALUES (?, ?, ?, ?)
	`, woID, fromState, toState, at.UnixNano())
	if err != nil {
		t.Fatalf("insert lifecycle transition: %v", err)
	}
}

func TestFindingMetrics(t *testing.T) {
	dir := t.TempDir()
	dbPath := createObservationDB(t, dir)

	now := time.Now().UTC()

	insertObservation(t, dbPath, "obs-1", "slow_queries", now)
	insertObservation(t, dbPath, "obs-2", "slow_queries", now)
	insertObservation(t, dbPath, "obs-3", "replication_lag", now)

	insertFindingHash(t, dbPath, "hash-1", "WO-001", "open", now.Add(-2*time.Hour), now)
	insertFindingHash(t, dbPath, "hash-2", "WO-002", "closed", now.Add(-4*time.Hour), now.Add(-1*time.Hour))
	insertFindingHash(t, dbPath, "hash-3", "WO-003", "open", now.Add(-1*time.Hour), now)

	c := NewCollector(dbPath, "", nil)
	stats, err := c.FindingMetrics()
	if err != nil {
		t.Fatalf("FindingMetrics: %v", err)
	}

	if stats.TotalFindings != 3 {
		t.Errorf("TotalFindings = %d, want 3", stats.TotalFindings)
	}
	if stats.OpenFindings != 2 {
		t.Errorf("OpenFindings = %d, want 2", stats.OpenFindings)
	}
	if stats.ResolvedFindings != 1 {
		t.Errorf("ResolvedFindings = %d, want 1", stats.ResolvedFindings)
	}
	if stats.FindingsByType["slow_queries"] != 2 {
		t.Errorf("FindingsByType[slow_queries] = %d, want 2", stats.FindingsByType["slow_queries"])
	}
	if stats.FindingsByType["replication_lag"] != 1 {
		t.Errorf("FindingsByType[replication_lag] = %d, want 1", stats.FindingsByType["replication_lag"])
	}
}

func TestPipelineMetrics(t *testing.T) {
	dir := t.TempDir()
	dbPath := createLifecycleDB(t, dir)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// WO-001: finding → wo → dispatched → pr_open → pr_merged → applied → verified
	insertLifecycleTransition(t, dbPath, "WO-001", "", "finding", base)
	insertLifecycleTransition(t, dbPath, "WO-001", "finding", "wo", base.Add(1*time.Hour))
	insertLifecycleTransition(t, dbPath, "WO-001", "wo", "dispatched", base.Add(2*time.Hour))
	insertLifecycleTransition(t, dbPath, "WO-001", "dispatched", "pr_open", base.Add(3*time.Hour))
	insertLifecycleTransition(t, dbPath, "WO-001", "pr_open", "pr_merged", base.Add(4*time.Hour))
	insertLifecycleTransition(t, dbPath, "WO-001", "pr_merged", "applied", base.Add(5*time.Hour))
	insertLifecycleTransition(t, dbPath, "WO-001", "applied", "verified", base.Add(6*time.Hour))

	// WO-002: finding → wo → dispatched (still in dispatched)
	insertLifecycleTransition(t, dbPath, "WO-002", "", "finding", base)
	insertLifecycleTransition(t, dbPath, "WO-002", "finding", "wo", base.Add(1*time.Hour))
	insertLifecycleTransition(t, dbPath, "WO-002", "wo", "dispatched", base.Add(2*time.Hour))

	now := base.Add(30 * time.Hour)
	c := NewCollector("", dbPath, func() time.Time { return now })
	stats, err := c.PipelineMetrics()
	if err != nil {
		t.Fatalf("PipelineMetrics: %v", err)
	}

	if stats.TotalWOs != 2 {
		t.Errorf("TotalWOs = %d, want 2", stats.TotalWOs)
	}
	if stats.WOsByState["verified"] != 1 {
		t.Errorf("WOsByState[verified] = %d, want 1", stats.WOsByState["verified"])
	}
	if stats.WOsByState["dispatched"] != 1 {
		t.Errorf("WOsByState[dispatched] = %d, want 1", stats.WOsByState["dispatched"])
	}

	// Mean time to merge: dispatched(+2h) → pr_merged(+4h) = 2h for WO-001 only
	expectedMerge := 2 * time.Hour
	if stats.MeanTimeToMerge != expectedMerge {
		t.Errorf("MeanTimeToMerge = %v, want %v", stats.MeanTimeToMerge, expectedMerge)
	}

	// Mean time to verify: applied(+5h) → verified(+6h) = 1h for WO-001 only
	expectedVerify := 1 * time.Hour
	if stats.MeanTimeToVerify != expectedVerify {
		t.Errorf("MeanTimeToVerify = %v, want %v", stats.MeanTimeToVerify, expectedVerify)
	}
}

func TestPipelineStalePRs(t *testing.T) {
	dir := t.TempDir()
	dbPath := createLifecycleDB(t, dir)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// WO-001: pr_open 48h ago, never merged → stale
	insertLifecycleTransition(t, dbPath, "WO-001", "", "finding", base)
	insertLifecycleTransition(t, dbPath, "WO-001", "finding", "wo", base.Add(1*time.Hour))
	insertLifecycleTransition(t, dbPath, "WO-001", "wo", "dispatched", base.Add(2*time.Hour))
	insertLifecycleTransition(t, dbPath, "WO-001", "dispatched", "pr_open", base.Add(3*time.Hour))

	// WO-002: pr_open 1h ago → not stale
	insertLifecycleTransition(t, dbPath, "WO-002", "", "finding", base.Add(50*time.Hour))
	insertLifecycleTransition(t, dbPath, "WO-002", "finding", "wo", base.Add(50*time.Hour))
	insertLifecycleTransition(t, dbPath, "WO-002", "wo", "dispatched", base.Add(50*time.Hour))
	insertLifecycleTransition(t, dbPath, "WO-002", "dispatched", "pr_open", base.Add(51*time.Hour))

	now := base.Add(52 * time.Hour)
	c := NewCollector("", dbPath, func() time.Time { return now })
	stats, err := c.PipelineMetrics()
	if err != nil {
		t.Fatalf("PipelineMetrics: %v", err)
	}

	if stats.StalePRs != 1 {
		t.Errorf("StalePRs = %d, want 1", stats.StalePRs)
	}
}

func TestEmptyDatabase(t *testing.T) {
	dir := t.TempDir()
	obsDB := createObservationDB(t, dir)
	lcDB := createLifecycleDB(t, dir)

	c := NewCollector(obsDB, lcDB, nil)

	findings, err := c.FindingMetrics()
	if err != nil {
		t.Fatalf("FindingMetrics on empty: %v", err)
	}
	if findings.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0", findings.TotalFindings)
	}
	if findings.OpenFindings != 0 {
		t.Errorf("OpenFindings = %d, want 0", findings.OpenFindings)
	}
	if len(findings.FindingsByType) != 0 {
		t.Errorf("FindingsByType should be empty, got %v", findings.FindingsByType)
	}

	pipeline, err := c.PipelineMetrics()
	if err != nil {
		t.Fatalf("PipelineMetrics on empty: %v", err)
	}
	if pipeline.TotalWOs != 0 {
		t.Errorf("TotalWOs = %d, want 0", pipeline.TotalWOs)
	}
	if len(pipeline.WOsByState) != 0 {
		t.Errorf("WOsByState should be empty, got %v", pipeline.WOsByState)
	}
}

func TestMeanTimeToResolve(t *testing.T) {
	dir := t.TempDir()
	dbPath := createObservationDB(t, dir)

	now := time.Now().UTC()

	// Two closed findings with known durations
	insertFindingHash(t, dbPath, "h1", "WO-1", "closed", now.Add(-4*time.Hour), now.Add(-2*time.Hour))
	insertFindingHash(t, dbPath, "h2", "WO-2", "closed", now.Add(-6*time.Hour), now.Add(-2*time.Hour))

	// Open finding should not affect MTTR
	insertFindingHash(t, dbPath, "h3", "WO-3", "open", now.Add(-10*time.Hour), now)

	c := NewCollector(dbPath, "", nil)
	stats, err := c.FindingMetrics()
	if err != nil {
		t.Fatalf("FindingMetrics: %v", err)
	}

	// h1: 2h, h2: 4h → avg = 3h
	expected := 3 * time.Hour
	if stats.MeanTimeToResolve != expected {
		t.Errorf("MeanTimeToResolve = %v, want %v", stats.MeanTimeToResolve, expected)
	}
}

func TestMissingDatabasePaths(t *testing.T) {
	c := NewCollector("", "", nil)

	findings, err := c.FindingMetrics()
	if err != nil {
		t.Fatalf("FindingMetrics with empty path: %v", err)
	}
	if findings.TotalFindings != 0 {
		t.Errorf("expected zero findings")
	}

	pipeline, err := c.PipelineMetrics()
	if err != nil {
		t.Fatalf("PipelineMetrics with empty path: %v", err)
	}
	if pipeline.TotalWOs != 0 {
		t.Errorf("expected zero WOs")
	}
}

func TestNonexistentDatabasePaths(t *testing.T) {
	dir := t.TempDir()
	c := NewCollector(
		filepath.Join(dir, "nonexistent-obs.db"),
		filepath.Join(dir, "nonexistent-lc.db"),
		nil,
	)

	findings, err := c.FindingMetrics()
	if err != nil {
		t.Fatalf("FindingMetrics with missing file: %v", err)
	}
	if findings.TotalFindings != 0 {
		t.Errorf("expected zero findings")
	}

	pipeline, err := c.PipelineMetrics()
	if err != nil {
		t.Fatalf("PipelineMetrics with missing file: %v", err)
	}
	if pipeline.TotalWOs != 0 {
		t.Errorf("expected zero WOs")
	}
}

func TestRedactionMetrics(t *testing.T) {
	c := NewCollector("", "", nil)
	stats, err := c.RedactionMetrics()
	if err != nil {
		t.Fatalf("RedactionMetrics: %v", err)
	}
	if stats.TotalRedactions != 0 {
		t.Errorf("expected zero redactions")
	}
	if len(stats.RedactionsByCategory) != 0 {
		t.Errorf("expected empty category map")
	}
}

func TestCollectorIgnoresMissingDBFile(t *testing.T) {
	// Verify no panic or error when DB files don't exist on disk
	noSuchDir := filepath.Join(os.TempDir(), "chainwatch-metrics-test-nonexistent-"+t.Name())
	c := NewCollector(
		filepath.Join(noSuchDir, "obs.db"),
		filepath.Join(noSuchDir, "lc.db"),
		nil,
	)

	stats, err := c.FindingMetrics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.TotalFindings != 0 {
		t.Error("expected zero findings for missing DB")
	}

	pipeline, err := c.PipelineMetrics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pipeline.TotalWOs != 0 {
		t.Error("expected zero WOs for missing DB")
	}
}
