package metrics

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteBusyMillis = 5000

// FindingStats summarizes finding hash data from the observation cache.
type FindingStats struct {
	TotalFindings     int            `json:"total_findings"`
	OpenFindings      int            `json:"open_findings"`
	ResolvedFindings  int            `json:"resolved_findings"`
	FindingsByType    map[string]int `json:"findings_by_type"`
	MeanTimeToResolve time.Duration  `json:"mean_time_to_resolve_ns"`
}

// PipelineStats summarizes WO lifecycle data.
type PipelineStats struct {
	TotalWOs         int            `json:"total_wos"`
	WOsByState       map[string]int `json:"wos_by_state"`
	MeanTimeToMerge  time.Duration  `json:"mean_time_to_merge_ns"`
	MeanTimeToVerify time.Duration  `json:"mean_time_to_verify_ns"`
	StalePRs         int            `json:"stale_prs"`
}

// RedactionStats summarizes redaction counts. Currently a placeholder
// since the existing schema does not store redaction data.
type RedactionStats struct {
	TotalRedactions      int            `json:"total_redactions"`
	RedactionsByCategory map[string]int `json:"redactions_by_category"`
}

// Collector queries existing SQLite databases for pipeline metrics.
type Collector struct {
	observationDBPath string
	lifecycleDBPath   string
	nowFn             func() time.Time
}

// NewCollector creates a metrics collector. Both paths are optional;
// methods return zero-value stats when their database is unavailable.
func NewCollector(observationDBPath, lifecycleDBPath string, nowFn func() time.Time) *Collector {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Collector{
		observationDBPath: strings.TrimSpace(observationDBPath),
		lifecycleDBPath:   strings.TrimSpace(lifecycleDBPath),
		nowFn:             nowFn,
	}
}

// FindingMetrics queries observation_hashes and observations tables.
func (c *Collector) FindingMetrics() (*FindingStats, error) {
	stats := &FindingStats{
		FindingsByType: make(map[string]int),
	}

	if c.observationDBPath == "" {
		return stats, nil
	}

	db, err := openReadOnly(c.observationDBPath)
	if err != nil {
		return stats, nil // DB missing is not an error for metrics
	}
	defer func() { _ = db.Close() }()

	// Total, open, resolved from finding_hashes
	row := db.QueryRow(`SELECT COUNT(*) FROM finding_hashes`)
	if err := row.Scan(&stats.TotalFindings); err != nil {
		return nil, fmt.Errorf("count finding hashes: %w", err)
	}

	row = db.QueryRow(`SELECT COUNT(*) FROM finding_hashes WHERE status != 'closed'`)
	if err := row.Scan(&stats.OpenFindings); err != nil {
		return nil, fmt.Errorf("count open findings: %w", err)
	}

	row = db.QueryRow(`SELECT COUNT(*) FROM finding_hashes WHERE status = 'closed'`)
	if err := row.Scan(&stats.ResolvedFindings); err != nil {
		return nil, fmt.Errorf("count resolved findings: %w", err)
	}

	// Findings by observation type — join finding_hashes with observations
	// via wo_id or fall back to counting observations by type directly.
	rows, err := db.Query(`SELECT type, COUNT(*) FROM observations WHERE type != '' GROUP BY type`)
	if err != nil {
		return nil, fmt.Errorf("findings by type: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var obsType string
		var count int
		if err := rows.Scan(&obsType, &count); err != nil {
			return nil, fmt.Errorf("scan findings by type: %w", err)
		}
		stats.FindingsByType[obsType] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings by type: %w", err)
	}

	// Mean time to resolve: avg(last_seen - first_seen) for closed findings
	var avgNanos sql.NullFloat64
	row = db.QueryRow(`
		SELECT AVG(last_seen - first_seen)
		FROM finding_hashes
		WHERE status = 'closed' AND last_seen > first_seen
	`)
	if err := row.Scan(&avgNanos); err != nil {
		return nil, fmt.Errorf("mean time to resolve: %w", err)
	}
	if avgNanos.Valid {
		stats.MeanTimeToResolve = time.Duration(int64(avgNanos.Float64))
	}

	return stats, nil
}

// PipelineMetrics queries the wo_lifecycle table.
func (c *Collector) PipelineMetrics() (*PipelineStats, error) {
	stats := &PipelineStats{
		WOsByState: make(map[string]int),
	}

	if c.lifecycleDBPath == "" {
		return stats, nil
	}

	db, err := openReadOnly(c.lifecycleDBPath)
	if err != nil {
		return stats, nil
	}
	defer func() { _ = db.Close() }()

	// Count distinct WOs
	row := db.QueryRow(`SELECT COUNT(DISTINCT wo_id) FROM wo_lifecycle`)
	if err := row.Scan(&stats.TotalWOs); err != nil {
		return nil, fmt.Errorf("count WOs: %w", err)
	}

	// Current state per WO = last transition row per wo_id
	rows, err := db.Query(`
		SELECT to_state, COUNT(*) FROM (
			SELECT wo_id, to_state
			FROM wo_lifecycle
			WHERE id IN (
				SELECT MAX(id) FROM wo_lifecycle GROUP BY wo_id
			)
		) GROUP BY to_state
	`)
	if err != nil {
		return nil, fmt.Errorf("WOs by state: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return nil, fmt.Errorf("scan WOs by state: %w", err)
		}
		stats.WOsByState[state] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate WOs by state: %w", err)
	}

	// Mean time to merge: avg(pr_merged.transitioned_at - dispatched.transitioned_at)
	var avgMerge sql.NullFloat64
	row = db.QueryRow(`
		SELECT AVG(m.transitioned_at - d.transitioned_at)
		FROM wo_lifecycle d
		JOIN wo_lifecycle m ON d.wo_id = m.wo_id
		WHERE d.to_state = 'dispatched' AND m.to_state = 'pr_merged'
		AND m.transitioned_at > d.transitioned_at
	`)
	if err := row.Scan(&avgMerge); err != nil {
		return nil, fmt.Errorf("mean time to merge: %w", err)
	}
	if avgMerge.Valid {
		stats.MeanTimeToMerge = time.Duration(int64(avgMerge.Float64))
	}

	// Mean time to verify: avg(verified.transitioned_at - applied.transitioned_at)
	var avgVerify sql.NullFloat64
	row = db.QueryRow(`
		SELECT AVG(v.transitioned_at - a.transitioned_at)
		FROM wo_lifecycle a
		JOIN wo_lifecycle v ON a.wo_id = v.wo_id
		WHERE a.to_state = 'applied' AND v.to_state = 'verified'
		AND v.transitioned_at > a.transitioned_at
	`)
	if err := row.Scan(&avgVerify); err != nil {
		return nil, fmt.Errorf("mean time to verify: %w", err)
	}
	if avgVerify.Valid {
		stats.MeanTimeToVerify = time.Duration(int64(avgVerify.Float64))
	}

	// Stale PRs: pr_open for > 24h without progressing to pr_merged
	now := c.nowFn().UTC()
	staleThreshold := now.Add(-24 * time.Hour).UnixNano()
	row = db.QueryRow(`
		SELECT COUNT(DISTINCT wo_id) FROM wo_lifecycle
		WHERE to_state = 'pr_open'
		AND transitioned_at < ?
		AND wo_id NOT IN (
			SELECT wo_id FROM wo_lifecycle WHERE to_state = 'pr_merged'
		)
	`, staleThreshold)
	if err := row.Scan(&stats.StalePRs); err != nil {
		return nil, fmt.Errorf("stale PRs: %w", err)
	}

	return stats, nil
}

// RedactionMetrics returns redaction counts. The current schema does not
// store redaction data, so this returns zero-value stats.
func (c *Collector) RedactionMetrics() (*RedactionStats, error) {
	return &RedactionStats{
		TotalRedactions:      0,
		RedactionsByCategory: make(map[string]int),
	}, nil
}

func openReadOnly(dbPath string) (*sql.DB, error) {
	info, err := os.Stat(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("stat db %q: %w", dbPath, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("db path %q is a directory", dbPath)
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open db %q: %w", dbPath, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if _, err := db.Exec(fmt.Sprintf("PRAGMA busy_timeout = %d", sqliteBusyMillis)); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure sqlite: %w", err)
	}
	return db, nil
}
