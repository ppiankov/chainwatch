package orchestrator

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	lifecycleDBPerm      = 0750
	lifecycleBusyMillis  = 5000
	defaultSortTimestamp = int64(0)
)

// LifecycleState is a stage in the WO lifecycle.
type LifecycleState string

const (
	LifecycleStateFinding    LifecycleState = "finding"
	LifecycleStateWO         LifecycleState = "wo"
	LifecycleStateDispatched LifecycleState = "dispatched"
	LifecycleStatePROpen     LifecycleState = "pr_open"
	LifecycleStatePRMerged   LifecycleState = "pr_merged"
	LifecycleStateApplied    LifecycleState = "applied"
	LifecycleStateVerified   LifecycleState = "verified"
)

var (
	orderedLifecycleStates = []LifecycleState{
		LifecycleStateFinding,
		LifecycleStateWO,
		LifecycleStateDispatched,
		LifecycleStatePROpen,
		LifecycleStatePRMerged,
		LifecycleStateApplied,
		LifecycleStateVerified,
	}

	allowedTransitions = map[LifecycleState]LifecycleState{
		LifecycleStateFinding:    LifecycleStateWO,
		LifecycleStateWO:         LifecycleStateDispatched,
		LifecycleStateDispatched: LifecycleStatePROpen,
		LifecycleStatePROpen:     LifecycleStatePRMerged,
		LifecycleStatePRMerged:   LifecycleStateApplied,
		LifecycleStateApplied:    LifecycleStateVerified,
	}

	// ErrWorkOrderNotFound indicates lifecycle data is missing for a WO ID.
	ErrWorkOrderNotFound = errors.New("work order not found")
)

// LifecycleTransition records one state transition row.
type LifecycleTransition struct {
	WOID           string
	FromState      LifecycleState
	ToState        LifecycleState
	TransitionedAt time.Time
	Finding        string
	PRURL          string
}

// WOStatus is the full lifecycle for one WO.
type WOStatus struct {
	WOID           string
	CurrentState   LifecycleState
	LastTransition time.Time
	Finding        string
	PRURL          string
	Transitions    []LifecycleTransition
}

// WOCurrentStatus is a summary row for --all listing.
type WOCurrentStatus struct {
	WOID           string
	CurrentState   LifecycleState
	LastTransition time.Time
	Finding        string
	PRURL          string
}

// LifecycleStore persists WO lifecycle transitions in SQLite.
type LifecycleStore struct {
	dbPath string
	nowFn  func() time.Time
}

// NewLifecycleStore creates a lifecycle store.
func NewLifecycleStore(dbPath string, nowFn func() time.Time) *LifecycleStore {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &LifecycleStore{
		dbPath: strings.TrimSpace(dbPath),
		nowFn:  nowFn,
	}
}

// OrderedLifecycleStates returns states in canonical lifecycle order.
func OrderedLifecycleStates() []LifecycleState {
	out := make([]LifecycleState, len(orderedLifecycleStates))
	copy(out, orderedLifecycleStates)
	return out
}

// ParseLifecycleState validates and normalizes a state.
func ParseLifecycleState(raw string) (LifecycleState, error) {
	state := LifecycleState(strings.ToLower(strings.TrimSpace(raw)))
	for _, allowed := range orderedLifecycleStates {
		if state == allowed {
			return state, nil
		}
	}
	return "", fmt.Errorf("invalid lifecycle state %q", raw)
}

// RecordTransition appends one state transition after validating the state machine.
func (s *LifecycleStore) RecordTransition(transition LifecycleTransition) error {
	if s == nil {
		return fmt.Errorf("lifecycle store is nil")
	}

	woID := strings.TrimSpace(transition.WOID)
	if woID == "" {
		return fmt.Errorf("work order ID is required")
	}
	if s.dbPath == "" {
		return fmt.Errorf("database path is required")
	}

	toState, err := ParseLifecycleState(string(transition.ToState))
	if err != nil {
		return err
	}

	at := transition.TransitionedAt
	if at.IsZero() {
		at = s.nowFn().UTC()
	} else {
		at = at.UTC()
	}

	db, err := openLifecycleDB(s.dbPath, true)
	if err != nil {
		return err
	}
	defer func() {
		_ = db.Close()
	}()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin lifecycle transition: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	lastState, err := readCurrentState(tx, woID)
	if err != nil {
		return err
	}

	fromState, err := validateTransition(lastState, toState)
	if err != nil {
		return fmt.Errorf("validate transition for %q: %w", woID, err)
	}

	_, err = tx.Exec(`
		INSERT INTO wo_lifecycle (
			wo_id, from_state, to_state, transitioned_at, finding, pr_url
		) VALUES (?, ?, ?, ?, ?, ?)
	`,
		woID,
		string(fromState),
		string(toState),
		at.UnixNano(),
		strings.TrimSpace(transition.Finding),
		strings.TrimSpace(transition.PRURL),
	)
	if err != nil {
		return fmt.Errorf("insert lifecycle transition: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit lifecycle transition: %w", err)
	}
	committed = true
	return nil
}

// GetWOStatus returns the full lifecycle for one WO.
func (s *LifecycleStore) GetWOStatus(woID string) (*WOStatus, error) {
	if s == nil {
		return nil, fmt.Errorf("lifecycle store is nil")
	}
	trimmedID := strings.TrimSpace(woID)
	if trimmedID == "" {
		return nil, fmt.Errorf("work order ID is required")
	}
	if s.dbPath == "" {
		return nil, fmt.Errorf("database path is required")
	}

	db, err := openLifecycleDB(s.dbPath, false)
	if err != nil {
		return nil, err
	}
	if db == nil {
		return nil, ErrWorkOrderNotFound
	}
	defer func() {
		_ = db.Close()
	}()

	rows, err := db.Query(`
		SELECT wo_id, from_state, to_state, transitioned_at, finding, pr_url
		FROM wo_lifecycle
		WHERE wo_id = ?
		ORDER BY id ASC
	`, trimmedID)
	if err != nil {
		return nil, fmt.Errorf("query work order lifecycle %q: %w", trimmedID, err)
	}
	defer func() {
		_ = rows.Close()
	}()

	status := &WOStatus{
		WOID:        trimmedID,
		Transitions: make([]LifecycleTransition, 0, len(orderedLifecycleStates)),
	}

	for rows.Next() {
		transition, scanErr := scanLifecycleTransition(rows)
		if scanErr != nil {
			return nil, scanErr
		}

		status.Transitions = append(status.Transitions, transition)
		status.CurrentState = transition.ToState
		status.LastTransition = transition.TransitionedAt
		if transition.Finding != "" {
			status.Finding = transition.Finding
		}
		if transition.PRURL != "" {
			status.PRURL = transition.PRURL
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate lifecycle rows for %q: %w", trimmedID, err)
	}
	if len(status.Transitions) == 0 {
		return nil, ErrWorkOrderNotFound
	}
	return status, nil
}

// ListCurrentStatuses returns one summary row per WO, optionally filtered by state.
func (s *LifecycleStore) ListCurrentStatuses(filterState LifecycleState) ([]WOCurrentStatus, error) {
	if s == nil {
		return nil, fmt.Errorf("lifecycle store is nil")
	}
	if s.dbPath == "" {
		return nil, fmt.Errorf("database path is required")
	}

	filter := LifecycleState("")
	if strings.TrimSpace(string(filterState)) != "" {
		parsed, err := ParseLifecycleState(string(filterState))
		if err != nil {
			return nil, err
		}
		filter = parsed
	}

	db, err := openLifecycleDB(s.dbPath, false)
	if err != nil {
		return nil, err
	}
	if db == nil {
		return []WOCurrentStatus{}, nil
	}
	defer func() {
		_ = db.Close()
	}()

	rows, err := db.Query(`
		SELECT wo_id, from_state, to_state, transitioned_at, finding, pr_url
		FROM wo_lifecycle
		ORDER BY wo_id ASC, id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query lifecycle status list: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	indexByWO := make(map[string]int)
	summaries := make([]WOCurrentStatus, 0)

	for rows.Next() {
		transition, scanErr := scanLifecycleTransition(rows)
		if scanErr != nil {
			return nil, scanErr
		}

		idx, found := indexByWO[transition.WOID]
		if !found {
			summaries = append(summaries, WOCurrentStatus{
				WOID:           transition.WOID,
				CurrentState:   transition.ToState,
				LastTransition: transition.TransitionedAt,
				Finding:        transition.Finding,
				PRURL:          transition.PRURL,
			})
			indexByWO[transition.WOID] = len(summaries) - 1
			continue
		}

		current := &summaries[idx]
		current.CurrentState = transition.ToState
		current.LastTransition = transition.TransitionedAt
		if transition.Finding != "" {
			current.Finding = transition.Finding
		}
		if transition.PRURL != "" {
			current.PRURL = transition.PRURL
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate lifecycle status rows: %w", err)
	}

	filtered := make([]WOCurrentStatus, 0, len(summaries))
	for _, summary := range summaries {
		if filter != "" && summary.CurrentState != filter {
			continue
		}
		filtered = append(filtered, summary)
	}

	sort.Slice(filtered, func(i, j int) bool {
		iTime := filtered[i].LastTransition.UnixNano()
		jTime := filtered[j].LastTransition.UnixNano()
		if iTime == defaultSortTimestamp && jTime == defaultSortTimestamp {
			return filtered[i].WOID < filtered[j].WOID
		}
		if iTime == jTime {
			return filtered[i].WOID < filtered[j].WOID
		}
		return iTime > jTime
	})

	return filtered, nil
}

func validateTransition(current LifecycleState, next LifecycleState) (LifecycleState, error) {
	if current == "" {
		if next != LifecycleStateFinding {
			return "", fmt.Errorf("initial transition must be %q", LifecycleStateFinding)
		}
		return "", nil
	}

	expectedNext, ok := allowedTransitions[current]
	if !ok {
		return "", fmt.Errorf("current state %q is terminal", current)
	}
	if next != expectedNext {
		return "", fmt.Errorf("expected next state %q, got %q", expectedNext, next)
	}
	return current, nil
}

func readCurrentState(tx *sql.Tx, woID string) (LifecycleState, error) {
	var stateRaw string
	err := tx.QueryRow(`
		SELECT to_state
		FROM wo_lifecycle
		WHERE wo_id = ?
		ORDER BY id DESC
		LIMIT 1
	`, woID).Scan(&stateRaw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("read current state for %q: %w", woID, err)
	}
	state, err := ParseLifecycleState(stateRaw)
	if err != nil {
		return "", fmt.Errorf("stored state for %q is invalid: %w", woID, err)
	}
	return state, nil
}

func openLifecycleDB(dbPath string, create bool) (*sql.DB, error) {
	trimmedPath := strings.TrimSpace(dbPath)
	if trimmedPath == "" {
		return nil, fmt.Errorf("database path is required")
	}

	cleanPath := filepath.Clean(trimmedPath)
	if !create {
		exists, err := fileExists(cleanPath)
		if err != nil {
			return nil, fmt.Errorf("stat lifecycle db: %w", err)
		}
		if !exists {
			return nil, nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(cleanPath), lifecycleDBPerm); err != nil {
		return nil, fmt.Errorf("create lifecycle db parent: %w", err)
	}

	db, err := sql.Open("sqlite", cleanPath)
	if err != nil {
		return nil, fmt.Errorf("open lifecycle db: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := configureLifecycleSQLite(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureLifecycleSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func configureLifecycleSQLite(db *sql.DB) error {
	pragmas := []string{
		fmt.Sprintf("PRAGMA busy_timeout = %d", lifecycleBusyMillis),
		"PRAGMA synchronous = NORMAL",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			return fmt.Errorf("configure lifecycle sqlite %q: %w", pragma, err)
		}
	}
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		if !strings.Contains(err.Error(), "SQLITE_BUSY") {
			return fmt.Errorf("configure lifecycle sqlite %q: %w", "PRAGMA journal_mode = WAL", err)
		}
	}
	return nil
}

func ensureLifecycleSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS wo_lifecycle (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			wo_id TEXT NOT NULL,
			from_state TEXT NOT NULL DEFAULT '',
			to_state TEXT NOT NULL,
			transitioned_at INTEGER NOT NULL,
			finding TEXT NOT NULL DEFAULT '',
			pr_url TEXT NOT NULL DEFAULT '',
			CHECK (
				to_state IN ('finding', 'wo', 'dispatched', 'pr_open', 'pr_merged', 'applied', 'verified')
			)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_wo_lifecycle_wo ON wo_lifecycle(wo_id, id)`,
		`CREATE INDEX IF NOT EXISTS idx_wo_lifecycle_to_state ON wo_lifecycle(to_state)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_wo_lifecycle_unique_state ON wo_lifecycle(wo_id, to_state)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("create lifecycle schema: %w", err)
		}
	}
	return nil
}

func scanLifecycleTransition(rows *sql.Rows) (LifecycleTransition, error) {
	var (
		transition               LifecycleTransition
		fromStateRaw, toStateRaw string
		transitionedAt           int64
	)

	if err := rows.Scan(
		&transition.WOID,
		&fromStateRaw,
		&toStateRaw,
		&transitionedAt,
		&transition.Finding,
		&transition.PRURL,
	); err != nil {
		return LifecycleTransition{}, fmt.Errorf("scan lifecycle row: %w", err)
	}

	if strings.TrimSpace(fromStateRaw) != "" {
		fromState, err := ParseLifecycleState(fromStateRaw)
		if err != nil {
			return LifecycleTransition{}, fmt.Errorf("scan lifecycle from_state: %w", err)
		}
		transition.FromState = fromState
	}

	toState, err := ParseLifecycleState(toStateRaw)
	if err != nil {
		return LifecycleTransition{}, fmt.Errorf("scan lifecycle to_state: %w", err)
	}
	transition.ToState = toState
	transition.TransitionedAt = time.Unix(0, transitionedAt).UTC()
	transition.WOID = strings.TrimSpace(transition.WOID)
	transition.Finding = strings.TrimSpace(transition.Finding)
	transition.PRURL = strings.TrimSpace(transition.PRURL)

	return transition, nil
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
