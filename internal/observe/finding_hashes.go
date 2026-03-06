package observe

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ppiankov/chainwatch/internal/wo"
)

// FindingStatus is the lifecycle state for a deduplicated finding hash.
type FindingStatus string

const (
	// FindingStatusOpen means the finding currently has an active WO.
	FindingStatusOpen FindingStatus = "open"
	// FindingStatusClosed means the finding was resolved/closed.
	FindingStatusClosed FindingStatus = "closed"
)

// FindingDedupAction describes how the dedup engine handled a finding.
type FindingDedupAction string

const (
	// FindingDedupActionCreate means the finding hash was new and WO should be created.
	FindingDedupActionCreate FindingDedupAction = "create"
	// FindingDedupActionSuppress means finding was suppressed by dedup rules.
	FindingDedupActionSuppress FindingDedupAction = "suppress"
	// FindingDedupActionReopen means a previously closed finding recurred and should be reopened.
	FindingDedupActionReopen FindingDedupAction = "reopen"
)

// FindingDedupReason explains why the action was chosen.
type FindingDedupReason string

const (
	// FindingDedupReasonNewHash indicates a brand-new finding hash.
	FindingDedupReasonNewHash FindingDedupReason = "new_hash"
	// FindingDedupReasonOpenWO indicates suppression due to existing open WO.
	FindingDedupReasonOpenWO FindingDedupReason = "open_wo"
	// FindingDedupReasonDedupWindow indicates suppression due to recurrence inside dedup window.
	FindingDedupReasonDedupWindow FindingDedupReason = "dedup_window"
	// FindingDedupReasonRecurring indicates a closed finding recurred outside dedup window.
	FindingDedupReasonRecurring FindingDedupReason = "recurring"
)

// FindingHashRecord stores dedup state for a finding hash.
type FindingHashRecord struct {
	Hash      string
	FirstSeen time.Time
	LastSeen  time.Time
	WOID      string
	Status    FindingStatus
}

// FindingDedupDecision captures dedup action and resulting state.
type FindingDedupDecision struct {
	Action FindingDedupAction
	Reason FindingDedupReason
	Record FindingHashRecord
}

// ComputeFindingHash returns stable content hash for finding_type + scope + key_attributes.
func ComputeFindingHash(findingType, scope string, keyAttributes map[string]any) (string, error) {
	normalizedType := strings.ToLower(strings.TrimSpace(findingType))
	if normalizedType == "" {
		return "", fmt.Errorf("finding type is required")
	}
	normalizedScope := strings.TrimSpace(scope)
	if normalizedScope == "" {
		return "", fmt.Errorf("scope is required")
	}
	if keyAttributes == nil {
		keyAttributes = map[string]any{}
	}

	payload := struct {
		FindingType   string         `json:"finding_type"`
		Scope         string         `json:"scope"`
		KeyAttributes map[string]any `json:"key_attributes"`
	}{
		FindingType:   normalizedType,
		Scope:         normalizedScope,
		KeyAttributes: keyAttributes,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal finding hash payload: %w", err)
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// ComputeObservationHash builds finding hash from observation data.
func ComputeObservationHash(scope string, observation wo.Observation) (string, error) {
	keyAttributes := make(map[string]any, len(observation.Data)+1)
	for k, v := range observation.Data {
		keyAttributes[k] = v
	}

	// Detail is used as a fallback key attribute when classifier did not provide structured data.
	if len(keyAttributes) == 0 {
		if detail := strings.TrimSpace(observation.Detail); detail != "" {
			keyAttributes["detail"] = detail
		}
	}

	return ComputeFindingHash(string(observation.Type), scope, keyAttributes)
}

// ApplyFindingDedup evaluates and updates finding hash lifecycle state.
func ApplyFindingDedup(
	cachePath string,
	findingHash string,
	woID string,
	now time.Time,
	dedupWindow time.Duration,
) (*FindingDedupDecision, error) {
	normalizedHash := strings.TrimSpace(findingHash)
	if normalizedHash == "" {
		return nil, fmt.Errorf("finding hash is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if dedupWindow < 0 {
		dedupWindow = 0
	}

	db, err := openCacheDB(cachePath, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = db.Close()
	}()

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin finding dedup tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	record, err := readFindingHashTx(tx, normalizedHash)
	if err != nil {
		return nil, err
	}
	if record == nil {
		newRecord := FindingHashRecord{
			Hash:      normalizedHash,
			FirstSeen: now,
			LastSeen:  now,
			WOID:      strings.TrimSpace(woID),
			Status:    FindingStatusOpen,
		}
		if _, err := tx.Exec(`
			INSERT INTO finding_hashes (hash, first_seen, last_seen, wo_id, status)
			VALUES (?, ?, ?, ?, ?)
		`,
			newRecord.Hash,
			newRecord.FirstSeen.UnixNano(),
			newRecord.LastSeen.UnixNano(),
			newRecord.WOID,
			string(newRecord.Status),
		); err != nil {
			return nil, fmt.Errorf("insert finding hash %q: %w", normalizedHash, err)
		}
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit finding dedup tx: %w", err)
		}
		committed = true
		return &FindingDedupDecision{
			Action: FindingDedupActionCreate,
			Reason: FindingDedupReasonNewHash,
			Record: newRecord,
		}, nil
	}

	record.WOID = strings.TrimSpace(record.WOID)
	if record.WOID == "" {
		record.WOID = strings.TrimSpace(woID)
	}
	record.Status = normalizeFindingStatus(record.Status)

	if record.Status == FindingStatusOpen {
		record.LastSeen = now
		if _, err := tx.Exec(`
			UPDATE finding_hashes
			SET last_seen = ?, wo_id = ?, status = ?
			WHERE hash = ?
		`,
			record.LastSeen.UnixNano(),
			record.WOID,
			string(FindingStatusOpen),
			record.Hash,
		); err != nil {
			return nil, fmt.Errorf("update open finding hash %q: %w", normalizedHash, err)
		}
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit finding dedup tx: %w", err)
		}
		committed = true
		return &FindingDedupDecision{
			Action: FindingDedupActionSuppress,
			Reason: FindingDedupReasonOpenWO,
			Record: *record,
		}, nil
	}

	if dedupWindow > 0 && now.Sub(record.LastSeen) < dedupWindow {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit finding dedup tx: %w", err)
		}
		committed = true
		return &FindingDedupDecision{
			Action: FindingDedupActionSuppress,
			Reason: FindingDedupReasonDedupWindow,
			Record: *record,
		}, nil
	}

	record.LastSeen = now
	record.Status = FindingStatusOpen
	if _, err := tx.Exec(`
		UPDATE finding_hashes
		SET last_seen = ?, wo_id = ?, status = ?
		WHERE hash = ?
	`,
		record.LastSeen.UnixNano(),
		record.WOID,
		string(record.Status),
		record.Hash,
	); err != nil {
		return nil, fmt.Errorf("reopen finding hash %q: %w", normalizedHash, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit finding dedup tx: %w", err)
	}
	committed = true
	return &FindingDedupDecision{
		Action: FindingDedupActionReopen,
		Reason: FindingDedupReasonRecurring,
		Record: *record,
	}, nil
}

// ReadFindingHash returns finding hash state record or nil when missing.
func ReadFindingHash(cachePath, findingHash string) (*FindingHashRecord, error) {
	normalizedHash := strings.TrimSpace(findingHash)
	if normalizedHash == "" {
		return nil, fmt.Errorf("finding hash is required")
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

	row := db.QueryRow(`
		SELECT hash, first_seen, last_seen, wo_id, status
		FROM finding_hashes
		WHERE hash = ?
	`, normalizedHash)
	return scanFindingHashRow(row)
}

// UpdateFindingHashStatus updates finding hash lifecycle status.
func UpdateFindingHashStatus(cachePath, findingHash string, status FindingStatus, at time.Time) error {
	normalizedHash := strings.TrimSpace(findingHash)
	if normalizedHash == "" {
		return fmt.Errorf("finding hash is required")
	}
	if !isValidFindingStatus(status) {
		return fmt.Errorf("invalid finding status %q", status)
	}
	if at.IsZero() {
		at = time.Now().UTC()
	} else {
		at = at.UTC()
	}

	db, err := openCacheDB(cachePath, true)
	if err != nil {
		return err
	}
	defer func() {
		_ = db.Close()
	}()

	result, err := db.Exec(`
		UPDATE finding_hashes
		SET status = ?, last_seen = ?
		WHERE hash = ?
	`, string(status), at.UnixNano(), normalizedHash)
	if err != nil {
		return fmt.Errorf("update finding hash status %q: %w", normalizedHash, err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected for finding hash %q: %w", normalizedHash, err)
	}
	if affected == 0 {
		return fmt.Errorf("finding hash %q not found", normalizedHash)
	}
	return nil
}

func readFindingHashTx(tx *sql.Tx, findingHash string) (*FindingHashRecord, error) {
	row := tx.QueryRow(`
		SELECT hash, first_seen, last_seen, wo_id, status
		FROM finding_hashes
		WHERE hash = ?
	`, findingHash)
	return scanFindingHashRow(row)
}

type sqlRow interface {
	Scan(dest ...any) error
}

func scanFindingHashRow(row sqlRow) (*FindingHashRecord, error) {
	var (
		record    FindingHashRecord
		firstSeen int64
		lastSeen  int64
		statusRaw string
	)
	err := row.Scan(&record.Hash, &firstSeen, &lastSeen, &record.WOID, &statusRaw)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan finding hash row: %w", err)
	}

	record.FirstSeen = time.Unix(0, firstSeen).UTC()
	record.LastSeen = time.Unix(0, lastSeen).UTC()
	record.Status = normalizeFindingStatus(FindingStatus(statusRaw))
	return &record, nil
}

func normalizeFindingStatus(status FindingStatus) FindingStatus {
	switch FindingStatus(strings.ToLower(strings.TrimSpace(string(status)))) {
	case FindingStatusClosed:
		return FindingStatusClosed
	default:
		return FindingStatusOpen
	}
}

func isValidFindingStatus(status FindingStatus) bool {
	switch status {
	case FindingStatusOpen, FindingStatusClosed:
		return true
	default:
		return false
	}
}
