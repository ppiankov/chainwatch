package observe

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	defaultVerifyMaxRetries = 1
	defaultVerifyRetryDelay = 30 * time.Second
)

// VerifyConfig defines the inputs required to re-run observation after remediation.
type VerifyConfig struct {
	WOID                string
	RunnerConfig        RunnerConfig
	OriginalFindingHash string
	MaxRetries          int
	RetryDelay          time.Duration
}

// VerifyResult captures the outcome of drift verification.
type VerifyResult struct {
	WOID         string
	Passed       bool
	OriginalHash string
	CurrentHash  string
	Attempt      int
	Detail       string
}

// VerifyRunner executes observation for verification.
type VerifyRunner func(context.Context, RunnerConfig) (*RunResult, error)

// Verify re-runs observation and compares the new evidence hash to the original finding hash.
func Verify(ctx context.Context, cfg VerifyConfig) (*VerifyResult, error) {
	return VerifyWithRunner(ctx, cfg, nil)
}

// VerifyWithRunner re-runs observation using a caller-provided runner.
func VerifyWithRunner(
	ctx context.Context,
	cfg VerifyConfig,
	runner VerifyRunner,
) (*VerifyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runner == nil {
		runner = defaultVerifyRunner
	}

	normalized, err := normalizeVerifyConfig(cfg)
	if err != nil {
		return nil, err
	}

	attempts := normalized.MaxRetries + 1
	var result *VerifyResult

	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		runResult, err := runner(ctx, normalized.RunnerConfig)
		if err != nil {
			return nil, fmt.Errorf("verify attempt %d: %w", attempt, err)
		}

		evidence := ""
		if runResult != nil {
			evidence = CollectEvidence(runResult)
		}

		currentHash := ComputeEvidenceHash(evidence)
		passed := currentHash != normalized.OriginalFindingHash

		result = &VerifyResult{
			WOID:         normalized.WOID,
			Passed:       passed,
			OriginalHash: normalized.OriginalFindingHash,
			CurrentHash:  currentHash,
			Attempt:      attempt,
			Detail:       buildVerifyDetail(passed, attempt, normalized.OriginalFindingHash, currentHash, evidence),
		}
		if passed {
			return result, nil
		}
		if attempt == attempts {
			return result, nil
		}
		if err := waitForVerifyRetry(ctx, normalized.RetryDelay); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// ComputeEvidenceHash returns a stable SHA256 hash for collected observation evidence.
func ComputeEvidenceHash(evidence string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(evidence)))
	return hex.EncodeToString(sum[:])
}

// LookupFindingHashByWOID resolves the stored finding hash for a work order ID.
func LookupFindingHashByWOID(cachePath, woID string) (string, error) {
	trimmedWOID := strings.TrimSpace(woID)
	if trimmedWOID == "" {
		return "", fmt.Errorf("work order ID is required")
	}

	db, err := openCacheDB(cachePath, false)
	if err != nil {
		return "", err
	}
	if db == nil {
		return "", fmt.Errorf("observation cache %q not found", cachePath)
	}
	defer func() {
		_ = db.Close()
	}()

	hash, err := queryFindingHashByWOID(db, trimmedWOID)
	if err != nil {
		return "", err
	}
	if hash != "" {
		return hash, nil
	}

	baseWOID := trimWOIDRetrySuffix(trimmedWOID)
	if baseWOID != trimmedWOID {
		hash, err = queryFindingHashByWOID(db, baseWOID)
		if err != nil {
			return "", err
		}
		if hash != "" {
			return hash, nil
		}
	}

	prefix := findingHashPrefixFromWOID(baseWOID)
	if prefix == "" {
		return "", fmt.Errorf("finding hash not found for work order %q", trimmedWOID)
	}

	hashes, err := queryFindingHashesByPrefix(db, prefix)
	if err != nil {
		return "", err
	}
	switch len(hashes) {
	case 0:
		return "", fmt.Errorf("finding hash not found for work order %q", trimmedWOID)
	case 1:
		return hashes[0], nil
	default:
		return "", fmt.Errorf("multiple finding hashes match work order %q", trimmedWOID)
	}
}

func normalizeVerifyConfig(cfg VerifyConfig) (VerifyConfig, error) {
	cfg.WOID = strings.TrimSpace(cfg.WOID)
	if cfg.WOID == "" {
		return VerifyConfig{}, fmt.Errorf("work order ID is required")
	}

	cfg.OriginalFindingHash = strings.TrimSpace(cfg.OriginalFindingHash)
	if cfg.OriginalFindingHash == "" {
		return VerifyConfig{}, fmt.Errorf("original finding hash is required")
	}

	cfg.RunnerConfig.Type = strings.TrimSpace(cfg.RunnerConfig.Type)
	if len(cfg.RunnerConfig.Types) > 0 {
		types := make([]string, 0, len(cfg.RunnerConfig.Types))
		for _, rawType := range cfg.RunnerConfig.Types {
			trimmedType := strings.TrimSpace(rawType)
			if trimmedType == "" {
				continue
			}
			types = append(types, trimmedType)
		}
		cfg.RunnerConfig.Types = types
		if cfg.RunnerConfig.Type == "" && len(types) > 0 {
			cfg.RunnerConfig.Type = types[0]
		}
	}
	if cfg.RunnerConfig.Type == "" {
		return VerifyConfig{}, fmt.Errorf("runner config type is required")
	}

	if cfg.MaxRetries < 0 {
		return VerifyConfig{}, fmt.Errorf("max retries cannot be negative")
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = defaultVerifyMaxRetries
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = defaultVerifyRetryDelay
	}

	return cfg, nil
}

func defaultVerifyRunner(_ context.Context, cfg RunnerConfig) (*RunResult, error) {
	if len(cfg.Types) > 1 {
		return RunMulti(cfg, cfg.Types)
	}

	runbookType := strings.TrimSpace(cfg.Type)
	if runbookType == "" && len(cfg.Types) == 1 {
		runbookType = cfg.Types[0]
	}
	if runbookType == "" {
		return nil, fmt.Errorf("runner config type is required")
	}

	return Run(cfg, GetRunbook(runbookType))
}

func buildVerifyDetail(
	passed bool,
	attempt int,
	originalHash string,
	currentHash string,
	evidence string,
) string {
	if passed {
		if strings.TrimSpace(evidence) == "" {
			return fmt.Sprintf(
				"attempt %d collected no evidence; hash changed from %s to %s, so the original finding no longer reproduces",
				attempt,
				originalHash,
				currentHash,
			)
		}
		return fmt.Sprintf(
			"attempt %d produced a different evidence hash (%s -> %s); the original drift no longer matches current observation",
			attempt,
			originalHash,
			currentHash,
		)
	}

	return fmt.Sprintf(
		"attempt %d produced the same evidence hash (%s); the finding persists after remediation",
		attempt,
		currentHash,
	)
}

func waitForVerifyRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func queryFindingHashByWOID(db *sql.DB, woID string) (string, error) {
	var hash string
	err := db.QueryRow(`
		SELECT hash
		FROM finding_hashes
		WHERE wo_id = ?
		ORDER BY last_seen DESC
		LIMIT 1
	`, woID).Scan(&hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("query finding hash for work order %q: %w", woID, err)
	}
	return strings.TrimSpace(hash), nil
}

func queryFindingHashesByPrefix(db *sql.DB, prefix string) ([]string, error) {
	rows, err := db.Query(`
		SELECT hash
		FROM finding_hashes
		WHERE hash LIKE ?
		ORDER BY last_seen DESC
		LIMIT 2
	`, prefix+"%")
	if err != nil {
		return nil, fmt.Errorf("query finding hashes by prefix %q: %w", prefix, err)
	}
	defer func() {
		_ = rows.Close()
	}()

	hashes := make([]string, 0, 2)
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, fmt.Errorf("scan finding hash prefix match: %w", err)
		}
		hashes = append(hashes, strings.TrimSpace(hash))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding hash prefix matches: %w", err)
	}
	return hashes, nil
}

func trimWOIDRetrySuffix(woID string) string {
	lastDash := strings.LastIndex(woID, "-")
	if lastDash < 0 || lastDash == len(woID)-1 {
		return woID
	}
	suffix := woID[lastDash+1:]
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return woID
		}
	}
	return woID[:lastDash]
}

func findingHashPrefixFromWOID(woID string) string {
	trimmed := strings.TrimSpace(woID)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "wo-") {
		return trimmed[3:]
	}
	return ""
}
