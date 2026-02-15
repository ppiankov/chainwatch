package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// TimestampFormat is the layout used in audit entry timestamps.
const TimestampFormat = "2006-01-02T15:04:05.000Z"

// ReplayFilter holds filtering criteria for session replay.
type ReplayFilter struct {
	TraceID string
	From    time.Time // zero value = no lower bound
	To      time.Time // zero value = no upper bound
}

// ReplaySummary holds decision counts and metadata for a replayed session.
type ReplaySummary struct {
	Total           int    `json:"total"`
	AllowCount      int    `json:"allow_count"`
	DenyCount       int    `json:"deny_count"`
	ApprovalCount   int    `json:"approval_count"`
	RedactCount     int    `json:"redact_count"`
	BreakGlassCount int    `json:"break_glass_count"`
	FirstTimestamp  string `json:"first_timestamp"`
	LastTimestamp   string `json:"last_timestamp"`
	MaxTier         int    `json:"max_tier"`
}

// ReplayResult holds filtered entries and summary for a session replay.
type ReplayResult struct {
	TraceID string        `json:"trace_id"`
	Entries []AuditEntry  `json:"entries"`
	Summary ReplaySummary `json:"summary"`
}

// Replay reads the audit log and returns entries matching the filter.
func Replay(path string, filter ReplayFilter) (*ReplayResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	result := &ReplayResult{
		TraceID: filter.TraceID,
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue // skip malformed lines
		}

		if entry.TraceID != filter.TraceID {
			continue
		}

		// Time range filtering
		if !filter.From.IsZero() || !filter.To.IsZero() {
			ts, err := time.Parse(TimestampFormat, entry.Timestamp)
			if err != nil {
				continue // skip unparseable timestamps
			}
			if !filter.From.IsZero() && ts.Before(filter.From) {
				continue
			}
			if !filter.To.IsZero() && ts.After(filter.To) {
				continue
			}
		}

		result.Entries = append(result.Entries, entry)
		updateSummary(&result.Summary, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}

	return result, nil
}

func updateSummary(s *ReplaySummary, entry AuditEntry) {
	s.Total++

	decision := strings.ToLower(entry.Decision)
	switch decision {
	case "allow":
		s.AllowCount++
	case "deny":
		s.DenyCount++
	case "require_approval":
		s.ApprovalCount++
	case "allow_with_redaction":
		s.RedactCount++
	}

	if entry.Type == "break_glass_used" {
		s.BreakGlassCount++
	}

	if entry.Tier > s.MaxTier {
		s.MaxTier = entry.Tier
	}

	if s.FirstTimestamp == "" {
		s.FirstTimestamp = entry.Timestamp
	}
	s.LastTimestamp = entry.Timestamp
}
