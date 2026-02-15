package audit

import (
	"path/filepath"
	"testing"
	"time"
)

// writeTestLog creates a temp audit log with known entries for testing.
func writeTestLog(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test-audit.jsonl")
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	base := time.Date(2025, 1, 15, 14, 0, 0, 0, time.UTC)

	entries := []AuditEntry{
		{Timestamp: base.Format(TimestampFormat), TraceID: "t-aaa", Action: AuditAction{Tool: "file_read", Resource: "/data/users.csv"}, Decision: "allow", Tier: 0},
		{Timestamp: base.Add(2 * time.Second).Format(TimestampFormat), TraceID: "t-aaa", Action: AuditAction{Tool: "file_read", Resource: "/data/report.csv"}, Decision: "allow", Tier: 1},
		{Timestamp: base.Add(4 * time.Second).Format(TimestampFormat), TraceID: "t-bbb", Action: AuditAction{Tool: "command", Resource: "ls /tmp"}, Decision: "allow", Tier: 0},
		{Timestamp: base.Add(6 * time.Second).Format(TimestampFormat), TraceID: "t-aaa", Action: AuditAction{Tool: "http_proxy", Resource: "https://slack.com/api"}, Decision: "deny", Reason: "denylisted", Tier: 3},
		{Timestamp: base.Add(8 * time.Second).Format(TimestampFormat), TraceID: "t-aaa", Action: AuditAction{Tool: "command", Resource: "sudo systemctl restart"}, Decision: "allow", Reason: "break-glass override", Tier: 2, Type: "break_glass_used", TokenID: "bg-123"},
		{Timestamp: base.Add(10 * time.Second).Format(TimestampFormat), TraceID: "t-aaa", Action: AuditAction{Tool: "http_proxy", Resource: "https://internal/report"}, Decision: "require_approval", Tier: 2},
	}

	for _, e := range entries {
		if err := log.Record(e); err != nil {
			t.Fatal(err)
		}
	}

	return path
}

func TestReplayFiltersByTraceID(t *testing.T) {
	path := writeTestLog(t)

	result, err := Replay(path, ReplayFilter{TraceID: "t-aaa"})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Entries) != 5 {
		t.Errorf("expected 5 entries for t-aaa, got %d", len(result.Entries))
	}

	// Verify no entries from t-bbb
	for _, e := range result.Entries {
		if e.TraceID != "t-aaa" {
			t.Errorf("unexpected trace ID: %s", e.TraceID)
		}
	}
}

func TestReplayTimeRangeFrom(t *testing.T) {
	path := writeTestLog(t)

	from := time.Date(2025, 1, 15, 14, 0, 5, 0, time.UTC)
	result, err := Replay(path, ReplayFilter{TraceID: "t-aaa", From: from})
	if err != nil {
		t.Fatal(err)
	}

	// Should only include entries at 14:00:06, 14:00:08, 14:00:10
	if len(result.Entries) != 3 {
		t.Errorf("expected 3 entries after from filter, got %d", len(result.Entries))
	}
}

func TestReplayTimeRangeTo(t *testing.T) {
	path := writeTestLog(t)

	to := time.Date(2025, 1, 15, 14, 0, 3, 0, time.UTC)
	result, err := Replay(path, ReplayFilter{TraceID: "t-aaa", To: to})
	if err != nil {
		t.Fatal(err)
	}

	// Should only include entries at 14:00:00, 14:00:02
	if len(result.Entries) != 2 {
		t.Errorf("expected 2 entries before to filter, got %d", len(result.Entries))
	}
}

func TestReplayTimeRangeBoth(t *testing.T) {
	path := writeTestLog(t)

	from := time.Date(2025, 1, 15, 14, 0, 1, 0, time.UTC)
	to := time.Date(2025, 1, 15, 14, 0, 7, 0, time.UTC)
	result, err := Replay(path, ReplayFilter{TraceID: "t-aaa", From: from, To: to})
	if err != nil {
		t.Fatal(err)
	}

	// Should include entries at 14:00:02 and 14:00:06
	if len(result.Entries) != 2 {
		t.Errorf("expected 2 entries in time window, got %d", len(result.Entries))
	}
}

func TestReplayEmptyResult(t *testing.T) {
	path := writeTestLog(t)

	result, err := Replay(path, ReplayFilter{TraceID: "t-nonexistent"})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Entries) != 0 {
		t.Errorf("expected 0 entries for unknown trace, got %d", len(result.Entries))
	}
	if result.Summary.Total != 0 {
		t.Errorf("expected 0 total, got %d", result.Summary.Total)
	}
}

func TestReplaySummaryCountsCorrect(t *testing.T) {
	path := writeTestLog(t)

	result, err := Replay(path, ReplayFilter{TraceID: "t-aaa"})
	if err != nil {
		t.Fatal(err)
	}

	s := result.Summary
	if s.Total != 5 {
		t.Errorf("total: expected 5, got %d", s.Total)
	}
	if s.AllowCount != 3 {
		t.Errorf("allow: expected 3, got %d", s.AllowCount)
	}
	if s.DenyCount != 1 {
		t.Errorf("deny: expected 1, got %d", s.DenyCount)
	}
	if s.ApprovalCount != 1 {
		t.Errorf("approval: expected 1, got %d", s.ApprovalCount)
	}
}

func TestReplayMaxTierTracked(t *testing.T) {
	path := writeTestLog(t)

	result, err := Replay(path, ReplayFilter{TraceID: "t-aaa"})
	if err != nil {
		t.Fatal(err)
	}

	if result.Summary.MaxTier != 3 {
		t.Errorf("max tier: expected 3, got %d", result.Summary.MaxTier)
	}

	// t-bbb only has tier 0 entries
	result2, err := Replay(path, ReplayFilter{TraceID: "t-bbb"})
	if err != nil {
		t.Fatal(err)
	}
	if result2.Summary.MaxTier != 0 {
		t.Errorf("max tier for t-bbb: expected 0, got %d", result2.Summary.MaxTier)
	}
}

func TestReplayBreakGlassCount(t *testing.T) {
	path := writeTestLog(t)

	result, err := Replay(path, ReplayFilter{TraceID: "t-aaa"})
	if err != nil {
		t.Fatal(err)
	}

	if result.Summary.BreakGlassCount != 1 {
		t.Errorf("break-glass count: expected 1, got %d", result.Summary.BreakGlassCount)
	}
}
