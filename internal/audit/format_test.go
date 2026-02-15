package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFormatTimelineHeaderAndSummary(t *testing.T) {
	path := writeTestLog(t)
	result, err := Replay(path, ReplayFilter{TraceID: "t-aaa"})
	if err != nil {
		t.Fatal(err)
	}

	out := FormatTimeline(result)

	if !strings.Contains(out, "Trace: t-aaa") {
		t.Error("expected header to contain trace ID")
	}
	if !strings.Contains(out, "Summary:") {
		t.Error("expected summary line")
	}
	if !strings.Contains(out, "3 allow") {
		t.Errorf("expected '3 allow' in summary, got:\n%s", out)
	}
	if !strings.Contains(out, "1 deny") {
		t.Errorf("expected '1 deny' in summary, got:\n%s", out)
	}
	if !strings.Contains(out, "Max tier: 3 (critical)") {
		t.Errorf("expected max tier in summary, got:\n%s", out)
	}
}

func TestFormatTimelineEntryColumns(t *testing.T) {
	path := writeTestLog(t)
	result, err := Replay(path, ReplayFilter{TraceID: "t-aaa"})
	if err != nil {
		t.Fatal(err)
	}

	out := FormatTimeline(result)

	// Check that entries contain expected fields
	if !strings.Contains(out, "T0") {
		t.Error("expected T0 tier badge")
	}
	if !strings.Contains(out, "T3") {
		t.Error("expected T3 tier badge")
	}
	if !strings.Contains(out, "DENY") {
		t.Error("expected DENY decision")
	}
	if !strings.Contains(out, "ALLOW") {
		t.Error("expected ALLOW decision")
	}
	if !strings.Contains(out, "file_read") {
		t.Error("expected file_read tool")
	}
	if !strings.Contains(out, "[break-glass]") {
		t.Error("expected [break-glass] tag")
	}
}

func TestFormatJSONValid(t *testing.T) {
	path := writeTestLog(t)
	result, err := Replay(path, ReplayFilter{TraceID: "t-aaa"})
	if err != nil {
		t.Fatal(err)
	}

	jsonStr, err := FormatJSON(result)
	if err != nil {
		t.Fatal(err)
	}

	// Should unmarshal back to a ReplayResult
	var parsed ReplayResult
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("JSON output not valid: %v", err)
	}
	if parsed.TraceID != "t-aaa" {
		t.Errorf("expected trace ID t-aaa, got %s", parsed.TraceID)
	}
	if len(parsed.Entries) != 5 {
		t.Errorf("expected 5 entries in JSON, got %d", len(parsed.Entries))
	}
	if parsed.Summary.Total != 5 {
		t.Errorf("expected total 5 in JSON summary, got %d", parsed.Summary.Total)
	}
}

func TestFormatTimelineEmptyEntries(t *testing.T) {
	result := &ReplayResult{
		TraceID: "t-empty",
	}

	out := FormatTimeline(result)
	if !strings.Contains(out, "No entries found") {
		t.Errorf("expected 'No entries found' message, got:\n%s", out)
	}
}
