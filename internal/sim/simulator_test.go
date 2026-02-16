package sim

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ppiankov/chainwatch/internal/audit"
)

// writeAuditLog writes entries as JSONL to a temp file.
func writeAuditLog(t *testing.T, entries []audit.AuditEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// writePolicy writes YAML to a temp file.
func writePolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIdenticalPolicyZeroChanges(t *testing.T) {
	entries := []audit.AuditEntry{
		{
			Timestamp: "2025-01-15T14:00:12.000Z",
			TraceID:   "t-1",
			Action:    audit.AuditAction{Tool: "file_read", Resource: "/data/report.csv"},
			Decision:  "allow",
			Tier:      1,
		},
		{
			Timestamp: "2025-01-15T14:00:14.000Z",
			TraceID:   "t-1",
			Action:    audit.AuditAction{Tool: "command", Resource: "ls /tmp"},
			Decision:  "allow",
			Tier:      1,
		},
	}
	logPath := writeAuditLog(t, entries)

	// Default policy: guarded mode, tier 1 = allow
	policyPath := writePolicy(t, `
enforcement_mode: guarded
thresholds:
  allow_max: 5
  approval_min: 11
sensitivity_weights:
  low: 1
  medium: 3
  high: 6
`)

	result, err := Simulate(logPath, policyPath, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalActions != 2 {
		t.Errorf("expected 2 total actions, got %d", result.TotalActions)
	}
	if result.ChangedActions != 0 {
		t.Errorf("expected 0 changed, got %d", result.ChangedActions)
	}
}

func TestStricterPolicyNewlyBlocked(t *testing.T) {
	// Original: advisory mode → all allowed
	entries := []audit.AuditEntry{
		{
			Timestamp: "2025-01-15T14:00:12.000Z",
			TraceID:   "t-1",
			Action:    audit.AuditAction{Tool: "file_read", Resource: "/data/report.csv"},
			Decision:  "allow",
			Tier:      1,
		},
	}
	logPath := writeAuditLog(t, entries)

	// New policy: locked mode → tier 1 requires approval
	policyPath := writePolicy(t, `
enforcement_mode: locked
`)

	result, err := Simulate(logPath, policyPath, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.ChangedActions != 1 {
		t.Errorf("expected 1 changed, got %d", result.ChangedActions)
	}
	if result.NewlyBlocked != 1 {
		t.Errorf("expected 1 newly blocked, got %d", result.NewlyBlocked)
	}
}

func TestLooserPolicyNewlyAllowed(t *testing.T) {
	// Original: deny decision
	entries := []audit.AuditEntry{
		{
			Timestamp: "2025-01-15T14:00:12.000Z",
			TraceID:   "t-1",
			Action:    audit.AuditAction{Tool: "file_read", Resource: "/data/report.csv"},
			Decision:  "deny",
			Tier:      3,
		},
	}
	logPath := writeAuditLog(t, entries)

	// New policy: advisory mode → everything allowed
	policyPath := writePolicy(t, `
enforcement_mode: advisory
`)

	result, err := Simulate(logPath, policyPath, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.ChangedActions != 1 {
		t.Errorf("expected 1 changed, got %d", result.ChangedActions)
	}
	if result.NewlyAllowed != 1 {
		t.Errorf("expected 1 newly allowed, got %d", result.NewlyAllowed)
	}
}

func TestEmptyAuditLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(logPath, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	policyPath := writePolicy(t, `enforcement_mode: guarded`)

	result, err := Simulate(logPath, policyPath, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalActions != 0 {
		t.Errorf("expected 0 total actions, got %d", result.TotalActions)
	}
	if result.ChangedActions != 0 {
		t.Errorf("expected 0 changed, got %d", result.ChangedActions)
	}
}

func TestInvalidPolicyReturnsError(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	// Write invalid YAML content (LoadConfig returns defaults for missing files)
	badPolicy := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(badPolicy, []byte(":::not yaml\x00"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Simulate(logPath, badPolicy, "", "", "")
	if err == nil {
		t.Error("expected error for invalid policy YAML")
	}
}

func TestNewlyBlockedAndAllowedCounts(t *testing.T) {
	entries := []audit.AuditEntry{
		{
			Timestamp: "2025-01-15T14:00:12.000Z",
			TraceID:   "t-1",
			Action:    audit.AuditAction{Tool: "file_read", Resource: "/data/a.csv"},
			Decision:  "allow",
			Tier:      1,
		},
		{
			Timestamp: "2025-01-15T14:00:13.000Z",
			TraceID:   "t-1",
			Action:    audit.AuditAction{Tool: "file_read", Resource: "/data/b.csv"},
			Decision:  "deny",
			Tier:      3,
		},
	}
	logPath := writeAuditLog(t, entries)

	// locked mode: tier 1 → require_approval (blocks the allow), but tier 3 → deny (stays deny)
	// Actually tier 1 in locked → require_approval. The "allow" entry becomes "require_approval" (newly blocked).
	// The "deny" entry stays deny (no change).
	policyPath := writePolicy(t, `enforcement_mode: locked`)

	result, err := Simulate(logPath, policyPath, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalActions != 2 {
		t.Errorf("expected 2 total, got %d", result.TotalActions)
	}
	if result.NewlyBlocked != 1 {
		t.Errorf("expected 1 newly blocked, got %d", result.NewlyBlocked)
	}
	if result.NewlyAllowed != 0 {
		t.Errorf("expected 0 newly allowed, got %d", result.NewlyAllowed)
	}
}

func TestMultiTraceIndependentState(t *testing.T) {
	entries := []audit.AuditEntry{
		{
			Timestamp: "2025-01-15T14:00:12.000Z",
			TraceID:   "t-1",
			Action:    audit.AuditAction{Tool: "file_read", Resource: "/data/a.csv"},
			Decision:  "allow",
			Tier:      1,
		},
		{
			Timestamp: "2025-01-15T14:00:13.000Z",
			TraceID:   "t-2",
			Action:    audit.AuditAction{Tool: "file_read", Resource: "/data/b.csv"},
			Decision:  "allow",
			Tier:      1,
		},
	}
	logPath := writeAuditLog(t, entries)

	policyPath := writePolicy(t, `enforcement_mode: guarded`)

	result, err := Simulate(logPath, policyPath, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalActions != 2 {
		t.Errorf("expected 2 total, got %d", result.TotalActions)
	}
}

func TestDiffEntryFieldsPopulated(t *testing.T) {
	entries := []audit.AuditEntry{
		{
			Timestamp: "2025-01-15T14:00:12.000Z",
			TraceID:   "t-1",
			Action:    audit.AuditAction{Tool: "file_read", Resource: "/data/salary.csv"},
			Decision:  "allow",
			Reason:    "tier 1 in advisory mode",
			Tier:      1,
		},
	}
	logPath := writeAuditLog(t, entries)

	// locked mode: tier 1 → require_approval
	policyPath := writePolicy(t, `enforcement_mode: locked`)

	result, err := Simulate(logPath, policyPath, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(result.Changes))
	}
	d := result.Changes[0]
	if d.Timestamp != "2025-01-15T14:00:12.000Z" {
		t.Errorf("timestamp: got %s", d.Timestamp)
	}
	if d.TraceID != "t-1" {
		t.Errorf("trace_id: got %s", d.TraceID)
	}
	if d.Tool != "file_read" {
		t.Errorf("tool: got %s", d.Tool)
	}
	if d.Resource != "/data/salary.csv" {
		t.Errorf("resource: got %s", d.Resource)
	}
	if d.OldDecision != "allow" {
		t.Errorf("old_decision: got %s", d.OldDecision)
	}
	if d.NewDecision != "require_approval" {
		t.Errorf("new_decision: got %s", d.NewDecision)
	}
	if d.OldReason != "tier 1 in advisory mode" {
		t.Errorf("old_reason: got %s", d.OldReason)
	}
	if d.NewReason == "" {
		t.Error("new_reason should not be empty")
	}
}
