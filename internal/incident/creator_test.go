package incident

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ppiankov/chainwatch/internal/observe"
)

// mockBackend records calls and returns predictable incidents.
type mockBackend struct {
	calls   []CreateInput
	failing bool
}

func (m *mockBackend) Name() string { return "mock" }

func (m *mockBackend) Create(_ context.Context, input CreateInput) (*Incident, error) {
	m.calls = append(m.calls, input)
	if m.failing {
		return nil, fmt.Errorf("mock failure")
	}
	return &Incident{
		ID:        fmt.Sprintf("mock-%d", len(m.calls)),
		Source:    "mock",
		Key:       fmt.Sprintf("MOCK-%d", len(m.calls)),
		URL:       fmt.Sprintf("https://mock/issue/%d", len(m.calls)),
		CreatedAt: time.Now(),
	}, nil
}

func tempStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestDedup_SameHashSkipped(t *testing.T) {
	store := tempStore(t)
	backend := &mockBackend{}
	creator := NewCreator(backend, store)
	ctx := context.Background()

	finding := observe.Finding{
		Type:     "slow_queries",
		Severity: "high",
		Detail:   "query took 30s",
		Hash:     "abc123",
	}

	inc1, err := creator.CreateFromFinding(ctx, finding)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	if inc1 == nil {
		t.Fatal("expected incident, got nil")
	}

	inc2, err := creator.CreateFromFinding(ctx, finding)
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if inc2 != nil {
		t.Fatal("expected nil (dedup), got incident")
	}

	if len(backend.calls) != 1 {
		t.Fatalf("expected 1 backend call, got %d", len(backend.calls))
	}
}

func TestBatchCreation(t *testing.T) {
	store := tempStore(t)
	backend := &mockBackend{}
	creator := NewCreator(backend, store)
	ctx := context.Background()

	findings := []observe.Finding{
		{Type: "slow_queries", Severity: "high", Detail: "query 1", Hash: "hash1"},
		{Type: "missing_ttl", Severity: "medium", Detail: "no TTL on table", Hash: "hash2"},
		{Type: "replication_lag", Severity: "critical", Detail: "lag 5m", Hash: "hash3"},
	}

	incidents, err := creator.CreateFromFindings(ctx, findings)
	if err != nil {
		t.Fatalf("batch create: %v", err)
	}

	if len(incidents) != 3 {
		t.Fatalf("expected 3 incidents, got %d", len(incidents))
	}
	if len(backend.calls) != 3 {
		t.Fatalf("expected 3 backend calls, got %d", len(backend.calls))
	}
}

func TestBatchWithDuplicates(t *testing.T) {
	store := tempStore(t)
	backend := &mockBackend{}
	creator := NewCreator(backend, store)
	ctx := context.Background()

	findings := []observe.Finding{
		{Type: "slow_queries", Severity: "high", Detail: "query 1", Hash: "dup1"},
		{Type: "slow_queries", Severity: "high", Detail: "query 1 again", Hash: "dup1"},
		{Type: "missing_ttl", Severity: "medium", Detail: "no TTL", Hash: "dup2"},
	}

	incidents, err := creator.CreateFromFindings(ctx, findings)
	if err != nil {
		t.Fatalf("batch create: %v", err)
	}

	if len(incidents) != 2 {
		t.Fatalf("expected 2 incidents (1 deduped), got %d", len(incidents))
	}
	if len(backend.calls) != 2 {
		t.Fatalf("expected 2 backend calls, got %d", len(backend.calls))
	}
}

func TestSeverityMapping(t *testing.T) {
	store := tempStore(t)
	backend := &mockBackend{}
	creator := NewCreator(backend, store)
	ctx := context.Background()

	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "critical"},
		{"high", "high"},
		{"medium", "medium"},
		{"low", "low"},
	}

	for i, tt := range tests {
		f := observe.Finding{
			Type:     "test",
			Severity: tt.severity,
			Detail:   fmt.Sprintf("detail %d", i),
			Hash:     fmt.Sprintf("sev-%d", i),
		}
		_, err := creator.CreateFromFinding(ctx, f)
		if err != nil {
			t.Fatalf("create %s: %v", tt.severity, err)
		}
		call := backend.calls[i]
		if call.Severity != tt.want {
			t.Errorf("severity %s: got input.Severity=%s, want %s", tt.severity, call.Severity, tt.want)
		}
		// Verify severity is in labels
		found := false
		for _, l := range call.Labels {
			if l == tt.severity {
				found = true
			}
		}
		if !found {
			t.Errorf("severity %s not in labels: %v", tt.severity, call.Labels)
		}
	}
}

func TestJIRAPriorityMapping(t *testing.T) {
	tests := []struct {
		severity string
		custom   map[string]string
		want     string
	}{
		{"critical", nil, "Highest"},
		{"high", nil, "High"},
		{"medium", nil, "Medium"},
		{"low", nil, "Low"},
		{"unknown", nil, "Medium"},
		{"critical", map[string]string{"critical": "Blocker"}, "Blocker"},
		{"high", map[string]string{"critical": "Blocker"}, "High"}, // falls through to default
	}

	for _, tt := range tests {
		got := mapSeverityToJIRAPriority(tt.severity, tt.custom)
		if got != tt.want {
			t.Errorf("mapSeverityToJIRAPriority(%q, %v) = %q, want %q", tt.severity, tt.custom, got, tt.want)
		}
	}
}

func TestFormatTitle_Truncation(t *testing.T) {
	short := observe.Finding{Type: "test", Detail: "short detail", Hash: "h1"}
	title := formatTitle(short)
	if title != "[chainwatch] test: short detail" {
		t.Errorf("unexpected title: %s", title)
	}

	long := observe.Finding{Type: "test", Detail: string(make([]byte, 200)), Hash: "h2"}
	longTitle := formatTitle(long)
	if len(longTitle) > 120 {
		t.Errorf("title too long: %d chars", len(longTitle))
	}
}

func TestStoreOpenClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "incidents.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("db file not created: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestStoreFindByHash_NotFound(t *testing.T) {
	store := tempStore(t)
	inc, err := store.FindByHash("nonexistent")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if inc != nil {
		t.Fatal("expected nil for nonexistent hash")
	}
}

func TestStoreSaveAndFind(t *testing.T) {
	store := tempStore(t)
	now := time.Now()

	inc := &Incident{
		ID:          "test-1",
		Source:      "jira",
		Key:         "PROJ-1",
		URL:         "https://jira/PROJ-1",
		FindingHash: "hash1",
		Status:      "open",
		CreatedAt:   now,
	}

	if err := store.Save(inc); err != nil {
		t.Fatalf("save: %v", err)
	}

	found, err := store.FindByHash("hash1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if found == nil {
		t.Fatal("expected incident, got nil")
	}
	if found.Key != "PROJ-1" {
		t.Errorf("key = %s, want PROJ-1", found.Key)
	}
}

func TestBackendFailure(t *testing.T) {
	store := tempStore(t)
	backend := &mockBackend{failing: true}
	creator := NewCreator(backend, store)

	f := observe.Finding{Type: "test", Severity: "high", Detail: "fail", Hash: "fail1"}
	_, err := creator.CreateFromFinding(context.Background(), f)
	if err == nil {
		t.Fatal("expected error from failing backend")
	}
}
