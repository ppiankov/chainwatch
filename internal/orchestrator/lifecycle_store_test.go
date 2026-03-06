package orchestrator

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestLifecycleStoreRecordAndGetStatus(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "lifecycle.db")
	store := NewLifecycleStore(dbPath, nil)

	base := time.Date(2026, 3, 6, 9, 0, 0, 0, time.UTC)
	finding := "missing TTL on events table (dev-analytics)"
	prURL := "https://github.com/infra/clickhouse-dev-analytics/pull/42"

	sequence := []LifecycleTransition{
		{
			WOID:           "WO-CH-001",
			ToState:        LifecycleStateFinding,
			TransitionedAt: base,
			Finding:        finding,
		},
		{
			WOID:           "WO-CH-001",
			ToState:        LifecycleStateWO,
			TransitionedAt: base.Add(1 * time.Minute),
		},
		{
			WOID:           "WO-CH-001",
			ToState:        LifecycleStateDispatched,
			TransitionedAt: base.Add(2 * time.Minute),
		},
		{
			WOID:           "WO-CH-001",
			ToState:        LifecycleStatePROpen,
			TransitionedAt: base.Add(3 * time.Minute),
			PRURL:          prURL,
		},
		{
			WOID:           "WO-CH-001",
			ToState:        LifecycleStatePRMerged,
			TransitionedAt: base.Add(4 * time.Minute),
		},
		{
			WOID:           "WO-CH-001",
			ToState:        LifecycleStateApplied,
			TransitionedAt: base.Add(5 * time.Minute),
		},
		{
			WOID:           "WO-CH-001",
			ToState:        LifecycleStateVerified,
			TransitionedAt: base.Add(6 * time.Minute),
		},
	}

	for _, transition := range sequence {
		if err := store.RecordTransition(transition); err != nil {
			t.Fatalf("RecordTransition(%s) returned error: %v", transition.ToState, err)
		}
	}

	status, err := store.GetWOStatus("WO-CH-001")
	if err != nil {
		t.Fatalf("GetWOStatus returned error: %v", err)
	}
	if status.CurrentState != LifecycleStateVerified {
		t.Fatalf("CurrentState = %q, want %q", status.CurrentState, LifecycleStateVerified)
	}
	if status.Finding != finding {
		t.Fatalf("Finding = %q, want %q", status.Finding, finding)
	}
	if status.PRURL != prURL {
		t.Fatalf("PRURL = %q, want %q", status.PRURL, prURL)
	}
	if len(status.Transitions) != len(sequence) {
		t.Fatalf("Transitions length = %d, want %d", len(status.Transitions), len(sequence))
	}
	for i, transition := range status.Transitions {
		if transition.ToState != sequence[i].ToState {
			t.Fatalf("Transitions[%d].ToState = %q, want %q", i, transition.ToState, sequence[i].ToState)
		}
	}
}

func TestLifecycleStoreRejectsInvalidSequence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "lifecycle.db")
	store := NewLifecycleStore(dbPath, nil)

	err := store.RecordTransition(LifecycleTransition{
		WOID:    "WO-CH-002",
		ToState: LifecycleStateWO,
	})
	if err == nil {
		t.Fatal("expected error for invalid initial state")
	}

	if err := store.RecordTransition(LifecycleTransition{
		WOID:    "WO-CH-002",
		ToState: LifecycleStateFinding,
	}); err != nil {
		t.Fatalf("RecordTransition(finding) returned error: %v", err)
	}

	err = store.RecordTransition(LifecycleTransition{
		WOID:    "WO-CH-002",
		ToState: LifecycleStateDispatched,
	})
	if err == nil {
		t.Fatal("expected error for skipping lifecycle state")
	}
}

func TestLifecycleStoreListCurrentStatusesFilter(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "lifecycle.db")
	store := NewLifecycleStore(dbPath, nil)

	base := time.Date(2026, 3, 6, 9, 0, 0, 0, time.UTC)

	recordSequence(t, store, []LifecycleTransition{
		{WOID: "WO-CH-101", ToState: LifecycleStateFinding, TransitionedAt: base},
		{WOID: "WO-CH-101", ToState: LifecycleStateWO, TransitionedAt: base.Add(1 * time.Minute)},
		{WOID: "WO-CH-101", ToState: LifecycleStateDispatched, TransitionedAt: base.Add(2 * time.Minute)},
	})
	recordSequence(t, store, []LifecycleTransition{
		{WOID: "WO-CH-102", ToState: LifecycleStateFinding, TransitionedAt: base.Add(3 * time.Minute)},
		{WOID: "WO-CH-102", ToState: LifecycleStateWO, TransitionedAt: base.Add(4 * time.Minute)},
		{WOID: "WO-CH-102", ToState: LifecycleStateDispatched, TransitionedAt: base.Add(5 * time.Minute)},
		{
			WOID:           "WO-CH-102",
			ToState:        LifecycleStatePROpen,
			TransitionedAt: base.Add(6 * time.Minute),
			PRURL:          "https://github.com/example/repo/pull/10",
		},
	})

	all, err := store.ListCurrentStatuses("")
	if err != nil {
		t.Fatalf("ListCurrentStatuses(all) returned error: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListCurrentStatuses(all) length = %d, want 2", len(all))
	}
	if all[0].WOID != "WO-CH-102" || all[0].CurrentState != LifecycleStatePROpen {
		t.Fatalf("first status = %#v, want WO-CH-102 in pr_open", all[0])
	}

	filtered, err := store.ListCurrentStatuses(LifecycleStatePROpen)
	if err != nil {
		t.Fatalf("ListCurrentStatuses(pr_open) returned error: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("ListCurrentStatuses(pr_open) length = %d, want 1", len(filtered))
	}
	if filtered[0].WOID != "WO-CH-102" {
		t.Fatalf("filtered[0].WOID = %q, want %q", filtered[0].WOID, "WO-CH-102")
	}
	if filtered[0].PRURL == "" {
		t.Fatal("expected PR URL in filtered status")
	}
}

func TestLifecycleStoreGetWOStatusNotFound(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "lifecycle.db")
	store := NewLifecycleStore(dbPath, nil)

	_, err := store.GetWOStatus("WO-UNKNOWN")
	if !errors.Is(err, ErrWorkOrderNotFound) {
		t.Fatalf("GetWOStatus error = %v, want ErrWorkOrderNotFound", err)
	}
}

func recordSequence(t *testing.T, store *LifecycleStore, sequence []LifecycleTransition) {
	t.Helper()
	for _, transition := range sequence {
		if err := store.RecordTransition(transition); err != nil {
			t.Fatalf("RecordTransition(%s, %s) returned error: %v", transition.WOID, transition.ToState, err)
		}
	}
}
