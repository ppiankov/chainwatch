package observe

import (
	"testing"
	"time"
)

func TestComputeFindingHashStableAcrossMapOrder(t *testing.T) {
	a := map[string]any{
		"database": "analytics",
		"table":    "events",
		"column":   "event_time",
	}
	b := map[string]any{
		"column":   "event_time",
		"table":    "events",
		"database": "analytics",
	}

	hashA, err := ComputeFindingHash("missing_ttl", "dev-analytics", a)
	if err != nil {
		t.Fatalf("ComputeFindingHash(a): %v", err)
	}
	hashB, err := ComputeFindingHash("missing_ttl", "dev-analytics", b)
	if err != nil {
		t.Fatalf("ComputeFindingHash(b): %v", err)
	}

	if hashA != hashB {
		t.Fatalf("hash mismatch: %q != %q", hashA, hashB)
	}

	hashDifferentScope, err := ComputeFindingHash("missing_ttl", "prod-analytics", a)
	if err != nil {
		t.Fatalf("ComputeFindingHash(different scope): %v", err)
	}
	if hashA == hashDifferentScope {
		t.Fatal("expected different hash for different scope")
	}
}

func TestApplyFindingDedupLifecycle(t *testing.T) {
	cachePath := CacheDir(t.TempDir())
	hash, err := ComputeFindingHash("clickhouse_missing_ttl", "dev-analytics", map[string]any{
		"table":  "events",
		"column": "event_time",
	})
	if err != nil {
		t.Fatalf("ComputeFindingHash: %v", err)
	}

	base := time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)
	window := 24 * time.Hour

	first, err := ApplyFindingDedup(cachePath, hash, "wo-ttl-001", base, window)
	if err != nil {
		t.Fatalf("ApplyFindingDedup(create): %v", err)
	}
	if first.Action != FindingDedupActionCreate {
		t.Fatalf("first action = %q, want %q", first.Action, FindingDedupActionCreate)
	}
	if first.Record.Status != FindingStatusOpen {
		t.Fatalf("first status = %q, want %q", first.Record.Status, FindingStatusOpen)
	}

	dup, err := ApplyFindingDedup(cachePath, hash, "wo-ttl-ignored", base.Add(2*time.Hour), window)
	if err != nil {
		t.Fatalf("ApplyFindingDedup(open duplicate): %v", err)
	}
	if dup.Action != FindingDedupActionSuppress {
		t.Fatalf("dup action = %q, want %q", dup.Action, FindingDedupActionSuppress)
	}
	if dup.Reason != FindingDedupReasonOpenWO {
		t.Fatalf("dup reason = %q, want %q", dup.Reason, FindingDedupReasonOpenWO)
	}

	closedAt := base.Add(4 * time.Hour)
	if err := UpdateFindingHashStatus(cachePath, hash, FindingStatusClosed, closedAt); err != nil {
		t.Fatalf("UpdateFindingHashStatus(closed): %v", err)
	}

	flap, err := ApplyFindingDedup(cachePath, hash, "wo-ttl-ignored", closedAt.Add(2*time.Hour), window)
	if err != nil {
		t.Fatalf("ApplyFindingDedup(window suppress): %v", err)
	}
	if flap.Action != FindingDedupActionSuppress {
		t.Fatalf("flap action = %q, want %q", flap.Action, FindingDedupActionSuppress)
	}
	if flap.Reason != FindingDedupReasonDedupWindow {
		t.Fatalf("flap reason = %q, want %q", flap.Reason, FindingDedupReasonDedupWindow)
	}
	if flap.Record.Status != FindingStatusClosed {
		t.Fatalf("flap status = %q, want %q", flap.Record.Status, FindingStatusClosed)
	}

	reopenedAt := closedAt.Add(30 * time.Hour)
	reopened, err := ApplyFindingDedup(cachePath, hash, "wo-ttl-ignored", reopenedAt, window)
	if err != nil {
		t.Fatalf("ApplyFindingDedup(reopen): %v", err)
	}
	if reopened.Action != FindingDedupActionReopen {
		t.Fatalf("reopen action = %q, want %q", reopened.Action, FindingDedupActionReopen)
	}
	if reopened.Reason != FindingDedupReasonRecurring {
		t.Fatalf("reopen reason = %q, want %q", reopened.Reason, FindingDedupReasonRecurring)
	}
	if reopened.Record.Status != FindingStatusOpen {
		t.Fatalf("reopen status = %q, want %q", reopened.Record.Status, FindingStatusOpen)
	}

	stored, err := ReadFindingHash(cachePath, hash)
	if err != nil {
		t.Fatalf("ReadFindingHash: %v", err)
	}
	if stored == nil {
		t.Fatal("expected stored finding hash record")
	}
	if !stored.LastSeen.Equal(reopenedAt) {
		t.Fatalf("last_seen = %s, want %s", stored.LastSeen.Format(time.RFC3339), reopenedAt.Format(time.RFC3339))
	}
	if stored.Status != FindingStatusOpen {
		t.Fatalf("stored status = %q, want %q", stored.Status, FindingStatusOpen)
	}
}
