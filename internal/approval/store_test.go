package approval

import (
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	return s
}

func TestRequestCreatesFile(t *testing.T) {
	s := newTestStore(t)
	err := s.Request("test_key", "test reason", "policy.test", "/data/file.csv")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	a, err := s.read("test_key")
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if a.Key != "test_key" {
		t.Errorf("expected key=test_key, got %s", a.Key)
	}
	if a.Status != StatusPending {
		t.Errorf("expected status=pending, got %s", a.Status)
	}
	if a.Reason != "test reason" {
		t.Errorf("expected reason='test reason', got %s", a.Reason)
	}
	if a.PolicyID != "policy.test" {
		t.Errorf("expected policyID=policy.test, got %s", a.PolicyID)
	}
	if a.Resource != "/data/file.csv" {
		t.Errorf("expected resource=/data/file.csv, got %s", a.Resource)
	}
}

func TestRequestIdempotent(t *testing.T) {
	s := newTestStore(t)
	s.Request("key1", "reason1", "p1", "/r1")
	s.Request("key1", "reason2", "p2", "/r2") // should not overwrite

	a, _ := s.read("key1")
	if a.Reason != "reason1" {
		t.Errorf("expected original reason, got %s", a.Reason)
	}
}

func TestApproveOneTime(t *testing.T) {
	s := newTestStore(t)
	s.Request("key1", "test", "p1", "/r1")

	err := s.Approve("key1", 0)
	if err != nil {
		t.Fatalf("Approve failed: %v", err)
	}

	status, _ := s.Check("key1")
	if status != StatusApproved {
		t.Errorf("expected approved, got %s", status)
	}

	a, _ := s.read("key1")
	if a.ExpiresAt != nil {
		t.Error("expected no expiration for one-time approval")
	}
	if a.ResolvedAt == nil {
		t.Error("expected resolved_at to be set")
	}
}

func TestApproveTimeLimited(t *testing.T) {
	s := newTestStore(t)
	s.Request("key1", "test", "p1", "/r1")

	err := s.Approve("key1", 5*time.Minute)
	if err != nil {
		t.Fatalf("Approve failed: %v", err)
	}

	a, _ := s.read("key1")
	if a.ExpiresAt == nil {
		t.Fatal("expected expires_at for time-limited approval")
	}
	if time.Until(*a.ExpiresAt) < 4*time.Minute {
		t.Error("expected expiration ~5 minutes from now")
	}
}

func TestDeny(t *testing.T) {
	s := newTestStore(t)
	s.Request("key1", "test", "p1", "/r1")

	err := s.Deny("key1")
	if err != nil {
		t.Fatalf("Deny failed: %v", err)
	}

	status, _ := s.Check("key1")
	if status != StatusDenied {
		t.Errorf("expected denied, got %s", status)
	}
}

func TestCheckPending(t *testing.T) {
	s := newTestStore(t)
	s.Request("key1", "test", "p1", "/r1")

	status, err := s.Check("key1")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if status != StatusPending {
		t.Errorf("expected pending, got %s", status)
	}
}

func TestCheckApproved(t *testing.T) {
	s := newTestStore(t)
	s.Request("key1", "test", "p1", "/r1")
	s.Approve("key1", 0)

	status, _ := s.Check("key1")
	if status != StatusApproved {
		t.Errorf("expected approved, got %s", status)
	}
}

func TestCheckDenied(t *testing.T) {
	s := newTestStore(t)
	s.Request("key1", "test", "p1", "/r1")
	s.Deny("key1")

	status, _ := s.Check("key1")
	if status != StatusDenied {
		t.Errorf("expected denied, got %s", status)
	}
}

func TestCheckExpired(t *testing.T) {
	s := newTestStore(t)
	s.Request("key1", "test", "p1", "/r1")

	// Approve with very short duration
	s.Approve("key1", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	status, _ := s.Check("key1")
	if status != StatusExpired {
		t.Errorf("expected expired, got %s", status)
	}
}

func TestCheckNotFound(t *testing.T) {
	s := newTestStore(t)

	_, err := s.Check("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestConsume(t *testing.T) {
	s := newTestStore(t)
	s.Request("key1", "test", "p1", "/r1")
	s.Approve("key1", 0)

	err := s.Consume("key1")
	if err != nil {
		t.Fatalf("Consume failed: %v", err)
	}

	status, _ := s.Check("key1")
	if status != StatusConsumed {
		t.Errorf("expected consumed, got %s", status)
	}
}

func TestConsumeAlreadyConsumed(t *testing.T) {
	s := newTestStore(t)
	s.Request("key1", "test", "p1", "/r1")
	s.Approve("key1", 0)
	s.Consume("key1")

	err := s.Consume("key1")
	if err == nil {
		t.Error("expected error for double consume")
	}
}

func TestList(t *testing.T) {
	s := newTestStore(t)
	s.Request("key1", "reason1", "p1", "/r1")
	s.Request("key2", "reason2", "p2", "/r2")
	s.Request("key3", "reason3", "p3", "/r3")

	list, err := s.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("expected 3 approvals, got %d", len(list))
	}
}

func TestCleanup(t *testing.T) {
	s := newTestStore(t)
	s.Request("key1", "test", "p1", "/r1")
	s.Request("key2", "test", "p2", "/r2")

	err := s.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	list, _ := s.List()
	if len(list) != 0 {
		t.Errorf("expected 0 after cleanup, got %d", len(list))
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := newTestStore(t)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := "concurrent_key"
			s.Request(key, "test", "p1", "/r1")
			s.Check(key)
		}(i)
	}
	wg.Wait()

	status, err := s.Check("concurrent_key")
	if err != nil {
		t.Fatalf("Check failed after concurrent access: %v", err)
	}
	if status != StatusPending {
		t.Errorf("expected pending, got %s", status)
	}
}

func TestApproveNonexistent(t *testing.T) {
	s := newTestStore(t)
	err := s.Approve("nonexistent", 0)
	if err == nil {
		t.Error("expected error for approving nonexistent key")
	}
}

func TestDenyNonexistent(t *testing.T) {
	s := newTestStore(t)
	err := s.Deny("nonexistent")
	if err == nil {
		t.Error("expected error for denying nonexistent key")
	}
}
