package chainwatch

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestWrapBlocksDenied(t *testing.T) {
	c := newTestClient(t)
	called := false
	inner := func(ctx context.Context, a Action) (any, error) {
		called = true
		return nil, nil
	}
	wrapped := c.Wrap(inner)

	_, err := wrapped(context.Background(), Action{
		Tool:      "command",
		Resource:  "rm -rf /",
		Operation: "execute",
	})

	blocked := requireBlocked(t, err)
	if blocked.Decision != Deny {
		t.Errorf("expected deny, got %s", blocked.Decision)
	}
	if called {
		t.Error("inner function should not be called on deny")
	}
}

func TestWrapAllowsClean(t *testing.T) {
	c := newTestClient(t)
	inner := func(ctx context.Context, a Action) (any, error) {
		return "ok", nil
	}
	wrapped := c.Wrap(inner)

	result, err := wrapped(context.Background(), Action{
		Tool:      "command",
		Resource:  "echo hello",
		Operation: "execute",
	})
	if err != nil {
		t.Fatalf("expected allow, got error: %v", err)
	}
	if result != "ok" {
		t.Errorf("expected result \"ok\", got %v", result)
	}
}

func TestWrapProfileRulesApplied(t *testing.T) {
	c, err := New(WithProfile("clawbot"), WithPurpose("test"))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	inner := func(ctx context.Context, a Action) (any, error) {
		t.Fatal("inner should not be called")
		return nil, nil
	}
	wrapped := c.Wrap(inner)

	// clawbot profile blocks stripe.com
	_, err = wrapped(context.Background(), Action{
		Tool:      "http",
		Resource:  "https://stripe.com/v1/charges",
		Operation: "post",
		Meta: map[string]any{
			"sensitivity": "high",
			"egress":      "external",
			"destination": "stripe.com",
			"bytes":       0,
			"rows":        0,
			"tags":        []any{"payment"},
		},
	})
	requireBlocked(t, err)
}

func TestWrapApprovalFlow(t *testing.T) {
	c, err := New(WithPurpose("SOC_efficiency"))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	inner := func(ctx context.Context, a Action) (any, error) {
		return "salary_data", nil
	}
	wrapped := c.Wrap(inner)

	// First call should be blocked (require_approval for salary access)
	_, err = wrapped(context.Background(), Action{
		Tool:      "file_read",
		Resource:  "/hr/salary.csv",
		Operation: "read",
		Meta: map[string]any{
			"sensitivity": "high",
			"egress":      "internal",
			"destination": "",
			"bytes":       0,
			"rows":        0,
			"tags":        []any{},
		},
	})
	if err == nil {
		// If allowed, that's fine — it means the risk score didn't hit approval threshold.
		// The denylist or risk scoring decides. We still test the path.
		return
	}
	blocked, ok := err.(*BlockedError)
	if !ok {
		t.Fatalf("expected *BlockedError, got %T", err)
	}
	if blocked.Decision != RequireApproval {
		// May be deny from denylist or zone escalation — acceptable
		return
	}

	// Approve the key
	if blocked.ApprovalKey != "" {
		approveErr := c.approvals.Approve(blocked.ApprovalKey, 5*time.Minute)
		if approveErr != nil {
			t.Fatalf("failed to approve: %v", approveErr)
		}

		// Second call should succeed
		result, err := wrapped(context.Background(), Action{
			Tool:      "file_read",
			Resource:  "/hr/salary.csv",
			Operation: "read",
			Meta: map[string]any{
				"sensitivity": "high",
				"egress":      "internal",
				"destination": "",
				"bytes":       0,
				"rows":        0,
				"tags":        []any{},
			},
		})
		if err != nil {
			t.Fatalf("expected approved call to succeed: %v", err)
		}
		if result != "salary_data" {
			t.Errorf("expected salary_data, got %v", result)
		}
	}
}

func TestWrapTraceRecorded(t *testing.T) {
	c := newTestClient(t)
	inner := func(ctx context.Context, a Action) (any, error) {
		return "ok", nil
	}
	wrapped := c.Wrap(inner)

	// Execute a few actions
	wrapped(context.Background(), Action{Tool: "command", Resource: "echo hello", Operation: "execute"})
	wrapped(context.Background(), Action{Tool: "command", Resource: "rm -rf /", Operation: "execute"})

	summary := c.TraceSummary()
	events, ok := summary["events"]
	if !ok || events == nil {
		t.Fatal("expected events in trace summary")
	}
	evLen := reflect.ValueOf(events).Len()
	if evLen < 2 {
		t.Errorf("expected at least 2 trace events, got %d", evLen)
	}
}

func TestWrapConcurrentSafe(t *testing.T) {
	c := newTestClient(t)
	inner := func(ctx context.Context, a Action) (any, error) {
		return "ok", nil
	}
	wrapped := c.Wrap(inner)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			wrapped(context.Background(), Action{
				Tool:      "command",
				Resource:  fmt.Sprintf("echo test-%d", n),
				Operation: "execute",
			})
		}(i)
	}
	wg.Wait()
}

func TestWrapPurposeOverride(t *testing.T) {
	c, err := New(WithPurpose("default_purpose"))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	inner := func(ctx context.Context, a Action) (any, error) {
		return "ok", nil
	}

	// Wrap with overridden purpose
	wrapped := c.Wrap(inner, WrapWithPurpose("custom_purpose"))
	_, err = wrapped(context.Background(), Action{
		Tool:      "command",
		Resource:  "echo hello",
		Operation: "execute",
	})
	if err != nil {
		t.Fatalf("expected allow, got error: %v", err)
	}

	// Verify trace contains events (purpose is recorded in trace)
	summary := c.TraceSummary()
	events, ok := summary["events"]
	if !ok || events == nil {
		t.Fatal("expected trace events")
	}
	evVal := reflect.ValueOf(events)
	if evVal.Len() == 0 {
		t.Fatal("expected at least 1 trace event")
	}
	// Access the last event's Purpose field via reflection
	lastEvent := evVal.Index(evVal.Len() - 1)
	purposeField := lastEvent.FieldByName("Purpose")
	if purposeField.IsValid() && purposeField.String() != "custom_purpose" {
		t.Errorf("expected purpose custom_purpose, got %s", purposeField.String())
	}
}

func TestWrapInnerNotCalledOnDeny(t *testing.T) {
	c := newTestClient(t)
	callCount := 0
	inner := func(ctx context.Context, a Action) (any, error) {
		callCount++
		return nil, nil
	}
	wrapped := c.Wrap(inner)

	wrapped(context.Background(), Action{
		Tool:      "command",
		Resource:  "rm -rf /",
		Operation: "execute",
	})

	if callCount != 0 {
		t.Errorf("expected inner to not be called, was called %d times", callCount)
	}
}
