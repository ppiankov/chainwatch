package chainwatch

import (
	"testing"
)

func newTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(WithPurpose("test"))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return c
}

func requireBlocked(t *testing.T, err error) *BlockedError {
	t.Helper()
	if err == nil {
		t.Fatal("expected action to be blocked, got nil error")
	}
	blocked, ok := err.(*BlockedError)
	if !ok {
		t.Fatalf("expected *BlockedError, got %T: %v", err, err)
	}
	return blocked
}

func TestNewDefault(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New() with defaults should succeed: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewWithProfile(t *testing.T) {
	c, err := New(WithProfile("clawbot"))
	if err != nil {
		t.Fatalf("New(WithProfile(\"clawbot\")) should succeed: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewBadProfile(t *testing.T) {
	_, err := New(WithProfile("nonexistent-profile-xyz"))
	if err == nil {
		t.Fatal("expected error for nonexistent profile")
	}
}

func TestCheckAllow(t *testing.T) {
	c := newTestClient(t)
	result := c.Check(Action{
		Tool:      "command",
		Resource:  "echo hello",
		Operation: "execute",
	})
	if result.Decision != Allow {
		t.Errorf("expected allow for echo, got %s: %s", result.Decision, result.Reason)
	}
}

func TestCheckDenylistedCommand(t *testing.T) {
	c := newTestClient(t)
	result := c.Check(Action{
		Tool:      "command",
		Resource:  "rm -rf /",
		Operation: "execute",
	})
	if result.Decision != Deny {
		t.Errorf("expected deny for rm -rf /, got %s", result.Decision)
	}
}
