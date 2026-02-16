package identity

import (
	"strings"
	"testing"
	"time"
)

func TestNewSessionGeneratesID(t *testing.T) {
	s := NewSession("test-agent")
	if s.SessionID == "" {
		t.Error("expected non-empty session ID")
	}
	if !strings.HasPrefix(s.SessionID, "sess-") {
		t.Errorf("expected sess- prefix, got %q", s.SessionID)
	}
	if s.AgentID != "test-agent" {
		t.Errorf("expected agent_id test-agent, got %q", s.AgentID)
	}
}

func TestNewSessionTimestamp(t *testing.T) {
	before := time.Now().UTC()
	s := NewSession("test-agent")
	after := time.Now().UTC()

	if s.CreatedAt.Before(before) || s.CreatedAt.After(after) {
		t.Errorf("created_at %v not between %v and %v", s.CreatedAt, before, after)
	}
}
