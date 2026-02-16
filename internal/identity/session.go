package identity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Session tracks an active agent session within a trace.
type Session struct {
	AgentID   string    `json:"agent_id"`
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
}

// NewSession creates a session for the given agent with a generated session ID.
func NewSession(agentID string) *Session {
	return &Session{
		AgentID:   agentID,
		SessionID: generateSessionID(),
		CreatedAt: time.Now().UTC(),
	}
}

func generateSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("sess-%x", time.Now().UnixNano())
	}
	return "sess-" + hex.EncodeToString(b)
}
