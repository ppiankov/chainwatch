package audit

// AuditAction is the flattened action recorded in each audit entry.
type AuditAction struct {
	Tool     string `json:"tool"`
	Resource string `json:"resource"`
}

// AuditEntry is one line in the hash-chained JSONL audit log.
// All fields are structs (no map[string]any) to guarantee deterministic
// json.Marshal field order for reproducible hashing.
type AuditEntry struct {
	Timestamp  string      `json:"ts"`
	TraceID    string      `json:"trace_id"`
	Action     AuditAction `json:"action"`
	Decision   string      `json:"decision"`
	Reason     string      `json:"reason"`
	Tier       int         `json:"tier"`
	PolicyHash string      `json:"policy_hash"`
	PrevHash   string      `json:"prev_hash"`

	// Break-glass fields (CW-23.2) — only present for break-glass events.
	Type             string `json:"type,omitempty"`
	TokenID          string `json:"token_id,omitempty"`
	OriginalDecision string `json:"original_decision,omitempty"`
	OverriddenTo     string `json:"overridden_to,omitempty"`
	ExpiresAt        string `json:"expires_at,omitempty"`
}
