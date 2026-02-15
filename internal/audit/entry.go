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
	PolicyHash string      `json:"policy_hash"`
	PrevHash   string      `json:"prev_hash"`
}
