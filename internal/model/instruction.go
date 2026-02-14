package model

// InstructionContext is metadata about instruction origin and integrity.
// This is enforcement-layer context only — never passed to the model.
type InstructionContext struct {
	Origin          string  `json:"origin"`           // "direct_user_interface", "network", "file", "env"
	SecurityContext string  `json:"security_context"` // "user_terminal", "web_interface", "api_endpoint"
	Timestamp       float64 `json:"timestamp"`
	SessionID       string  `json:"session_id"`
	IsProxied       bool    `json:"is_proxied"`
	IsRelayed       bool    `json:"is_relayed"`
	HasControlChars bool    `json:"has_control_chars"`
}

// CrossesTrustBoundary returns true if this instruction crosses a trust boundary.
// Structural check — not a heuristic, not ML, just boolean logic.
func (ic InstructionContext) CrossesTrustBoundary() bool {
	if ic.Origin != "direct_user_interface" {
		return true
	}
	if ic.IsProxied || ic.IsRelayed {
		return true
	}
	return false
}

// AdmissionResult is the outcome of an authority boundary check.
type AdmissionResult struct {
	Admitted     bool              `json:"admitted"`
	Decision     Decision          `json:"decision,omitempty"`
	Reason       string            `json:"reason,omitempty"`
	BoundaryType AuthorityBoundary `json:"boundary_type,omitempty"`
}
