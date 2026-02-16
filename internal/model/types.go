package model

import "time"

// Sensitivity classifies data sensitivity level.
type Sensitivity string

const (
	SensLow    Sensitivity = "low"
	SensMedium Sensitivity = "medium"
	SensHigh   Sensitivity = "high"
)

// SensRank maps sensitivity to a comparable integer for monotonic escalation.
var SensRank = map[Sensitivity]int{
	SensLow:    0,
	SensMedium: 1,
	SensHigh:   2,
}

// EgressDirection indicates where data is going.
type EgressDirection string

const (
	EgressInternal EgressDirection = "internal"
	EgressExternal EgressDirection = "external"
)

// Decision is the policy enforcement outcome.
type Decision string

const (
	Allow              Decision = "allow"
	Deny               Decision = "deny"
	AllowWithRedaction Decision = "allow_with_redaction"
	RequireApproval    Decision = "require_approval"
	RewriteOutput      Decision = "rewrite_output"
)

// ResultMeta is standardized metadata describing what a tool call returned.
type ResultMeta struct {
	Sensitivity Sensitivity     `json:"sensitivity"`
	Tags        []string        `json:"tags"`
	Rows        int             `json:"rows"`
	Bytes       int             `json:"bytes"`
	Egress      EgressDirection `json:"egress"`
	Destination string          `json:"destination"`
}

// DefaultResultMeta returns a ResultMeta with safe defaults.
func DefaultResultMeta() ResultMeta {
	return ResultMeta{
		Sensitivity: SensLow,
		Tags:        []string{},
		Egress:      EgressInternal,
	}
}

// ResultMetaFromMap creates a ResultMeta from a raw map with defensive coercion.
func ResultMetaFromMap(m map[string]any) ResultMeta {
	rm := DefaultResultMeta()
	if m == nil {
		return rm
	}

	if s, ok := m["sensitivity"].(string); ok {
		switch Sensitivity(s) {
		case SensLow, SensMedium, SensHigh:
			rm.Sensitivity = Sensitivity(s)
		}
	}

	if e, ok := m["egress"].(string); ok {
		switch EgressDirection(e) {
		case EgressInternal, EgressExternal:
			rm.Egress = EgressDirection(e)
		}
	}

	if tags, ok := m["tags"].([]any); ok {
		for _, t := range tags {
			if s, ok := t.(string); ok {
				rm.Tags = append(rm.Tags, s)
			}
		}
	}

	rm.Rows = toInt(m["rows"])
	rm.Bytes = toInt(m["bytes"])

	if d, ok := m["destination"].(string); ok {
		rm.Destination = d
	}

	return rm
}

// ToMap converts ResultMeta to a map for serialization.
func (rm ResultMeta) ToMap() map[string]any {
	return map[string]any{
		"sensitivity": string(rm.Sensitivity),
		"tags":        rm.Tags,
		"rows":        rm.Rows,
		"bytes":       rm.Bytes,
		"egress":      string(rm.Egress),
		"destination": rm.Destination,
	}
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case int64:
		return int(n)
	default:
		return 0
	}
}

// Action represents one intercepted operation in the agent chain.
type Action struct {
	Tool       string         `json:"tool"`
	Resource   string         `json:"resource"`
	Operation  string         `json:"operation"`
	Params     map[string]any `json:"params"`
	RawMeta    map[string]any `json:"result_meta"`
	normalized *ResultMeta
}

// NormalizedMeta returns the normalized ResultMeta, computing it if needed.
func (a *Action) NormalizedMeta() ResultMeta {
	if a.normalized != nil {
		return *a.normalized
	}
	rm := ResultMetaFromMap(a.RawMeta)
	return rm
}

// NormalizeMeta normalizes the raw metadata in-place.
func (a *Action) NormalizeMeta() {
	rm := ResultMetaFromMap(a.RawMeta)
	a.normalized = &rm
	a.RawMeta = rm.ToMap()
}

// TraceState is the evolving trace-level context that policies reason about.
type TraceState struct {
	TraceID        string          `json:"trace_id"`
	SeenSources    []string        `json:"seen_sources"`
	MaxSensitivity Sensitivity     `json:"max_sensitivity"`
	VolumeRows     int             `json:"volume_rows"`
	VolumeBytes    int             `json:"volume_bytes"`
	Egress         EgressDirection `json:"egress"`
	Tags           []string        `json:"tags"`

	// v0.2.0: monotonic irreversibility tracking
	Zone         BoundaryZone  `json:"zone"`
	ZonesEntered map[Zone]bool `json:"zones_entered"`

	// v0.3.0: agent identity
	AgentID   string `json:"agent_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`

	// v0.4.0: budget enforcement
	StartedAt time.Time `json:"started_at"`

	// v0.5.0: rate limiting
	ToolCallCounts       map[string]int `json:"tool_call_counts,omitempty"`
	RateLimitWindowStart time.Time      `json:"rate_limit_window_start"`
}

// NewTraceState creates a TraceState with safe defaults.
func NewTraceState(traceID string) *TraceState {
	return &TraceState{
		TraceID:              traceID,
		SeenSources:          []string{},
		MaxSensitivity:       SensLow,
		Egress:               EgressInternal,
		Tags:                 []string{},
		Zone:                 Safe,
		ZonesEntered:         make(map[Zone]bool),
		StartedAt:            time.Now().UTC(),
		ToolCallCounts:       make(map[string]int),
		RateLimitWindowStart: time.Now().UTC(),
	}
}

// EscalateLevel advances the boundary zone monotonically.
// If newLevel <= current, this is a no-op (monotonic property preserved).
func (ts *TraceState) EscalateLevel(newLevel BoundaryZone) {
	if newLevel > ts.Zone {
		ts.Zone = newLevel
	}
}

// HasSource returns true if the source has been seen before.
func (ts *TraceState) HasSource(source string) bool {
	for _, s := range ts.SeenSources {
		if s == source {
			return true
		}
	}
	return false
}

// PolicyResult is the output of policy evaluation.
type PolicyResult struct {
	Decision      Decision       `json:"decision"`
	Reason        string         `json:"reason"`
	Tier          int            `json:"tier"`
	Redactions    map[string]any `json:"redactions,omitempty"`
	ApprovalKey   string         `json:"approval_key,omitempty"`
	OutputRewrite string         `json:"output_rewrite,omitempty"`
	PolicyID      string         `json:"policy_id,omitempty"`
}
