// Package wo defines the Work Order schema — the handoff artifact between
// nullbot (local observer) and runforge (cloud executor). A WO describes
// what was found during investigation and what remediation is proposed.
package wo

import "time"

// Version is the current WO schema version.
const Version = "1"

// ObservationType enumerates the kinds of findings nullbot can report.
type ObservationType string

const (
	FileHashMismatch  ObservationType = "file_hash_mismatch"
	RedirectDetected  ObservationType = "redirect_detected"
	UnauthorizedUser  ObservationType = "unauthorized_user"
	SuspiciousCode    ObservationType = "suspicious_code"
	ConfigModified    ObservationType = "config_modified"
	UnknownFile       ObservationType = "unknown_file"
	PermissionAnomaly ObservationType = "permission_anomaly"
	CronAnomaly       ObservationType = "cron_anomaly"
	ProcessAnomaly    ObservationType = "process_anomaly"
	NetworkAnomaly    ObservationType = "network_anomaly"
)

// validTypes is the set of recognized observation types.
var validTypes = map[ObservationType]bool{
	FileHashMismatch:  true,
	RedirectDetected:  true,
	UnauthorizedUser:  true,
	SuspiciousCode:    true,
	ConfigModified:    true,
	UnknownFile:       true,
	PermissionAnomaly: true,
	CronAnomaly:       true,
	ProcessAnomaly:    true,
	NetworkAnomaly:    true,
}

// IsValidType returns true if t is a recognized observation type.
func IsValidType(t ObservationType) bool {
	return validTypes[t]
}

// Severity indicates the urgency of an observation.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// validSeverities is the set of recognized severity levels.
var validSeverities = map[Severity]bool{
	SeverityLow:      true,
	SeverityMedium:   true,
	SeverityHigh:     true,
	SeverityCritical: true,
}

// IsValidSeverity returns true if s is a recognized severity level.
func IsValidSeverity(s Severity) bool {
	return validSeverities[s]
}

// WorkOrder is the structured handoff document between nullbot and runforge.
type WorkOrder struct {
	WOVersion     string        `json:"wo_version"`
	ID            string        `json:"id"`
	CreatedAt     time.Time     `json:"created_at"`
	IncidentID    string        `json:"incident_id"`
	Target        Target        `json:"target"`
	Observations  []Observation `json:"observations"`
	Constraints   Constraints   `json:"constraints"`
	ProposedGoals []string      `json:"proposed_goals"`
	RedactionMode string        `json:"redaction_mode"`
	TokenMapRef   string        `json:"token_map_ref,omitempty"`
}

// Target identifies the system under investigation.
type Target struct {
	Host  string `json:"host"`
	Scope string `json:"scope"`
}

// Observation is a single finding from the investigation.
type Observation struct {
	Type     ObservationType        `json:"type"`
	Severity Severity               `json:"severity"`
	Detail   string                 `json:"detail"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

// Constraints define what the remediation agent is allowed to do.
type Constraints struct {
	AllowPaths []string `json:"allow_paths"`
	DenyPaths  []string `json:"deny_paths"`
	Network    bool     `json:"network"`
	Sudo       bool     `json:"sudo"`
	MaxSteps   int      `json:"max_steps"`
}
