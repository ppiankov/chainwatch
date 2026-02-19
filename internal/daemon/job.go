// Package daemon implements the nullbot inbox/outbox job processing service.
// Jobs arrive as JSON files in the inbox directory, are processed sequentially,
// and results are written to the outbox directory.
package daemon

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ppiankov/chainwatch/internal/wo"
)

// JobStatus represents the lifecycle state of an inbox job.
type JobStatus string

const (
	JobQueued     JobStatus = "queued"
	JobProcessing JobStatus = "processing"
	JobDone       JobStatus = "done"
	JobFailed     JobStatus = "failed"
)

// Valid job types that the daemon can process.
const (
	JobTypeInvestigate = "investigate"
	JobTypeObserve     = "observe"
)

// validJobTypes is the set of accepted job type values.
var validJobTypes = map[string]bool{
	JobTypeInvestigate: true,
	JobTypeObserve:     true,
}

// validID matches alphanumeric characters, dashes, and underscores only.
var validID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Job is a unit of work dropped into the inbox.
type Job struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Target    JobTarget `json:"target"`
	Brief     string    `json:"brief"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

// JobTarget identifies the system to investigate.
type JobTarget struct {
	Host  string `json:"host"`
	Scope string `json:"scope"`
}

// Result is written to the outbox after processing a job.
type Result struct {
	ID           string           `json:"id"`
	Status       string           `json:"status"`
	Observations []wo.Observation `json:"observations,omitempty"`
	ProposedWO   *wo.WorkOrder    `json:"proposed_wo,omitempty"`
	Error        string           `json:"error,omitempty"`
	CompletedAt  time.Time        `json:"completed_at"`
}

// Result status values.
const (
	ResultDone            = "done"
	ResultFailed          = "failed"
	ResultPendingApproval = "pending_approval"
)

// ValidateJob checks that a job has all required fields and safe values.
func ValidateJob(j *Job) error {
	if j.ID == "" {
		return fmt.Errorf("job ID is required")
	}
	if strings.Contains(j.ID, "..") {
		return fmt.Errorf("job ID must not contain '..'")
	}
	if !validID.MatchString(j.ID) {
		return fmt.Errorf("job ID contains invalid characters: only alphanumeric, dash, and underscore allowed")
	}
	if j.Type == "" {
		return fmt.Errorf("job type is required")
	}
	if !validJobTypes[j.Type] {
		return fmt.Errorf("invalid job type %q: must be one of: investigate, observe", j.Type)
	}
	if j.Target.Scope == "" {
		return fmt.Errorf("job target scope is required")
	}
	if j.Brief == "" {
		return fmt.Errorf("job brief is required")
	}
	return nil
}
