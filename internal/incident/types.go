package incident

import (
	"context"
	"time"
)

// Incident represents a created issue in JIRA or GitHub.
type Incident struct {
	ID          string
	Source      string // "jira" or "github"
	Key         string // JIRA key (e.g. "PROJ-123") or GitHub issue number
	URL         string
	FindingHash string
	Status      string
	CreatedAt   time.Time
}

// Backend creates issues in an external tracker.
type Backend interface {
	Create(ctx context.Context, input CreateInput) (*Incident, error)
	Name() string
}

// CreateInput holds the data needed to create an incident.
type CreateInput struct {
	Title    string
	Body     string
	Severity string
	Labels   []string
}
