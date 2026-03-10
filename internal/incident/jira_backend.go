package incident

import (
	"context"
	"fmt"
	"time"

	"github.com/ppiankov/chainwatch/internal/jira"
)

// JIRABackend creates incidents as JIRA issues.
type JIRABackend struct {
	client      jira.Creator
	priorityMap map[string]string
}

// NewJIRABackend returns a backend that creates JIRA issues via the given client.
// priorityMap maps severity (critical/high/medium/low) to JIRA priority names.
func NewJIRABackend(client jira.Creator, priorityMap map[string]string) *JIRABackend {
	return &JIRABackend{client: client, priorityMap: priorityMap}
}

func (b *JIRABackend) Name() string { return "jira" }

func (b *JIRABackend) Create(ctx context.Context, input CreateInput) (*Incident, error) {
	priority := mapSeverityToJIRAPriority(input.Severity, b.priorityMap)

	issue, err := b.client.CreateIssue(ctx, jira.CreateIssueInput{
		Summary:     input.Title,
		Description: input.Body,
		Priority:    priority,
		Labels:      input.Labels,
	})
	if err != nil {
		return nil, fmt.Errorf("jira create: %w", err)
	}

	return &Incident{
		Source:    "jira",
		Key:       issue.Key,
		URL:       "", // JIRA client does not return URL; caller can construct from baseURL + key
		CreatedAt: time.Now(),
	}, nil
}

var defaultPriorityMap = map[string]string{
	"critical": "Highest",
	"high":     "High",
	"medium":   "Medium",
	"low":      "Low",
}

func mapSeverityToJIRAPriority(severity string, custom map[string]string) string {
	if custom != nil {
		if p, ok := custom[severity]; ok {
			return p
		}
	}
	if p, ok := defaultPriorityMap[severity]; ok {
		return p
	}
	return "Medium"
}
