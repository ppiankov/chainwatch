// Package jira provides a JIRA REST API client for work order ticket management.
// All tokens are resolved from environment variables — never stored in code or config.
package jira

import (
	"context"
	"net/http"
	"time"
)

// Issue represents a JIRA issue summary.
type Issue struct {
	Key         string   `json:"key"`
	Summary     string   `json:"summary"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Priority    string   `json:"priority"`
	Assignee    string   `json:"assignee,omitempty"`
	Labels      []string `json:"labels,omitempty"`
	WOID        string   `json:"wo_id,omitempty"` // chainwatch WO ID stored as label
}

// CreateIssueInput describes a new JIRA issue to create.
type CreateIssueInput struct {
	Summary     string
	Description string
	Priority    string // JIRA priority name (e.g. "Highest", "High")
	Assignee    string
	Labels      []string
	WOID        string // added as label: "wo:<id>"
}

// Transition describes a JIRA issue status transition.
type Transition struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Creator is the interface the orchestrator dispatch uses to create JIRA tickets.
type Creator interface {
	CreateIssue(ctx context.Context, input CreateIssueInput) (*Issue, error)
	AddComment(ctx context.Context, issueKey, body string) error
}

// Closer is the interface the orchestrator verify uses to close JIRA tickets.
type Closer interface {
	TransitionIssue(ctx context.Context, issueKey, targetStatus string) error
}

// Client is a JIRA REST API client.
type Client struct {
	baseURL    string
	token      string
	project    string
	assignee   string
	httpClient *http.Client
}

// ClientConfig holds construction parameters for a JIRA client.
type ClientConfig struct {
	BaseURL  string
	Token    string
	Project  string
	Assignee string
	Client   *http.Client // nil uses http.DefaultClient
}

// NewClient creates a JIRA REST API client.
func NewClient(cfg ClientConfig) *Client {
	hc := cfg.Client
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		baseURL:    cfg.BaseURL,
		token:      cfg.Token,
		project:    cfg.Project,
		assignee:   cfg.Assignee,
		httpClient: hc,
	}
}

// CreateIssue creates a JIRA issue via REST API.
// Implementation provided in client.go.
func (c *Client) CreateIssue(ctx context.Context, input CreateIssueInput) (*Issue, error) {
	return createIssue(c, ctx, input)
}

// GetIssue retrieves a JIRA issue by key.
func (c *Client) GetIssue(ctx context.Context, issueKey string) (*Issue, error) {
	return getIssue(c, ctx, issueKey)
}

// AddComment adds a comment to a JIRA issue.
func (c *Client) AddComment(ctx context.Context, issueKey, body string) error {
	return addComment(c, ctx, issueKey, body)
}

// TransitionIssue transitions a JIRA issue to the target status.
func (c *Client) TransitionIssue(ctx context.Context, issueKey, targetStatus string) error {
	return transitionIssue(c, ctx, issueKey, targetStatus)
}

// MapPriority converts a chainwatch severity to a JIRA priority name
// using the provided priority map from inventory config.
func MapPriority(severity string, priorityMap map[string]string) string {
	if p, ok := priorityMap[severity]; ok {
		return p
	}
	// Sensible defaults.
	defaults := map[string]string{
		"critical": "Highest",
		"high":     "High",
		"medium":   "Medium",
		"low":      "Low",
	}
	if p, ok := defaults[severity]; ok {
		return p
	}
	return "Medium"
}
