package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ppiankov/chainwatch/internal/jira"
)

// Remediation type constants for WO routing.
const (
	RemediationTerraform = "terraform"
	RemediationConfig    = "config"
	RemediationK8s       = "k8s"
	RemediationManual    = "manual"
	RemediationBoth      = "both"
)

// DispatchInput is the tokencontrol task file produced by `nullbot observe --format wo`.
type DispatchInput struct {
	Tasks []DispatchTask `json:"tasks"`
}

// DispatchTask is one WO task to route.
type DispatchTask struct {
	ID           string           `json:"id"`
	Repo         string           `json:"repo"`
	Title        string           `json:"title"`
	Prompt       string           `json:"prompt"`
	Priority     int              `json:"priority"`
	Difficulty   string           `json:"difficulty,omitempty"`
	Runner       string           `json:"runner,omitempty"`
	Dependencies []string         `json:"dependencies,omitempty"`
	Metadata     DispatchTaskMeta `json:"metadata"`
}

// DispatchTaskMeta carries finding provenance for routing decisions.
type DispatchTaskMeta struct {
	Source          string `json:"source"`
	Runbook         string `json:"runbook"`
	FindingHash     string `json:"finding_hash"`
	Scope           string `json:"scope"`
	Severity        string `json:"severity,omitempty"`
	RemediationType string `json:"remediation_type,omitempty"`
}

// DispatchResult captures the outcome of dispatching one task.
type DispatchResult struct {
	WOID     string `json:"wo_id"`
	JIRAKey  string `json:"jira_key,omitempty"`
	JIRALink string `json:"jira_link,omitempty"`
	Routed   string `json:"routed_to"` // "terraform", "config", "manual", etc.
	DryRun   bool   `json:"dry_run"`
	Error    string `json:"error,omitempty"`
}

// DispatcherConfig holds construction parameters for a Dispatcher.
type DispatcherConfig struct {
	LifecycleStore *LifecycleStore
	JIRAClient     jira.Creator // nil disables JIRA ticket creation
	NotifyService  *Service
	NotifyConfig   Config
	JIRABaseURL    string            // for building JIRA links
	PriorityMap    map[string]string // severity → JIRA priority
	DryRun         bool
	NowFn          func() time.Time
}

// Dispatcher routes WO tasks by remediation type, creates JIRA tickets,
// and records lifecycle transitions.
type Dispatcher struct {
	store       *LifecycleStore
	jiraClient  jira.Creator
	notifySvc   *Service
	notifyCfg   Config
	jiraBaseURL string
	priorityMap map[string]string
	dryRun      bool
	nowFn       func() time.Time
}

// NewDispatcher creates a new WO task dispatcher.
func NewDispatcher(cfg DispatcherConfig) *Dispatcher {
	nowFn := cfg.NowFn
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	return &Dispatcher{
		store:       cfg.LifecycleStore,
		jiraClient:  cfg.JIRAClient,
		notifySvc:   cfg.NotifyService,
		notifyCfg:   cfg.NotifyConfig,
		jiraBaseURL: cfg.JIRABaseURL,
		priorityMap: cfg.PriorityMap,
		dryRun:      cfg.DryRun,
		nowFn:       nowFn,
	}
}

// ParseDispatchInput reads a tokencontrol task file from a reader.
func ParseDispatchInput(r io.Reader) (*DispatchInput, error) {
	var input DispatchInput
	if err := json.NewDecoder(r).Decode(&input); err != nil {
		return nil, fmt.Errorf("parse dispatch input: %w", err)
	}
	return &input, nil
}

// Dispatch routes all tasks: creates lifecycle entries, JIRA tickets,
// and returns dispatch results. In dry-run mode, no side effects occur.
func (d *Dispatcher) Dispatch(ctx context.Context, input *DispatchInput) ([]DispatchResult, error) {
	results := make([]DispatchResult, 0, len(input.Tasks))

	for _, task := range input.Tasks {
		result := d.dispatchOne(ctx, task)
		results = append(results, result)
	}

	return results, nil
}

func (d *Dispatcher) dispatchOne(ctx context.Context, task DispatchTask) DispatchResult {
	result := DispatchResult{
		WOID:   task.ID,
		Routed: routeTarget(task.Metadata.RemediationType),
		DryRun: d.dryRun,
	}

	if d.dryRun {
		return result
	}

	now := d.nowFn()

	// Record lifecycle: finding → wo.
	if d.store != nil {
		if err := d.store.RecordTransition(LifecycleTransition{
			WOID:           task.ID,
			FromState:      "",
			ToState:        LifecycleStateFinding,
			TransitionedAt: now,
			Finding:        task.Title,
		}); err != nil {
			result.Error = fmt.Sprintf("lifecycle finding: %v", err)
			return result
		}
		if err := d.store.RecordTransition(LifecycleTransition{
			WOID:           task.ID,
			FromState:      LifecycleStateFinding,
			ToState:        LifecycleStateWO,
			TransitionedAt: now,
		}); err != nil {
			result.Error = fmt.Sprintf("lifecycle wo: %v", err)
			return result
		}
	}

	// Create JIRA ticket.
	if d.jiraClient != nil {
		priority := jira.MapPriority(task.Metadata.Severity, d.priorityMap)
		issue, err := d.jiraClient.CreateIssue(ctx, jira.CreateIssueInput{
			Summary:     task.Title,
			Description: task.Prompt,
			Priority:    priority,
			Labels:      []string{task.Metadata.Runbook, task.Metadata.RemediationType},
			WOID:        task.ID,
		})
		if err != nil {
			result.Error = fmt.Sprintf("jira create: %v", err)
			return result
		}
		result.JIRAKey = issue.Key
		if d.jiraBaseURL != "" {
			result.JIRALink = fmt.Sprintf("%s/browse/%s", d.jiraBaseURL, issue.Key)
		}
	}

	// Record lifecycle: wo → dispatched.
	if d.store != nil {
		if err := d.store.RecordTransition(LifecycleTransition{
			WOID:           task.ID,
			FromState:      LifecycleStateWO,
			ToState:        LifecycleStateDispatched,
			TransitionedAt: now,
		}); err != nil {
			result.Error = fmt.Sprintf("lifecycle dispatched: %v", err)
			return result
		}
	}

	// Send notification.
	if d.notifySvc != nil {
		notifyInput := Input{
			LifecycleEvents: []LifecycleEvent{{
				Event:    eventCreated,
				Summary:  task.Title,
				WOID:     task.ID,
				JIRALink: result.JIRALink,
				Severity: task.Metadata.Severity,
			}},
		}
		_, _ = d.notifySvc.Notify(ctx, notifyInput, d.notifyCfg, false)
	}

	return result
}

// routeTarget determines the dispatch destination from remediation type.
func routeTarget(remediationType string) string {
	switch remediationType {
	case RemediationTerraform:
		return "codex:terraform-planner"
	case RemediationConfig:
		return "codex:config-writer"
	case RemediationK8s:
		return "codex:k8s"
	case RemediationBoth:
		return "codex:terraform-planner+config-writer"
	case RemediationManual:
		return "jira-only"
	default:
		return "codex:default"
	}
}
