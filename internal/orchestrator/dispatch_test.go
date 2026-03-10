package orchestrator

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/chainwatch/internal/jira"
)

type fakeJIRACreator struct {
	calls         []jira.CreateIssueInput
	createIssueFn func(context.Context, jira.CreateIssueInput) (*jira.Issue, error)
}

func (f *fakeJIRACreator) CreateIssue(
	ctx context.Context,
	input jira.CreateIssueInput,
) (*jira.Issue, error) {
	f.calls = append(f.calls, input)
	if f.createIssueFn != nil {
		return f.createIssueFn(ctx, input)
	}
	return &jira.Issue{Key: "CHAIN-1"}, nil
}

func (f *fakeJIRACreator) AddComment(context.Context, string, string) error {
	return nil
}

func TestParseDispatchInput(t *testing.T) {
	t.Run("valid JSON", func(t *testing.T) {
		input, err := ParseDispatchInput(strings.NewReader(`{
			"tasks": [
				{
					"id": "WO-1",
					"repo": "infra/prod",
					"title": "Fix drift",
					"prompt": "Apply change",
					"priority": 2,
					"metadata": {
						"source": "nullbot",
						"runbook": "rb-1",
						"finding_hash": "hash-1",
						"scope": "prod",
						"severity": "high",
						"remediation_type": "terraform"
					}
				}
			]
		}`))
		if err != nil {
			t.Fatalf("ParseDispatchInput returned error: %v", err)
		}
		if len(input.Tasks) != 1 {
			t.Fatalf("task count = %d, want 1", len(input.Tasks))
		}
		if input.Tasks[0].ID != "WO-1" {
			t.Fatalf("task ID = %q, want %q", input.Tasks[0].ID, "WO-1")
		}
	})

	t.Run("empty tasks", func(t *testing.T) {
		input, err := ParseDispatchInput(strings.NewReader(`{"tasks":[]}`))
		if err != nil {
			t.Fatalf("ParseDispatchInput returned error: %v", err)
		}
		if len(input.Tasks) != 0 {
			t.Fatalf("task count = %d, want 0", len(input.Tasks))
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		_, err := ParseDispatchInput(strings.NewReader(`{"tasks":`))
		if err == nil {
			t.Fatal("ParseDispatchInput error = nil, want non-nil")
		}
		if !strings.Contains(err.Error(), "parse dispatch input") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestRouteTarget(t *testing.T) {
	tests := []struct {
		name            string
		remediationType string
		want            string
	}{
		{name: "terraform", remediationType: RemediationTerraform, want: "codex:terraform-planner"},
		{name: "config", remediationType: RemediationConfig, want: "codex:config-writer"},
		{name: "k8s", remediationType: RemediationK8s, want: "codex:k8s"},
		{name: "manual", remediationType: RemediationManual, want: "jira-only"},
		{name: "both", remediationType: RemediationBoth, want: "codex:terraform-planner+config-writer"},
		{name: "unknown", remediationType: "shell", want: "codex:default"},
	}

	for _, tt := range tests {
		if got := routeTarget(tt.remediationType); got != tt.want {
			t.Fatalf("%s routeTarget(%q) = %q, want %q", tt.name, tt.remediationType, got, tt.want)
		}
	}
}

func TestDispatchDryRun(t *testing.T) {
	store := NewLifecycleStore(t.TempDir()+"/lifecycle.db", nil)
	jiraCreator := &fakeJIRACreator{}
	dispatcher := NewDispatcher(DispatcherConfig{
		LifecycleStore: store,
		JIRACreator:    jiraCreator,
		DryRun:         true,
	})

	results, err := dispatcher.Dispatch(context.Background(), &DispatchInput{
		Tasks: []DispatchTask{testDispatchTask(RemediationTerraform)},
	})
	if err != nil {
		t.Fatalf("Dispatch returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("result count = %d, want 1", len(results))
	}

	result := results[0]
	if !result.DryRun {
		t.Fatalf("result DryRun = %t, want true", result.DryRun)
	}
	if result.Routed != "codex:terraform-planner" {
		t.Fatalf("result Routed = %q, want %q", result.Routed, "codex:terraform-planner")
	}
	if result.JIRAKey != "" {
		t.Fatalf("result JIRAKey = %q, want empty", result.JIRAKey)
	}
	if len(jiraCreator.calls) != 0 {
		t.Fatalf("CreateIssue calls = %d, want 0", len(jiraCreator.calls))
	}

	_, err = store.GetWOStatus("WO-123")
	if !errors.Is(err, ErrWorkOrderNotFound) {
		t.Fatalf("GetWOStatus error = %v, want %v", err, ErrWorkOrderNotFound)
	}
}

func TestDispatchCreatesJIRATicket(t *testing.T) {
	jiraCreator := &fakeJIRACreator{
		createIssueFn: func(_ context.Context, input jira.CreateIssueInput) (*jira.Issue, error) {
			return &jira.Issue{Key: "CHAIN-42"}, nil
		},
	}
	dispatcher := NewDispatcher(DispatcherConfig{
		JIRACreator: jiraCreator,
		JIRABaseURL: "https://jira.example/",
	})

	prompt := strings.Repeat("x", maxJIRADescriptionBytes+64)
	task := testDispatchTask(RemediationConfig)
	task.Title = "Rotate config secret"
	task.Prompt = prompt
	task.Priority = 2

	results, err := dispatcher.Dispatch(context.Background(), &DispatchInput{
		Tasks: []DispatchTask{task},
	})
	if err != nil {
		t.Fatalf("Dispatch returned error: %v", err)
	}
	if len(jiraCreator.calls) != 1 {
		t.Fatalf("CreateIssue calls = %d, want 1", len(jiraCreator.calls))
	}

	call := jiraCreator.calls[0]
	if call.Summary != "[chainwatch] Rotate config secret" {
		t.Fatalf("summary = %q, want %q", call.Summary, "[chainwatch] Rotate config secret")
	}
	if len(call.Description) != maxJIRADescriptionBytes {
		t.Fatalf("description length = %d, want %d", len(call.Description), maxJIRADescriptionBytes)
	}
	if call.Description != prompt[:maxJIRADescriptionBytes] {
		t.Fatal("description was not truncated from task prompt")
	}
	if call.Priority != "High" {
		t.Fatalf("priority = %q, want %q", call.Priority, "High")
	}
	wantLabels := []string{"chainwatch", "auto-dispatched", RemediationConfig}
	if !reflect.DeepEqual(call.Labels, wantLabels) {
		t.Fatalf("labels = %#v, want %#v", call.Labels, wantLabels)
	}
	if call.WOID != task.ID {
		t.Fatalf("WOID = %q, want %q", call.WOID, task.ID)
	}

	if len(results) != 1 {
		t.Fatalf("result count = %d, want 1", len(results))
	}
	if results[0].JIRAKey != "CHAIN-42" {
		t.Fatalf("JIRAKey = %q, want %q", results[0].JIRAKey, "CHAIN-42")
	}
	if results[0].JIRALink != "https://jira.example/browse/CHAIN-42" {
		t.Fatalf("JIRALink = %q, want %q", results[0].JIRALink, "https://jira.example/browse/CHAIN-42")
	}
}

func TestDispatchManualCreatesTicketOnly(t *testing.T) {
	jiraCreator := &fakeJIRACreator{
		createIssueFn: func(_ context.Context, input jira.CreateIssueInput) (*jira.Issue, error) {
			return &jira.Issue{Key: "CHAIN-77"}, nil
		},
	}
	dispatcher := NewDispatcher(DispatcherConfig{
		JIRACreator: jiraCreator,
	})

	task := testDispatchTask(RemediationManual)
	results, err := dispatcher.Dispatch(context.Background(), &DispatchInput{
		Tasks: []DispatchTask{task},
	})
	if err != nil {
		t.Fatalf("Dispatch returned error: %v", err)
	}
	if len(jiraCreator.calls) != 1 {
		t.Fatalf("CreateIssue calls = %d, want 1", len(jiraCreator.calls))
	}
	if len(results) != 1 {
		t.Fatalf("result count = %d, want 1", len(results))
	}
	if results[0].Routed != "jira-only" {
		t.Fatalf("Routed = %q, want %q", results[0].Routed, "jira-only")
	}
	if results[0].JIRAKey != "CHAIN-77" {
		t.Fatalf("JIRAKey = %q, want %q", results[0].JIRAKey, "CHAIN-77")
	}
}

func TestDispatchContinuesWhenJIRAFails(t *testing.T) {
	store := NewLifecycleStore(t.TempDir()+"/lifecycle.db", nil)
	jiraCreator := &fakeJIRACreator{
		createIssueFn: func(_ context.Context, input jira.CreateIssueInput) (*jira.Issue, error) {
			return nil, errors.New("jira unavailable")
		},
	}
	dispatcher := NewDispatcher(DispatcherConfig{
		LifecycleStore: store,
		JIRACreator:    jiraCreator,
	})

	task := testDispatchTask(RemediationConfig)
	results, err := dispatcher.Dispatch(context.Background(), &DispatchInput{
		Tasks: []DispatchTask{task},
	})
	if err != nil {
		t.Fatalf("Dispatch returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("result count = %d, want 1", len(results))
	}
	if results[0].Error != "" {
		t.Fatalf("result error = %q, want empty", results[0].Error)
	}
	if results[0].JIRAKey != "" {
		t.Fatalf("JIRAKey = %q, want empty", results[0].JIRAKey)
	}

	status, err := store.GetWOStatus(task.ID)
	if err != nil {
		t.Fatalf("GetWOStatus returned error: %v", err)
	}
	if status.CurrentState != LifecycleStateDispatched {
		t.Fatalf("CurrentState = %q, want %q", status.CurrentState, LifecycleStateDispatched)
	}
}

func TestDispatchUpdatesLifecycleState(t *testing.T) {
	baseTime := time.Date(2026, 3, 10, 15, 30, 0, 0, time.UTC)
	store := NewLifecycleStore(t.TempDir()+"/lifecycle.db", nil)
	dispatcher := NewDispatcher(DispatcherConfig{
		LifecycleStore: store,
		NowFn: func() time.Time {
			return baseTime
		},
	})

	task := testDispatchTask(RemediationK8s)
	results, err := dispatcher.Dispatch(context.Background(), &DispatchInput{
		Tasks: []DispatchTask{task},
	})
	if err != nil {
		t.Fatalf("Dispatch returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("result count = %d, want 1", len(results))
	}
	if results[0].Error != "" {
		t.Fatalf("result error = %q, want empty", results[0].Error)
	}

	status, err := store.GetWOStatus(task.ID)
	if err != nil {
		t.Fatalf("GetWOStatus returned error: %v", err)
	}
	if status.CurrentState != LifecycleStateDispatched {
		t.Fatalf("CurrentState = %q, want %q", status.CurrentState, LifecycleStateDispatched)
	}
	if status.Finding != task.Title {
		t.Fatalf("Finding = %q, want %q", status.Finding, task.Title)
	}
	if len(status.Transitions) != 3 {
		t.Fatalf("transition count = %d, want 3", len(status.Transitions))
	}

	gotStates := []LifecycleState{
		status.Transitions[0].ToState,
		status.Transitions[1].ToState,
		status.Transitions[2].ToState,
	}
	wantStates := []LifecycleState{
		LifecycleStateFinding,
		LifecycleStateWO,
		LifecycleStateDispatched,
	}
	if !reflect.DeepEqual(gotStates, wantStates) {
		t.Fatalf("states = %#v, want %#v", gotStates, wantStates)
	}
	if !status.LastTransition.Equal(baseTime) {
		t.Fatalf("LastTransition = %s, want %s", status.LastTransition, baseTime)
	}
}

func TestDispatchWithEmptyInput(t *testing.T) {
	dispatcher := NewDispatcher(DispatcherConfig{})

	results, err := dispatcher.Dispatch(context.Background(), &DispatchInput{})
	if err != nil {
		t.Fatalf("Dispatch returned error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("result count = %d, want 0", len(results))
	}
}

func testDispatchTask(remediationType string) DispatchTask {
	return DispatchTask{
		ID:       "WO-123",
		Repo:     "infra/prod",
		Title:    "Fix risky change",
		Prompt:   "Update the configuration safely.",
		Priority: 1,
		Metadata: DispatchTaskMeta{
			Source:          "nullbot",
			Runbook:         "rb-123",
			FindingHash:     "hash-123",
			Scope:           "prod",
			Severity:        "critical",
			RemediationType: remediationType,
		},
	}
}
