package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	orchestratorpkg "github.com/ppiankov/chainwatch/internal/orchestrator"
)

func TestNotifyDryRunPrintsMessages(t *testing.T) {
	inventoryPath := writeInventoryFile(t, `
clickhouse:
  clusters:
    - name: dev
      hosts: [ch-dev-01]
      config_repo: infra/dev
notifications:
  slack:
    webhook_env: TEST_SLACK_WEBHOOK
`)
	input := `{
  "findings": [
    {
      "cluster": "dev-analytics",
      "summary": "Replication lag on shard 2",
      "finding": "active_replicas < total_replicas on 3 tables",
      "wo_id": "WO-CH-005",
      "jira_link": "https://jira.example/INFRA-1",
      "severity": "critical"
    },
    {
      "cluster": "dev-analytics",
      "summary": "Stale readonly user",
      "wo_id": "WO-CH-006",
      "jira_link": "https://jira.example/INFRA-2",
      "severity": "low"
    }
  ]
}`

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newRootCmd(strings.NewReader(input), &stdout, &stderr, func() time.Time {
		return time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)
	})
	cmd.SetArgs([]string{"notify", "--inventory", inventoryPath, "--dry-run"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "channel=#infra-critical") {
		t.Fatalf("expected critical routing in dry-run output, got:\n%s", out)
	}
	if !strings.Contains(out, "Daily findings digest") {
		t.Fatalf("expected digest output, got:\n%s", out)
	}
	if !strings.Contains(out, "dry-run complete") {
		t.Fatalf("expected dry-run completion line, got:\n%s", out)
	}
}

func TestNotifyRequiresWebhookEnvWhenSending(t *testing.T) {
	inventoryPath := writeInventoryFile(t, `
clickhouse:
  clusters:
    - name: dev
      hosts: [ch-dev-01]
      config_repo: infra/dev
notifications:
  slack:
    webhook_env: MISSING_WEBHOOK_ENV
`)
	input := `{
  "findings": [
    {
      "summary": "Critical finding",
      "wo_id": "WO-CH-001",
      "jira_link": "https://jira.example/INFRA-1",
      "severity": "critical"
    }
  ]
}`

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newRootCmd(strings.NewReader(input), &stdout, &stderr, time.Now)
	cmd.SetArgs([]string{"notify", "--inventory", inventoryPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected Execute to fail when webhook env var is unset")
	}
	if !strings.Contains(err.Error(), `environment variable "MISSING_WEBHOOK_ENV"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNotifySendsWebhookMessages(t *testing.T) {
	t.Setenv("TEST_SLACK_WEBHOOK", "https://hooks.slack.test/123")

	inventoryPath := writeInventoryFile(t, `
clickhouse:
  clusters:
    - name: dev
      hosts: [ch-dev-01]
      config_repo: infra/dev
notifications:
  slack:
    webhook_env: TEST_SLACK_WEBHOOK
`)
	input := `{
  "findings": [
    {
      "summary": "Critical finding",
      "wo_id": "WO-CH-001",
      "jira_link": "https://jira.example/INFRA-1",
      "severity": "critical"
    }
  ],
  "lifecycle": [
    {
      "event": "created",
      "summary": "WO created",
      "wo_id": "WO-CH-001",
      "jira_link": "https://jira.example/INFRA-1",
      "severity": "high"
    }
  ]
}`

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	requests := 0
	var senderWebhook string
	cmd := newRootCmdWithFactory(
		strings.NewReader(input),
		&stdout,
		&stderr,
		time.Now,
		func(webhookURL string) orchestratorpkg.Sender {
			senderWebhook = webhookURL
			return mockSender{
				sendFn: func(_ orchestratorpkg.Message) error {
					requests++
					return nil
				},
			}
		},
	)
	cmd.SetArgs([]string{"notify", "--inventory", inventoryPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if requests != 2 {
		t.Fatalf("webhook requests = %d, want 2", requests)
	}
	if senderWebhook != "https://hooks.slack.test/123" {
		t.Fatalf("sender webhook = %q, want env URL", senderWebhook)
	}
	if !strings.Contains(stdout.String(), "sent 2 Slack message(s)") {
		t.Fatalf("unexpected command output: %s", stdout.String())
	}
}

func TestStatusWOShowsFullLifecycle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "lifecycle.db")
	base := time.Date(2026, 3, 6, 9, 0, 0, 0, time.UTC)
	seedLifecycle(t, dbPath, []orchestratorpkg.LifecycleTransition{
		{
			WOID:           "WO-CH-001",
			ToState:        orchestratorpkg.LifecycleStateFinding,
			TransitionedAt: base,
			Finding:        "missing TTL on events table (dev-analytics)",
		},
		{
			WOID:           "WO-CH-001",
			ToState:        orchestratorpkg.LifecycleStateWO,
			TransitionedAt: base.Add(1 * time.Minute),
		},
		{
			WOID:           "WO-CH-001",
			ToState:        orchestratorpkg.LifecycleStateDispatched,
			TransitionedAt: base.Add(2 * time.Minute),
		},
		{
			WOID:           "WO-CH-001",
			ToState:        orchestratorpkg.LifecycleStatePROpen,
			TransitionedAt: base.Add(3 * time.Minute),
			PRURL:          "https://github.com/infra/clickhouse-dev-analytics/pull/42",
		},
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newRootCmd(strings.NewReader(""), &stdout, &stderr, time.Now)
	cmd.SetArgs([]string{"status", "--db", dbPath, "--wo", "WO-CH-001"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Current state: pr_open") {
		t.Fatalf("expected current state in output, got:\n%s", out)
	}
	if !strings.Contains(out, "PR: https://github.com/infra/clickhouse-dev-analytics/pull/42") {
		t.Fatalf("expected PR URL in output, got:\n%s", out)
	}
	if !strings.Contains(out, "finding: 2026-03-06 09:00:00 UTC") {
		t.Fatalf("expected lifecycle timeline, got:\n%s", out)
	}
	if !strings.Contains(out, "pr_merged: -") {
		t.Fatalf("expected missing lifecycle state marker, got:\n%s", out)
	}
}

func TestStatusAllAndStateFilter(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "lifecycle.db")
	base := time.Date(2026, 3, 6, 9, 0, 0, 0, time.UTC)
	seedLifecycle(t, dbPath, []orchestratorpkg.LifecycleTransition{
		{WOID: "WO-CH-001", ToState: orchestratorpkg.LifecycleStateFinding, TransitionedAt: base},
		{WOID: "WO-CH-001", ToState: orchestratorpkg.LifecycleStateWO, TransitionedAt: base.Add(1 * time.Minute)},
		{WOID: "WO-CH-001", ToState: orchestratorpkg.LifecycleStateDispatched, TransitionedAt: base.Add(2 * time.Minute)},
	})
	seedLifecycle(t, dbPath, []orchestratorpkg.LifecycleTransition{
		{WOID: "WO-CH-002", ToState: orchestratorpkg.LifecycleStateFinding, TransitionedAt: base.Add(3 * time.Minute)},
		{WOID: "WO-CH-002", ToState: orchestratorpkg.LifecycleStateWO, TransitionedAt: base.Add(4 * time.Minute)},
		{WOID: "WO-CH-002", ToState: orchestratorpkg.LifecycleStateDispatched, TransitionedAt: base.Add(5 * time.Minute)},
		{
			WOID:           "WO-CH-002",
			ToState:        orchestratorpkg.LifecycleStatePROpen,
			TransitionedAt: base.Add(6 * time.Minute),
			PRURL:          "https://github.com/infra/example/pull/17",
		},
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newRootCmd(strings.NewReader(""), &stdout, &stderr, time.Now)
	cmd.SetArgs([]string{"status", "--db", dbPath, "--all"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	allOut := stdout.String()
	if !strings.Contains(allOut, "WO-CH-001 [dispatched]") {
		t.Fatalf("expected WO-CH-001 in --all output, got:\n%s", allOut)
	}
	if !strings.Contains(allOut, "WO-CH-002 [pr_open]") {
		t.Fatalf("expected WO-CH-002 in --all output, got:\n%s", allOut)
	}

	stdout.Reset()
	stderr.Reset()
	cmd = newRootCmd(strings.NewReader(""), &stdout, &stderr, time.Now)
	cmd.SetArgs([]string{"status", "--db", dbPath, "--all", "--state", "pr_open"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute (filtered) returned error: %v", err)
	}

	filteredOut := stdout.String()
	if strings.Contains(filteredOut, "WO-CH-001") {
		t.Fatalf("did not expect WO-CH-001 in filtered output, got:\n%s", filteredOut)
	}
	if !strings.Contains(filteredOut, "WO-CH-002 [pr_open]") {
		t.Fatalf("expected WO-CH-002 in filtered output, got:\n%s", filteredOut)
	}
	if !strings.Contains(filteredOut, "PR: https://github.com/infra/example/pull/17") {
		t.Fatalf("expected PR URL in filtered output, got:\n%s", filteredOut)
	}
}

type mockSender struct {
	sendFn func(orchestratorpkg.Message) error
}

func (m mockSender) Send(_ context.Context, msg orchestratorpkg.Message) error {
	return m.sendFn(msg)
}

func writeInventoryFile(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0600); err != nil {
		t.Fatalf("write inventory file: %v", err)
	}
	return path
}

func seedLifecycle(t *testing.T, dbPath string, transitions []orchestratorpkg.LifecycleTransition) {
	t.Helper()
	store := orchestratorpkg.NewLifecycleStore(dbPath, nil)
	for _, transition := range transitions {
		if err := store.RecordTransition(transition); err != nil {
			t.Fatalf("seed lifecycle transition (%s, %s): %v", transition.WOID, transition.ToState, err)
		}
	}
}
