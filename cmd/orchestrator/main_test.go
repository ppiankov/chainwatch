package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/chainwatch/internal/inventory"
	"github.com/ppiankov/chainwatch/internal/observe"
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

func TestTransitionCommand(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "lifecycle.db")
	base := time.Date(2026, 3, 6, 9, 0, 0, 0, time.UTC)
	seedLifecycle(t, dbPath, []orchestratorpkg.LifecycleTransition{
		{WOID: "WO-CH-003", ToState: orchestratorpkg.LifecycleStateFinding, TransitionedAt: base},
		{WOID: "WO-CH-003", ToState: orchestratorpkg.LifecycleStateWO, TransitionedAt: base.Add(1 * time.Minute)},
		{WOID: "WO-CH-003", ToState: orchestratorpkg.LifecycleStateDispatched, TransitionedAt: base.Add(2 * time.Minute)},
		{
			WOID:           "WO-CH-003",
			ToState:        orchestratorpkg.LifecycleStatePROpen,
			TransitionedAt: base.Add(3 * time.Minute),
			PRURL:          "https://github.com/infra/example/pull/22",
		},
	})

	t.Run("records allowed transition", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		cmd := newRootCmd(strings.NewReader(""), &stdout, &stderr, time.Now)
		cmd.SetArgs([]string{"transition", "--db", dbPath, "--wo", "WO-CH-003", "--to", "pr_merged"})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute returned error: %v", err)
		}

		out := stdout.String()
		if !strings.Contains(out, "recorded transition WO-CH-003: pr_open -> pr_merged") {
			t.Fatalf("expected transition confirmation, got:\n%s", out)
		}

		store := orchestratorpkg.NewLifecycleStore(dbPath, nil)
		status, err := store.GetWOStatus("WO-CH-003")
		if err != nil {
			t.Fatalf("GetWOStatus returned error: %v", err)
		}
		if status.CurrentState != orchestratorpkg.LifecycleStatePRMerged {
			t.Fatalf("CurrentState = %q, want %q", status.CurrentState, orchestratorpkg.LifecycleStatePRMerged)
		}
	})

	t.Run("rejects invalid transition", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		cmd := newRootCmd(strings.NewReader(""), &stdout, &stderr, time.Now)
		cmd.SetArgs([]string{"transition", "--db", dbPath, "--wo", "WO-CH-003", "--to", "verified"})

		err := cmd.Execute()
		if err == nil {
			t.Fatal("expected invalid transition to fail")
		}
		if !strings.Contains(err.Error(), `expected next state "applied", got "verified"`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestDispatchDryRunPrintsResults(t *testing.T) {
	inventoryPath := writeInventoryFile(t, `
clickhouse:
  clusters:
    - name: dev
      hosts: [ch-dev-01]
      config_repo: infra/dev
bedrock:
  region: us-east-1
`)
	input := `{
  "tasks": [
    {
      "id": "WO-TF-001",
      "repo": "infra/dev",
      "title": "Apply Terraform remediation",
      "prompt": "Update Terraform module settings.",
      "priority": 2,
      "metadata": {
        "source": "nullbot",
        "runbook": "rb-terraform",
        "finding_hash": "hash-terraform",
        "scope": "dev",
        "severity": "high",
        "remediation_type": "terraform"
      }
    }
  ]
}`

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newRootCmd(strings.NewReader(input), &stdout, &stderr, time.Now)
	cmd.SetArgs([]string{
		"dispatch",
		"--inventory", inventoryPath,
		"--db", filepath.Join(t.TempDir(), "dispatch.db"),
		"--dry-run",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "WO-TF-001 → codex:terraform-planner [dry-run]") {
		t.Fatalf("expected dry-run dispatch result, got:\n%s", out)
	}
	if !strings.Contains(out, "dry-run complete: 1 task(s) routed, 0 dispatched") {
		t.Fatalf("expected dry-run summary, got:\n%s", out)
	}
}

func TestDispatchRequiresInput(t *testing.T) {
	inventoryPath := writeInventoryFile(t, `
clickhouse:
  clusters:
    - name: dev
      hosts: [ch-dev-01]
      config_repo: infra/dev
bedrock:
  region: us-east-1
`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newRootCmd(strings.NewReader(""), &stdout, &stderr, time.Now)
	cmd.SetArgs([]string{"dispatch", "--inventory", inventoryPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected Execute to fail when no dispatch input is provided")
	}
	if !strings.Contains(err.Error(), "parse dispatch input") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyCommand(t *testing.T) {
	chainwatchPath, outputPath := writeFakeChainwatch(t)
	t.Setenv("CHAINWATCH_BIN", chainwatchPath)
	t.Setenv("AUDIT_LOG", filepath.Join(t.TempDir(), "audit.jsonl"))

	inventoryPath := writeInventoryFile(t, `
clickhouse:
  clusters:
    - name: dev
      hosts: [ch-dev-01]
      config_repo: infra/dev
`)
	inv, err := inventory.Load(inventoryPath)
	if err != nil {
		t.Fatalf("inventory.Load returned error: %v", err)
	}

	if err := os.WriteFile(outputPath, []byte("before-remediation\n"), 0600); err != nil {
		t.Fatalf("write fake chainwatch output: %v", err)
	}

	runnerCfg := observe.RunnerConfig{
		Scope:      defaultVerifyScopeFromInventory,
		Type:       "clickhouse",
		Chainwatch: chainwatchPath,
		AuditLog:   filepath.Join(t.TempDir(), "verify-audit.jsonl"),
	}
	initialRun, err := runVerifyWithInventory(context.Background(), runnerCfg, inv)
	if err != nil {
		t.Fatalf("runVerifyWithInventory returned error: %v", err)
	}
	originalHash := observe.ComputeEvidenceHash(observe.CollectEvidence(initialRun))

	dbPath := filepath.Join(t.TempDir(), "verify.db")
	woID := "wo-verify-cli"
	if _, err := observe.ApplyFindingDedup(
		dbPath,
		originalHash,
		woID,
		time.Date(2026, 3, 11, 10, 0, 0, 0, time.UTC),
		time.Hour,
	); err != nil {
		t.Fatalf("ApplyFindingDedup returned error: %v", err)
	}
	seedLifecycle(t, dbPath, []orchestratorpkg.LifecycleTransition{
		{WOID: woID, ToState: orchestratorpkg.LifecycleStateFinding},
		{WOID: woID, ToState: orchestratorpkg.LifecycleStateWO},
		{WOID: woID, ToState: orchestratorpkg.LifecycleStateDispatched},
		{WOID: woID, ToState: orchestratorpkg.LifecycleStatePROpen},
		{WOID: woID, ToState: orchestratorpkg.LifecycleStatePRMerged},
		{WOID: woID, ToState: orchestratorpkg.LifecycleStateApplied},
	})

	if err := os.WriteFile(outputPath, []byte("after-remediation\n"), 0600); err != nil {
		t.Fatalf("update fake chainwatch output: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newRootCmd(strings.NewReader(""), &stdout, &stderr, time.Now)
	cmd.SetArgs([]string{
		"verify",
		"--wo", woID,
		"--inventory", inventoryPath,
		"--type", "clickhouse",
		"--db", dbPath,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Passed: true") {
		t.Fatalf("expected successful verification output, got:\n%s", out)
	}
	if !strings.Contains(out, "Lifecycle: verified") {
		t.Fatalf("expected verified lifecycle output, got:\n%s", out)
	}

	store := orchestratorpkg.NewLifecycleStore(dbPath, nil)
	status, err := store.GetWOStatus(woID)
	if err != nil {
		t.Fatalf("GetWOStatus returned error: %v", err)
	}
	if status.CurrentState != orchestratorpkg.LifecycleStateVerified {
		t.Fatalf("CurrentState = %q, want %q", status.CurrentState, orchestratorpkg.LifecycleStateVerified)
	}

	record, err := observe.ReadFindingHash(dbPath, originalHash)
	if err != nil {
		t.Fatalf("ReadFindingHash returned error: %v", err)
	}
	if record == nil {
		t.Fatal("expected finding hash record")
	}
	if record.Status != observe.FindingStatusClosed {
		t.Fatalf("finding hash status = %q, want %q", record.Status, observe.FindingStatusClosed)
	}
}

func TestScheduleCommandCrontab(t *testing.T) {
	inventoryPath := writeInventoryFile(t, `
clickhouse:
  clusters:
    - name: prod
      hosts: [ch-01]
      config_repo: infra/clickhouse
`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newRootCmd(strings.NewReader(""), &stdout, &stderr, time.Now)
	cmd.SetArgs([]string{"schedule", "--inventory", inventoryPath, "--format", "crontab"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "# chainwatch nullbot observe schedules") {
		t.Fatalf("expected crontab header, got:\n%s", out)
	}
	if !strings.Contains(out, "operational-check") {
		t.Fatalf("expected operational-check in output, got:\n%s", out)
	}
	if !strings.Contains(out, "nullbot observe") {
		t.Fatalf("expected nullbot observe command, got:\n%s", out)
	}
}

func TestScheduleCommandSystemd(t *testing.T) {
	inventoryPath := writeInventoryFile(t, `
clickhouse:
  clusters:
    - name: prod
      hosts: [ch-01]
      config_repo: infra/clickhouse
`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newRootCmd(strings.NewReader(""), &stdout, &stderr, time.Now)
	cmd.SetArgs([]string{"schedule", "--inventory", inventoryPath, "--format", "systemd"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "[Timer]") {
		t.Fatalf("expected [Timer] section, got:\n%s", out)
	}
	if !strings.Contains(out, "[Service]") {
		t.Fatalf("expected [Service] section, got:\n%s", out)
	}
	if !strings.Contains(out, "nullbot-operational-check") {
		t.Fatalf("expected unit name in output, got:\n%s", out)
	}
}

func TestScheduleCommandEventBridge(t *testing.T) {
	inventoryPath := writeInventoryFile(t, `
clickhouse:
  clusters:
    - name: prod
      hosts: [ch-01]
      config_repo: infra/clickhouse
`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newRootCmd(strings.NewReader(""), &stdout, &stderr, time.Now)
	cmd.SetArgs([]string{"schedule", "--inventory", inventoryPath, "--format", "eventbridge"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "nullbot-operational-check") {
		t.Fatalf("expected rule name in JSON, got:\n%s", out)
	}
	if !strings.Contains(out, "schedule_expression") {
		t.Fatalf("expected schedule_expression in JSON, got:\n%s", out)
	}
	if !strings.Contains(out, "cron(") {
		t.Fatalf("expected cron expression in output, got:\n%s", out)
	}
}

func TestScheduleCommandInvalidFormat(t *testing.T) {
	inventoryPath := writeInventoryFile(t, `
clickhouse:
  clusters:
    - name: prod
      hosts: [ch-01]
      config_repo: infra/clickhouse
`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newRootCmd(strings.NewReader(""), &stdout, &stderr, time.Now)
	cmd.SetArgs([]string{"schedule", "--inventory", inventoryPath, "--format", "invalid"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Fatalf("unexpected error: %v", err)
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

func writeFakeChainwatch(t *testing.T) (string, string) {
	t.Helper()

	dir := t.TempDir()
	outputPath := filepath.Join(dir, "fake-output.txt")
	binPath := filepath.Join(dir, "chainwatch")
	script := fmt.Sprintf("#!/bin/sh\ncat %q\n", outputPath)
	if err := os.WriteFile(binPath, []byte(script), 0700); err != nil {
		t.Fatalf("write fake chainwatch: %v", err)
	}
	return binPath, outputPath
}

func TestMetricsCommandTextFormat(t *testing.T) {
	dir := t.TempDir()
	lcDB := filepath.Join(dir, "lifecycle.db")

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seedLifecycle(t, lcDB, []orchestratorpkg.LifecycleTransition{
		{WOID: "WO-001", ToState: "finding", TransitionedAt: base},
		{WOID: "WO-001", ToState: "wo", TransitionedAt: base.Add(1 * time.Hour)},
		{WOID: "WO-001", ToState: "dispatched", TransitionedAt: base.Add(2 * time.Hour)},
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newRootCmd(strings.NewReader(""), &stdout, &stderr, func() time.Time {
		return base.Add(30 * time.Hour)
	})
	cmd.SetArgs([]string{"metrics", "--lifecycle", lcDB, "--format", "text"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Pipeline") {
		t.Errorf("expected Pipeline header in output, got:\n%s", out)
	}
	if !strings.Contains(out, "total WOs:  1") {
		t.Errorf("expected total WOs in output, got:\n%s", out)
	}
}

func TestMetricsCommandJSONFormat(t *testing.T) {
	dir := t.TempDir()
	lcDB := filepath.Join(dir, "lifecycle.db")

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seedLifecycle(t, lcDB, []orchestratorpkg.LifecycleTransition{
		{WOID: "WO-001", ToState: "finding", TransitionedAt: base},
		{WOID: "WO-001", ToState: "wo", TransitionedAt: base.Add(1 * time.Hour)},
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newRootCmd(strings.NewReader(""), &stdout, &stderr, func() time.Time {
		return base.Add(30 * time.Hour)
	})
	cmd.SetArgs([]string{"metrics", "--lifecycle", lcDB, "--format", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, `"total_wos"`) {
		t.Errorf("expected JSON total_wos key in output, got:\n%s", out)
	}
	if !strings.Contains(out, `"findings"`) {
		t.Errorf("expected JSON findings key in output, got:\n%s", out)
	}
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
