package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ppiankov/chainwatch/internal/inventory"
	"github.com/ppiankov/chainwatch/internal/observe"
	"github.com/spf13/cobra"
)

func TestResolveRunbookTypesInventoryDefault(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("type", "linux", "")

	types := resolveRunbookTypes(cmd, "", "linux", true)
	if len(types) != 1 || types[0] != "clickhouse" {
		t.Fatalf("runbook types = %v, want [clickhouse]", types)
	}

	if err := cmd.Flags().Set("type", "nginx"); err != nil {
		t.Fatalf("set type flag: %v", err)
	}
	types = resolveRunbookTypes(cmd, "", "nginx", true)
	if len(types) != 1 || types[0] != "nginx" {
		t.Fatalf("runbook types = %v, want [nginx]", types)
	}
}

func TestRunObserveWithInventoryIteratesAllHosts(t *testing.T) {
	dir := t.TempDir()
	chainwatchPath := filepath.Join(dir, "chainwatch")
	writeExecutable(
		t,
		chainwatchPath,
		"#!/bin/sh\n"+
			"echo ok\n"+
			"exit 0\n",
	)

	inv, err := inventory.Parse([]byte(`
clickhouse:
  clusters:
    - name: dev-analytics
      hosts: [ch-dev-01, ch-dev-02]
      config_repo: infra/clickhouse-dev-analytics
    - name: dev-events
      hosts: [ch-dev-03]
      config_repo: infra/clickhouse-dev-events
`), dir)
	if err != nil {
		t.Fatalf("parse inventory: %v", err)
	}

	result, err := runObserveWithInventory(observe.RunnerConfig{
		Scope:      "/tmp",
		Type:       "linux",
		Types:      []string{"linux"},
		Chainwatch: chainwatchPath,
		AuditLog:   filepath.Join(dir, "audit.jsonl"),
	}, []string{"linux"}, inv)
	if err != nil {
		t.Fatalf("runObserveWithInventory returned error: %v", err)
	}

	hosts := 3
	expected := len(observe.GetRunbook("linux").Steps) * hosts
	if len(result.Steps) != expected {
		t.Fatalf("steps count = %d, want %d", len(result.Steps), expected)
	}

	clusterHostPairs := map[string]bool{
		"dev-analytics/ch-dev-01": false,
		"dev-analytics/ch-dev-02": false,
		"dev-events/ch-dev-03":    false,
	}
	for _, step := range result.Steps {
		pair := step.Cluster + "/" + step.Host
		if _, ok := clusterHostPairs[pair]; !ok {
			t.Fatalf("unexpected cluster/host pair in step: %q", pair)
		}
		clusterHostPairs[pair] = true
	}
	for pair, seen := range clusterHostPairs {
		if !seen {
			t.Fatalf("expected step records for %s", pair)
		}
	}
}

func TestRunnerConfigForHostResolvesConfigRepo(t *testing.T) {
	dir := t.TempDir()

	inv, err := inventory.Parse([]byte(`
clickhouse:
  clusters:
    - name: dev-analytics
      hosts: [ch-dev-01]
      config_repo: infra/clickhouse-dev-analytics
      config_path: config/users.d/
`), dir)
	if err != nil {
		t.Fatalf("parse inventory: %v", err)
	}

	cluster := inv.Clusters()[0]
	host := cluster.Hosts()[0]
	cfg := runnerConfigForHost(observe.RunnerConfig{
		Scope: "/var/lib/clickhouse",
		Params: map[string]string{
			"QUERY": "alice@example.com",
		},
	}, cluster, host)

	expectedRepo := filepath.Join(dir, "infra", "clickhouse-dev-analytics")
	if cfg.ConfigRepo != expectedRepo {
		t.Fatalf("ConfigRepo = %q, want %q", cfg.ConfigRepo, expectedRepo)
	}
	expectedConfigPath := filepath.Join(expectedRepo, "config", "users.d")
	if cfg.ConfigPath != expectedConfigPath {
		t.Fatalf("ConfigPath = %q, want %q", cfg.ConfigPath, expectedConfigPath)
	}
	if cfg.Params["QUERY"] != "alice@example.com" {
		t.Fatalf("QUERY param should be preserved, got %q", cfg.Params["QUERY"])
	}
	if cfg.Params["HOST"] != "ch-dev-01" {
		t.Fatalf("HOST param = %q, want ch-dev-01", cfg.Params["HOST"])
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}
