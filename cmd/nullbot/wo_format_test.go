package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/chainwatch/internal/observe"
	"github.com/ppiankov/chainwatch/internal/wo"
)

func TestBuildWOTasksOutputsWOShapeAndTerraformStub(t *testing.T) {
	finding := wo.Observation{
		Type:     wo.ConfigModified,
		Severity: wo.SeverityHigh,
		Detail:   "analytics.events table is missing TTL policy",
		Data: map[string]any{
			"database":       "analytics",
			"table":          "events",
			"ttl_column":     "event_time",
			"retention_days": 45,
		},
	}

	result, err := buildWOTasks([]wo.Observation{finding}, woTaskBuildConfig{
		Scope:        "dev-analytics",
		Runbook:      "clickhouse",
		DisableDedup: true,
	})
	if err != nil {
		t.Fatalf("buildWOTasks failed: %v", err)
	}
	if len(result.Payload.Tasks) != 1 {
		t.Fatalf("tasks = %d, want 1", len(result.Payload.Tasks))
	}

	task := result.Payload.Tasks[0]
	if task.ID == "" {
		t.Fatal("id is required")
	}
	if task.Repo == "" {
		t.Fatal("repo is required")
	}
	if task.Title == "" {
		t.Fatal("title is required")
	}
	if task.Prompt == "" {
		t.Fatal("prompt is required")
	}
	if task.Priority != taskPriorityHigh {
		t.Fatalf("priority = %d, want %d", task.Priority, taskPriorityHigh)
	}
	if task.Difficulty != taskDifficultySimple {
		t.Fatalf("difficulty = %q, want %q", task.Difficulty, taskDifficultySimple)
	}
	if task.Metadata.Scope != "dev-analytics" {
		t.Fatalf("metadata.scope = %q, want dev-analytics", task.Metadata.Scope)
	}
	if task.Metadata.RemediationType != observe.RemediationTypeTerraform {
		t.Fatalf(
			"metadata.remediation_type = %q, want terraform",
			task.Metadata.RemediationType,
		)
	}
	if task.Metadata.FindingHash == "" {
		t.Fatal("metadata.finding_hash is required")
	}
	expectedHash, err := observe.ComputeObservationHash("dev-analytics", finding)
	if err != nil {
		t.Fatalf("ComputeObservationHash: %v", err)
	}
	if task.Metadata.FindingHash != expectedHash {
		t.Fatalf("finding_hash = %q, want %q", task.Metadata.FindingHash, expectedHash)
	}
	if !strings.Contains(task.Prompt, `resource "clickhouse_table"`) {
		t.Fatalf("prompt missing clickhouse resource:\n%s", task.Prompt)
	}
	if !strings.Contains(task.Prompt, "INTERVAL 45 DAY") {
		t.Fatalf("prompt missing retention days:\n%s", task.Prompt)
	}
}

func TestBuildWOTasksOutputsTokencontrolEnvelope(t *testing.T) {
	finding := wo.Observation{
		Type:     wo.UnknownFile,
		Severity: wo.SeverityLow,
		Detail:   "unknown binary in /usr/local/bin",
	}
	result, err := buildWOTasks([]wo.Observation{finding}, woTaskBuildConfig{
		Scope:        "/usr/local/bin",
		Runbook:      "linux",
		DisableDedup: true,
	})
	if err != nil {
		t.Fatalf("buildWOTasks failed: %v", err)
	}

	data, err := json.Marshal(result.Payload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded struct {
		Tasks []map[string]any `json:"tasks"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(decoded.Tasks) != 1 {
		t.Fatalf("tasks = %d, want 1", len(decoded.Tasks))
	}

	task := decoded.Tasks[0]
	for _, key := range []string{"id", "repo", "title", "prompt", "priority", "difficulty"} {
		if _, ok := task[key]; !ok {
			t.Fatalf("missing required task key %q", key)
		}
	}

	metadata, ok := task["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata missing or wrong type: %#v", task["metadata"])
	}
	findingHash, _ := metadata["finding_hash"].(string)
	if strings.TrimSpace(findingHash) == "" {
		t.Fatalf("metadata.finding_hash is required: %#v", metadata)
	}
}

func TestBuildWOTasksSuppressesDuplicateOpenFinding(t *testing.T) {
	cachePath := observe.CacheDir(t.TempDir())
	finding := wo.Observation{
		Type:     wo.ConfigModified,
		Severity: wo.SeverityHigh,
		Detail:   "events table is missing TTL policy",
	}
	cfg := woTaskBuildConfig{
		Scope:       "dev-analytics",
		Runbook:     "clickhouse",
		DedupDBPath: cachePath,
		DedupWindow: 24 * time.Hour,
		Now:         time.Date(2026, 3, 6, 13, 0, 0, 0, time.UTC),
	}

	first, err := buildWOTasks([]wo.Observation{finding}, cfg)
	if err != nil {
		t.Fatalf("buildWOTasks(first): %v", err)
	}
	if first.Emitted != 1 || first.Suppressed != 0 {
		t.Fatalf("first stats: emitted=%d suppressed=%d", first.Emitted, first.Suppressed)
	}
	if len(first.Payload.Tasks) != 1 {
		t.Fatalf("first tasks = %d, want 1", len(first.Payload.Tasks))
	}

	secondCfg := cfg
	secondCfg.Now = cfg.Now.Add(30 * time.Minute)
	second, err := buildWOTasks([]wo.Observation{finding}, secondCfg)
	if err != nil {
		t.Fatalf("buildWOTasks(second): %v", err)
	}
	if second.Emitted != 0 || second.Suppressed != 1 {
		t.Fatalf("second stats: emitted=%d suppressed=%d", second.Emitted, second.Suppressed)
	}
	if len(second.Payload.Tasks) != 0 {
		t.Fatalf("second tasks = %d, want 0", len(second.Payload.Tasks))
	}
}

func TestBuildWOTasksReopensClosedFindingAfterWindow(t *testing.T) {
	cachePath := observe.CacheDir(t.TempDir())
	finding := wo.Observation{
		Type:     wo.ProcessAnomaly,
		Severity: wo.SeverityHigh,
		Detail:   "replication queue depth indicates replication lag",
	}
	base := time.Date(2026, 3, 6, 10, 0, 0, 0, time.UTC)
	window := 24 * time.Hour
	cfg := woTaskBuildConfig{
		Scope:       "dev-analytics",
		Runbook:     "clickhouse",
		DedupDBPath: cachePath,
		DedupWindow: window,
		Now:         base,
	}

	initial, err := buildWOTasks([]wo.Observation{finding}, cfg)
	if err != nil {
		t.Fatalf("buildWOTasks(initial): %v", err)
	}
	if len(initial.Payload.Tasks) != 1 {
		t.Fatalf("initial tasks = %d, want 1", len(initial.Payload.Tasks))
	}

	findingHash, err := observe.ComputeObservationHash(cfg.Scope, finding)
	if err != nil {
		t.Fatalf("ComputeObservationHash: %v", err)
	}
	initialWOID := initial.Payload.Tasks[0].ID

	closedAt := base.Add(3 * time.Hour)
	if err := observe.UpdateFindingHashStatus(cachePath, findingHash, observe.FindingStatusClosed, closedAt); err != nil {
		t.Fatalf("UpdateFindingHashStatus(closed): %v", err)
	}

	flapCfg := cfg
	flapCfg.Now = closedAt.Add(2 * time.Hour)
	flap, err := buildWOTasks([]wo.Observation{finding}, flapCfg)
	if err != nil {
		t.Fatalf("buildWOTasks(flap): %v", err)
	}
	if flap.Emitted != 0 || flap.Suppressed != 1 {
		t.Fatalf("flap stats: emitted=%d suppressed=%d", flap.Emitted, flap.Suppressed)
	}

	reopenCfg := cfg
	reopenCfg.Now = closedAt.Add(30 * time.Hour)
	reopened, err := buildWOTasks([]wo.Observation{finding}, reopenCfg)
	if err != nil {
		t.Fatalf("buildWOTasks(reopened): %v", err)
	}
	if reopened.Emitted != 1 || reopened.Reopened != 1 {
		t.Fatalf("reopen stats: emitted=%d reopened=%d", reopened.Emitted, reopened.Reopened)
	}
	if len(reopened.Payload.Tasks) != 1 {
		t.Fatalf("reopened tasks = %d, want 1", len(reopened.Payload.Tasks))
	}
	if reopened.Payload.Tasks[0].ID != initialWOID {
		t.Fatalf("reopened id = %q, want %q", reopened.Payload.Tasks[0].ID, initialWOID)
	}
}

func TestBuildWOTasksNoDedupBypassesState(t *testing.T) {
	cachePath := observe.CacheDir(t.TempDir())
	finding := wo.Observation{
		Type:     wo.UnknownFile,
		Severity: wo.SeverityLow,
		Detail:   "unknown binary in /usr/local/bin",
	}
	cfg := woTaskBuildConfig{
		Scope:        "/usr/local/bin",
		Runbook:      "linux",
		DedupDBPath:  cachePath,
		DedupWindow:  24 * time.Hour,
		DisableDedup: true,
		Now:          time.Date(2026, 3, 6, 15, 0, 0, 0, time.UTC),
	}

	first, err := buildWOTasks([]wo.Observation{finding}, cfg)
	if err != nil {
		t.Fatalf("buildWOTasks(first): %v", err)
	}
	secondCfg := cfg
	secondCfg.Now = cfg.Now.Add(10 * time.Minute)
	second, err := buildWOTasks([]wo.Observation{finding}, secondCfg)
	if err != nil {
		t.Fatalf("buildWOTasks(second): %v", err)
	}

	if len(first.Payload.Tasks) != 1 || len(second.Payload.Tasks) != 1 {
		t.Fatalf("expected one task per run when --no-dedup is used")
	}

	hash, err := observe.ComputeObservationHash(cfg.Scope, finding)
	if err != nil {
		t.Fatalf("ComputeObservationHash: %v", err)
	}
	record, err := observe.ReadFindingHash(cachePath, hash)
	if err != nil {
		t.Fatalf("ReadFindingHash: %v", err)
	}
	if record != nil {
		t.Fatalf("expected no dedup state writes, found record: %+v", *record)
	}
}

func TestBuildWOTasksClickHouseTemplateCoverage(t *testing.T) {
	tests := []struct {
		name             string
		detail           string
		wantTitleSnippet string
	}{
		{
			name:             "replication lag",
			detail:           "replication queue depth indicates replication lag on replica-1",
			wantTitleSnippet: "replication lag",
		},
		{
			name:             "slow queries",
			detail:           "slow queries observed in query_log with high elapsed",
			wantTitleSnippet: "slow queries",
		},
		{
			name:             "merge pressure",
			detail:           "merge pressure detected due to too many parts and active merges",
			wantTitleSnippet: "merge pressure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := wo.Observation{
				Type:     wo.ProcessAnomaly,
				Severity: wo.SeverityMedium,
				Detail:   tt.detail,
			}
			result, err := buildWOTasks([]wo.Observation{finding}, woTaskBuildConfig{
				Scope:        "dev-analytics",
				Runbook:      "clickhouse",
				DisableDedup: true,
			})
			if err != nil {
				t.Fatalf("buildWOTasks: %v", err)
			}
			if len(result.Payload.Tasks) != 1 {
				t.Fatalf("tasks = %d, want 1", len(result.Payload.Tasks))
			}

			task := result.Payload.Tasks[0]
			if task.Metadata.RemediationType != observe.RemediationTypeConfig {
				t.Fatalf(
					"metadata.remediation_type = %q, want config",
					task.Metadata.RemediationType,
				)
			}
			if strings.Contains(task.Prompt, `resource "clickhouse_`) {
				t.Fatalf("prompt should not include terraform stub for %s template", tt.name)
			}
			if !strings.Contains(strings.ToLower(task.Title), tt.wantTitleSnippet) {
				t.Fatalf("title = %q, want snippet %q", task.Title, tt.wantTitleSnippet)
			}
		})
	}
}

func TestNormalizeObserveFormat(t *testing.T) {
	got, err := normalizeObserveFormat("WO")
	if err != nil {
		t.Fatalf("normalizeObserveFormat: %v", err)
	}
	if got != observeFormatWO {
		t.Fatalf("format = %q, want %q", got, observeFormatWO)
	}

	if _, err := normalizeObserveFormat("yaml"); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}
