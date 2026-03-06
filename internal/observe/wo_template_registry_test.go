package observe

import (
	"strings"
	"testing"

	"github.com/ppiankov/chainwatch/internal/wo"
)

func TestLoadWOTemplateRegistryIncludesClickHouseTemplates(t *testing.T) {
	registry, err := LoadWOTemplateRegistry()
	if err != nil {
		t.Fatalf("LoadWOTemplateRegistry failed: %v", err)
	}

	templates := registry.Templates()
	if len(templates) < 4 {
		t.Fatalf("templates = %d, want at least 4", len(templates))
	}

	required := map[string]bool{
		"clickhouse_missing_ttl":     false,
		"clickhouse_replication_lag": false,
		"clickhouse_slow_queries":    false,
		"clickhouse_merge_pressure":  false,
	}
	for _, tpl := range templates {
		if _, ok := required[tpl.Name]; ok {
			required[tpl.Name] = true
		}
	}
	for name, found := range required {
		if !found {
			t.Fatalf("missing embedded WO template %q", name)
		}
	}
}

func TestWOTemplateRegistryMatchByTrigger(t *testing.T) {
	registry, err := LoadWOTemplateRegistry()
	if err != nil {
		t.Fatalf("LoadWOTemplateRegistry failed: %v", err)
	}

	finding := wo.Observation{
		Type:     wo.ConfigModified,
		Severity: wo.SeverityHigh,
		Detail:   "analytics.events table is missing TTL policy",
	}
	match := registry.Match(finding, "clickhouse")
	if match == nil {
		t.Fatal("expected a template match")
	}
	if match.Name != "clickhouse_missing_ttl" {
		t.Fatalf("matched template = %q, want clickhouse_missing_ttl", match.Name)
	}
}

func TestBuildWOTemplateContextAndRender(t *testing.T) {
	context := BuildWOTemplateContext(
		"dev-analytics",
		"clickhouse",
		wo.Observation{
			Type:     wo.ProcessAnomaly,
			Severity: wo.SeverityMedium,
			Detail:   "slow queries in query_log",
			Data: map[string]any{
				"database": "analytics",
			},
		},
	)

	got, err := RenderWOTemplateText(
		"Investigate {{.FindingType}} for {{.database}} on {{.Scope}}",
		context,
	)
	if err != nil {
		t.Fatalf("RenderWOTemplateText failed: %v", err)
	}
	if got != "Investigate process_anomaly for analytics on dev-analytics" {
		t.Fatalf("rendered text = %q", got)
	}
}

func TestWOTemplateRegistryRunbookScoped(t *testing.T) {
	registry, err := LoadWOTemplateRegistry()
	if err != nil {
		t.Fatalf("LoadWOTemplateRegistry failed: %v", err)
	}

	finding := wo.Observation{
		Type:   wo.ProcessAnomaly,
		Detail: "replication queue depth is high",
	}
	match := registry.Match(finding, "linux")
	if match != nil && strings.HasPrefix(match.Name, "clickhouse_") {
		t.Fatalf("unexpected clickhouse template for linux runbook: %q", match.Name)
	}
}
