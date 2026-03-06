package observe

import (
	"strings"
	"testing"

	observetemplates "github.com/ppiankov/chainwatch/internal/observe/templates"
)

func TestTerraformTemplateForFindingRoutes(t *testing.T) {
	tests := map[string]string{
		FindingClickHouseMissingTTL:      observetemplates.TemplateClickHouseTTL,
		"clickhouse_ttl":                 observetemplates.TemplateClickHouseTTL,
		FindingClickHouseMissingGrant:    observetemplates.TemplateClickHouseGrant,
		"clickhouse_grant":               observetemplates.TemplateClickHouseGrant,
		FindingClickHouseMissingRole:     observetemplates.TemplateClickHouseRole,
		"clickhouse_role":                observetemplates.TemplateClickHouseRole,
		FindingClickHouseMissingQuota:    observetemplates.TemplateClickHouseQuota,
		"clickhouse_quota":               observetemplates.TemplateClickHouseQuota,
		FindingClickHouseMissingDatabase: observetemplates.TemplateClickHouseDatabase,
		"clickhouse_database":            observetemplates.TemplateClickHouseDatabase,
		FindingClickHouseMissingUser:     observetemplates.TemplateClickHouseUser,
		"clickhouse_user":                observetemplates.TemplateClickHouseUser,
	}

	for findingType, wantTemplate := range tests {
		gotTemplate, err := TerraformTemplateForFinding(findingType)
		if err != nil {
			t.Fatalf("TerraformTemplateForFinding(%q) failed: %v", findingType, err)
		}
		if gotTemplate != wantTemplate {
			t.Fatalf("TerraformTemplateForFinding(%q) = %q, want %q", findingType, gotTemplate, wantTemplate)
		}
	}
}

func TestTerraformTemplateForFindingUnknown(t *testing.T) {
	_, err := TerraformTemplateForFinding("clickhouse_replication_lag")
	if err == nil {
		t.Fatal("expected routing error for unknown finding type")
	}
}

func TestRenderTerraformForFinding(t *testing.T) {
	outputName, rendered, err := RenderTerraformForFinding(FindingClickHouseMissingTTL, map[string]any{
		"ResourceName":  "events_ttl",
		"Database":      "analytics",
		"TableName":     "events",
		"Engine":        "MergeTree()",
		"TTLColumn":     "event_time",
		"RetentionDays": 30,
	})
	if err != nil {
		t.Fatalf("RenderTerraformForFinding failed: %v", err)
	}

	if outputName != "clickhouse_ttl.tf" {
		t.Fatalf("outputName = %q, want clickhouse_ttl.tf", outputName)
	}
	if !strings.Contains(rendered, `resource "clickhouse_table"`) {
		t.Fatalf("rendered output missing clickhouse_table resource:\n%s", rendered)
	}
	if strings.Contains(rendered, "{{") {
		t.Fatalf("rendered output still contains template placeholders:\n%s", rendered)
	}
}

func TestRenderTerraformForFindingMissingContextKey(t *testing.T) {
	_, _, err := RenderTerraformForFinding(FindingClickHouseMissingUser, map[string]any{
		"ResourceName": "analyst_user",
		"UserName":     "analyst",
	})
	if err == nil {
		t.Fatal("expected render error for missing context keys")
	}
}
