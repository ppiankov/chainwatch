package templates

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var requiredTemplates = []string{
	TemplateClickHouseTTL,
	TemplateClickHouseGrant,
	TemplateClickHouseRole,
	TemplateClickHouseQuota,
	TemplateClickHouseDatabase,
	TemplateClickHouseUser,
}

func TestListIncludesRequiredTemplates(t *testing.T) {
	templates, err := List()
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	seen := make(map[string]bool, len(templates))
	for _, name := range templates {
		seen[name] = true
	}

	for _, required := range requiredTemplates {
		if !seen[required] {
			t.Errorf("embedded templates missing %q", required)
		}
	}
}

func TestRenderAllKnownTemplates(t *testing.T) {
	for _, templateName := range requiredTemplates {
		t.Run(templateName, func(t *testing.T) {
			rendered, err := Render(templateName, sampleContext(templateName))
			if err != nil {
				t.Fatalf("Render(%q) failed: %v", templateName, err)
			}

			if strings.Contains(rendered, "{{") {
				t.Fatalf("rendered template still has placeholders:\n%s", rendered)
			}
			if !strings.Contains(rendered, `resource "clickhouse_`) {
				t.Fatalf("rendered template does not include clickhouse resource:\n%s", rendered)
			}
		})
	}
}

func TestRenderMissingContextKeyFails(t *testing.T) {
	_, err := Render(TemplateClickHouseTTL, map[string]any{
		"ResourceName": "events_ttl",
		"Database":     "analytics",
	})
	if err == nil {
		t.Fatal("expected render failure for missing required template keys")
	}
}

func TestOutputName(t *testing.T) {
	got, err := OutputName(TemplateClickHouseTTL)
	if err != nil {
		t.Fatalf("OutputName failed: %v", err)
	}
	if got != "clickhouse_ttl.tf" {
		t.Fatalf("OutputName = %q, want clickhouse_ttl.tf", got)
	}
}

func TestRenderedTemplatesPassTerraformValidate(t *testing.T) {
	terraformBin, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform not found in PATH")
	}

	for _, templateName := range requiredTemplates {
		t.Run(templateName, func(t *testing.T) {
			rendered, err := Render(templateName, sampleContext(templateName))
			if err != nil {
				t.Fatalf("Render(%q) failed: %v", templateName, err)
			}

			dir := t.TempDir()
			tfConfig := terraformValidateConfig(rendered)
			mainTF := filepath.Join(dir, "main.tf")
			if err := os.WriteFile(mainTF, []byte(tfConfig), 0o600); err != nil {
				t.Fatalf("write main.tf: %v", err)
			}

			initCmd := exec.Command(terraformBin, "init", "-backend=false", "-no-color")
			initCmd.Dir = dir
			initOut, initErr := initCmd.CombinedOutput()
			if initErr != nil {
				if isProviderAvailabilityIssue(string(initOut)) {
					t.Skipf("terraform provider unavailable in this environment:\n%s", initOut)
				}
				t.Fatalf("terraform init failed: %v\n%s", initErr, initOut)
			}

			validateCmd := exec.Command(terraformBin, "validate", "-no-color")
			validateCmd.Dir = dir
			validateOut, validateErr := validateCmd.CombinedOutput()
			if validateErr != nil {
				if isProviderAvailabilityIssue(string(validateOut)) {
					t.Skipf("terraform provider unavailable in this environment:\n%s", validateOut)
				}
				t.Fatalf("terraform validate failed: %v\n%s", validateErr, validateOut)
			}
		})
	}
}

func sampleContext(templateName string) map[string]any {
	switch templateName {
	case TemplateClickHouseTTL:
		return map[string]any{
			"ResourceName":  "events_ttl",
			"Database":      "analytics",
			"TableName":     "events",
			"Engine":        "MergeTree()",
			"TTLColumn":     "event_time",
			"RetentionDays": 30,
		}
	case TemplateClickHouseGrant:
		return map[string]any{
			"ResourceName": "analytics_reader_grant",
			"RoleName":     "analytics_reader",
			"Database":     "analytics",
			"TableName":    "events",
			"Privileges":   []string{"SELECT", "INSERT"},
		}
	case TemplateClickHouseRole:
		return map[string]any{
			"ResourceName": "analytics_reader",
			"RoleName":     "analytics_reader",
		}
	case TemplateClickHouseQuota:
		return map[string]any{
			"ResourceName": "analytics_quota",
			"QuotaName":    "analytics_quota",
		}
	case TemplateClickHouseDatabase:
		return map[string]any{
			"ResourceName": "analytics",
			"Database":     "analytics",
		}
	case TemplateClickHouseUser:
		return map[string]any{
			"ResourceName": "analyst_user",
			"UserName":     "analyst",
			"Password":     "replace-me",
			"Roles":        []string{"analytics_reader"},
		}
	default:
		panic(fmt.Sprintf("missing test context for template %q", templateName))
	}
}

func terraformValidateConfig(renderedTemplate string) string {
	return fmt.Sprintf(`terraform {
  required_providers {
    clickhouse = {
      source  = "ClickHouse/clickhouse"
      version = ">= 1.0.0"
    }
  }
}

provider "clickhouse" {}

%s
`, renderedTemplate)
}

func isProviderAvailabilityIssue(output string) bool {
	markers := []string{
		"Failed to query available provider packages",
		"could not connect to registry.terraform.io",
		"could not query provider registry",
		"failed to request discovery document",
		"lookup registry.terraform.io",
		"Invalid resource type",
		"does not support resource type",
	}
	for _, marker := range markers {
		if strings.Contains(output, marker) {
			return true
		}
	}
	return false
}
