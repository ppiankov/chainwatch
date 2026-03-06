package observe

import (
	"fmt"
	"strings"

	observetemplates "github.com/ppiankov/chainwatch/internal/observe/templates"
)

const (
	FindingClickHouseMissingTTL      = "clickhouse_missing_ttl"
	FindingClickHouseMissingGrant    = "clickhouse_missing_grant"
	FindingClickHouseMissingRole     = "clickhouse_missing_role"
	FindingClickHouseMissingQuota    = "clickhouse_missing_quota"
	FindingClickHouseMissingDatabase = "clickhouse_missing_database"
	FindingClickHouseMissingUser     = "clickhouse_missing_user"
)

var terraformTemplateRoutes = map[string]string{
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

// TerraformTemplateForFinding returns the embedded Terraform template file for a finding type.
func TerraformTemplateForFinding(findingType string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(findingType))
	if key == "" {
		return "", fmt.Errorf("finding type is required")
	}

	templateName, ok := terraformTemplateRoutes[key]
	if !ok {
		return "", fmt.Errorf("no terraform template route for finding type %q", findingType)
	}
	if !observetemplates.IsKnownTemplate(templateName) {
		return "", fmt.Errorf("finding route %q points to unknown template %q", findingType, templateName)
	}
	return templateName, nil
}

// RenderTerraformForFinding renders the .tf body for a finding and returns output filename + content.
func RenderTerraformForFinding(findingType string, findingContext map[string]any) (string, string, error) {
	templateName, err := TerraformTemplateForFinding(findingType)
	if err != nil {
		return "", "", err
	}

	rendered, err := observetemplates.Render(templateName, findingContext)
	if err != nil {
		return "", "", err
	}

	outputName, err := observetemplates.OutputName(templateName)
	if err != nil {
		return "", "", err
	}
	return outputName, rendered, nil
}
