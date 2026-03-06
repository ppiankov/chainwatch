package templates

import (
	"bytes"
	"embed"
	"fmt"
	"sort"
	"strings"
	"text/template"
)

const (
	TemplateClickHouseTTL      = "clickhouse_ttl.tf.tmpl"
	TemplateClickHouseGrant    = "clickhouse_grant.tf.tmpl"
	TemplateClickHouseRole     = "clickhouse_role.tf.tmpl"
	TemplateClickHouseQuota    = "clickhouse_quota.tf.tmpl"
	TemplateClickHouseDatabase = "clickhouse_database.tf.tmpl"
	TemplateClickHouseUser     = "clickhouse_user.tf.tmpl"
)

var knownTemplates = map[string]struct{}{
	TemplateClickHouseTTL:      {},
	TemplateClickHouseGrant:    {},
	TemplateClickHouseRole:     {},
	TemplateClickHouseQuota:    {},
	TemplateClickHouseDatabase: {},
	TemplateClickHouseUser:     {},
}

//go:embed *.tf.tmpl
var embeddedFS embed.FS

// List returns all embedded Terraform template names sorted lexicographically.
func List() ([]string, error) {
	entries, err := embeddedFS.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read embedded templates: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tf.tmpl") {
			continue
		}
		names = append(names, entry.Name())
	}

	sort.Strings(names)
	return names, nil
}

// IsKnownTemplate reports whether name is one of the built-in template files.
func IsKnownTemplate(name string) bool {
	_, ok := knownTemplates[name]
	return ok
}

// OutputName converts an embedded template filename to the generated .tf output name.
func OutputName(templateName string) (string, error) {
	if !strings.HasSuffix(templateName, ".tf.tmpl") {
		return "", fmt.Errorf("template %q must end with .tf.tmpl", templateName)
	}
	return strings.TrimSuffix(templateName, ".tmpl"), nil
}

// Render executes a template with the provided finding context.
func Render(templateName string, findingContext map[string]any) (string, error) {
	if !IsKnownTemplate(templateName) {
		return "", fmt.Errorf("unknown terraform template %q", templateName)
	}

	tpl, err := template.New(templateName).
		Option("missingkey=error").
		ParseFS(embeddedFS, templateName)
	if err != nil {
		return "", fmt.Errorf("parse terraform template %q: %w", templateName, err)
	}

	var out bytes.Buffer
	if err := tpl.Execute(&out, findingContext); err != nil {
		return "", fmt.Errorf("render terraform template %q: %w", templateName, err)
	}

	return out.String(), nil
}
