package observe

import (
	"bytes"
	"embed"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/ppiankov/chainwatch/internal/wo"
	"gopkg.in/yaml.v3"
)

const (
	RemediationTypeManual    = "manual"
	RemediationTypeConfig    = "config"
	RemediationTypeTerraform = "terraform"
	RemediationTypeK8s       = "k8s"
	RemediationTypeBoth      = "both"
)

var allowedRemediationTypes = map[string]struct{}{
	RemediationTypeManual:    {},
	RemediationTypeConfig:    {},
	RemediationTypeTerraform: {},
	RemediationTypeK8s:       {},
	RemediationTypeBoth:      {},
}

// WOTemplate describes how one finding pattern becomes a work order.
type WOTemplate struct {
	Name                 string         `yaml:"name"`
	Runbooks             []string       `yaml:"runbooks,omitempty"`
	FindingTypes         []string       `yaml:"finding_types,omitempty"`
	Triggers             []string       `yaml:"triggers,omitempty"`
	Severity             wo.Severity    `yaml:"severity,omitempty"`
	RemediationType      string         `yaml:"remediation_type"`
	TitleTemplate        string         `yaml:"title"`
	DescriptionTemplate  string         `yaml:"description"`
	TerraformFindingType string         `yaml:"terraform_finding_type,omitempty"`
	TerraformContext     map[string]any `yaml:"terraform_context,omitempty"`
}

// WOTemplateRegistry holds embedded template entries and resolves best matches.
type WOTemplateRegistry struct {
	templates []WOTemplate
}

//go:embed wo_templates/*.yaml
var woTemplateFS embed.FS

// LoadWOTemplateRegistry loads and validates all embedded WO templates.
func LoadWOTemplateRegistry() (*WOTemplateRegistry, error) {
	entries, err := woTemplateFS.ReadDir("wo_templates")
	if err != nil {
		return nil, fmt.Errorf("read embedded WO templates: %w", err)
	}

	templates := make([]WOTemplate, 0, len(entries))
	seenNames := make(map[string]struct{}, len(entries))

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := "wo_templates/" + entry.Name()
		data, err := woTemplateFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read embedded WO template %s: %w", path, err)
		}

		var tpl WOTemplate
		if err := yaml.Unmarshal(data, &tpl); err != nil {
			return nil, fmt.Errorf("parse WO template %s: %w", path, err)
		}
		if err := normalizeAndValidateWOTemplate(&tpl); err != nil {
			return nil, fmt.Errorf("invalid WO template %s: %w", path, err)
		}
		if _, exists := seenNames[tpl.Name]; exists {
			return nil, fmt.Errorf("duplicate WO template name %q", tpl.Name)
		}
		seenNames[tpl.Name] = struct{}{}
		templates = append(templates, tpl)
	}

	sort.Slice(templates, func(i, j int) bool {
		return templates[i].Name < templates[j].Name
	})
	return &WOTemplateRegistry{templates: templates}, nil
}

// Templates returns a copy of registered template definitions.
func (r *WOTemplateRegistry) Templates() []WOTemplate {
	if r == nil {
		return nil
	}
	out := make([]WOTemplate, len(r.templates))
	copy(out, r.templates)
	return out
}

// Match returns the highest-confidence WO template for an observation/runbook pair.
func (r *WOTemplateRegistry) Match(observation wo.Observation, runbook string) *WOTemplate {
	if r == nil || len(r.templates) == 0 {
		return nil
	}

	activeRunbooks := tokenizeCSVLower(runbook)
	bestIndex := -1
	bestScore := -1
	for i := range r.templates {
		score := r.templates[i].matchScore(observation, activeRunbooks)
		if score < 0 {
			continue
		}
		if score > bestScore {
			bestScore = score
			bestIndex = i
			continue
		}
		if score == bestScore && bestIndex >= 0 && r.templates[i].Name < r.templates[bestIndex].Name {
			bestIndex = i
		}
	}

	if bestIndex < 0 {
		return nil
	}
	return &r.templates[bestIndex]
}

// BuildWOTemplateContext builds the default render context for title/description templates.
func BuildWOTemplateContext(scope, runbook string, observation wo.Observation) map[string]any {
	context := map[string]any{
		"Scope":       strings.TrimSpace(scope),
		"Runbook":     strings.TrimSpace(runbook),
		"FindingType": strings.TrimSpace(string(observation.Type)),
		"Severity":    strings.TrimSpace(string(observation.Severity)),
		"Detail":      strings.TrimSpace(observation.Detail),
	}

	data := make(map[string]any, len(observation.Data))
	for k, v := range observation.Data {
		data[k] = v
		context[k] = v
	}
	context["Data"] = data
	return context
}

// RenderWOTemplateText renders one title/description template string.
func RenderWOTemplateText(raw string, context map[string]any) (string, error) {
	tpl, err := template.New("wo-template").
		Option("missingkey=error").
		Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var out bytes.Buffer
	if err := tpl.Execute(&out, context); err != nil {
		return "", fmt.Errorf("render template: %w", err)
	}
	return strings.TrimSpace(out.String()), nil
}

func normalizeAndValidateWOTemplate(tpl *WOTemplate) error {
	if tpl == nil {
		return fmt.Errorf("template is nil")
	}

	tpl.Name = strings.ToLower(strings.TrimSpace(tpl.Name))
	if tpl.Name == "" {
		return fmt.Errorf("name is required")
	}

	tpl.RemediationType = normalizeRemediationType(tpl.RemediationType)
	if tpl.RemediationType == "" {
		return fmt.Errorf("remediation_type is required")
	}

	tpl.TitleTemplate = strings.TrimSpace(tpl.TitleTemplate)
	if tpl.TitleTemplate == "" {
		return fmt.Errorf("title is required")
	}

	tpl.DescriptionTemplate = strings.TrimSpace(tpl.DescriptionTemplate)
	if tpl.DescriptionTemplate == "" {
		return fmt.Errorf("description is required")
	}

	tpl.FindingTypes = normalizeStringList(tpl.FindingTypes)
	tpl.Runbooks = normalizeStringList(tpl.Runbooks)
	tpl.Triggers = normalizeStringList(tpl.Triggers)
	if len(tpl.FindingTypes) == 0 && len(tpl.Triggers) == 0 {
		return fmt.Errorf("at least one of finding_types or triggers is required")
	}

	if tpl.Severity != "" && !wo.IsValidSeverity(tpl.Severity) {
		return fmt.Errorf("severity %q is not valid", tpl.Severity)
	}

	tpl.TerraformFindingType = strings.TrimSpace(tpl.TerraformFindingType)
	if tpl.TerraformFindingType != "" {
		if tpl.RemediationType != RemediationTypeTerraform &&
			tpl.RemediationType != RemediationTypeBoth {
			return fmt.Errorf("terraform_finding_type requires remediation_type terraform or both")
		}
		if _, err := TerraformTemplateForFinding(tpl.TerraformFindingType); err != nil {
			return fmt.Errorf("terraform_finding_type: %w", err)
		}
	}
	if tpl.TerraformContext == nil {
		tpl.TerraformContext = map[string]any{}
	}
	return nil
}

func normalizeRemediationType(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if _, ok := allowedRemediationTypes[normalized]; !ok {
		return ""
	}
	return normalized
}

func normalizeStringList(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, entry := range raw {
		normalized := strings.ToLower(strings.TrimSpace(entry))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func tokenizeCSVLower(raw string) map[string]struct{} {
	tokens := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		normalized := strings.ToLower(strings.TrimSpace(item))
		if normalized == "" {
			continue
		}
		tokens[normalized] = struct{}{}
	}
	return tokens
}

func (tpl WOTemplate) matchScore(
	observation wo.Observation,
	activeRunbooks map[string]struct{},
) int {
	if len(tpl.Runbooks) > 0 {
		match := false
		for _, candidate := range tpl.Runbooks {
			if _, ok := activeRunbooks[candidate]; ok {
				match = true
				break
			}
		}
		if !match {
			return -1
		}
	}

	findingType := strings.ToLower(strings.TrimSpace(string(observation.Type)))
	detail := strings.ToLower(strings.TrimSpace(observation.Detail))

	typeMatch := len(tpl.FindingTypes) == 0
	if !typeMatch {
		for _, candidate := range tpl.FindingTypes {
			if candidate == findingType {
				typeMatch = true
				break
			}
		}
	}

	triggerMatch := len(tpl.Triggers) == 0
	if !triggerMatch {
		for _, trigger := range tpl.Triggers {
			if strings.Contains(detail, trigger) {
				triggerMatch = true
				break
			}
		}
	}

	// At least one selector must match. When both are defined, either can match.
	if len(tpl.FindingTypes) > 0 && len(tpl.Triggers) > 0 && !typeMatch && !triggerMatch {
		return -1
	}
	if len(tpl.FindingTypes) > 0 && len(tpl.Triggers) == 0 && !typeMatch {
		return -1
	}
	if len(tpl.Triggers) > 0 && len(tpl.FindingTypes) == 0 && !triggerMatch {
		return -1
	}

	score := 0
	if typeMatch {
		score += 2
	}
	if triggerMatch {
		score += 1
	}
	if len(tpl.Runbooks) > 0 {
		score++
	}
	return score
}
