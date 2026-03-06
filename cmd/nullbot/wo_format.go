package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ppiankov/chainwatch/internal/observe"
	"github.com/ppiankov/chainwatch/internal/wo"
)

const (
	observeFormatText      = "text"
	observeFormatWO        = "wo"
	defaultObserveStateDir = ".nullbot/state"

	defaultTaskRepo   = "."
	defaultTaskRunner = "codex"

	taskPriorityCritical = 1
	taskPriorityHigh     = 2
	taskPriorityMedium   = 3
	taskPriorityLow      = 4

	taskDifficultySimple = "simple"
)

var (
	defaultObserveDedupWindow    = 24 * time.Hour
	clickhouseTableRefPattern    = regexp.MustCompile(`([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)`)
	terraformIdentifierSanitizer = regexp.MustCompile(`[^0-9A-Za-z_]`)
)

type tokencontrolTaskFile struct {
	Tasks []tokencontrolTask `json:"tasks"`
}

type tokencontrolTask struct {
	ID           string               `json:"id"`
	Repo         string               `json:"repo"`
	Title        string               `json:"title"`
	Prompt       string               `json:"prompt"`
	Priority     int                  `json:"priority"`
	Difficulty   string               `json:"difficulty"`
	Runner       string               `json:"runner,omitempty"`
	Dependencies []string             `json:"dependencies,omitempty"`
	Metadata     tokencontrolTaskMeta `json:"metadata"`
}

type tokencontrolTaskMeta struct {
	Source          string `json:"source"`
	Runbook         string `json:"runbook"`
	FindingHash     string `json:"finding_hash"`
	Scope           string `json:"scope"`
	Severity        string `json:"severity,omitempty"`
	RemediationType string `json:"remediation_type,omitempty"`
}

type woTaskBuildConfig struct {
	Scope        string
	Runbook      string
	Repo         string
	DedupDBPath  string
	DedupWindow  time.Duration
	DisableDedup bool
	Now          time.Time
}

type woTaskBuildResult struct {
	Payload    tokencontrolTaskFile
	Emitted    int
	Suppressed int
	Reopened   int
}

func normalizeObserveFormat(raw string) (string, error) {
	format := strings.ToLower(strings.TrimSpace(raw))
	if format == "" {
		return observeFormatText, nil
	}

	switch format {
	case observeFormatText, observeFormatWO:
		return format, nil
	default:
		return "", fmt.Errorf("--format must be one of: %s, %s", observeFormatText, observeFormatWO)
	}
}

func resolveObserveStateDir() string {
	if stateDir := strings.TrimSpace(os.Getenv("NULLBOT_STATE_DIR")); stateDir != "" {
		return stateDir
	}

	home, err := os.UserHomeDir()
	if err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, defaultObserveStateDir)
	}
	return filepath.Join(os.TempDir(), "nullbot-state")
}

func buildWOTasks(observations []wo.Observation, cfg woTaskBuildConfig) (*woTaskBuildResult, error) {
	now := cfg.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	window := cfg.DedupWindow
	if window == 0 {
		window = defaultObserveDedupWindow
	}
	if window < 0 {
		window = 0
	}

	registry, err := observe.LoadWOTemplateRegistry()
	if err != nil {
		return nil, fmt.Errorf("load WO template registry: %w", err)
	}

	result := &woTaskBuildResult{
		Payload: tokencontrolTaskFile{
			Tasks: make([]tokencontrolTask, 0, len(observations)),
		},
	}
	idCounts := make(map[string]int)

	for _, finding := range observations {
		findingHash, err := observe.ComputeObservationHash(cfg.Scope, finding)
		if err != nil {
			return nil, fmt.Errorf("compute finding hash: %w", err)
		}

		baseWOID := stableWOIDFromHash(findingHash)
		woID := baseWOID

		if !cfg.DisableDedup {
			if strings.TrimSpace(cfg.DedupDBPath) == "" {
				return nil, fmt.Errorf("dedup db path is required when dedup is enabled")
			}

			decision, err := observe.ApplyFindingDedup(cfg.DedupDBPath, findingHash, baseWOID, now, window)
			if err != nil {
				return nil, fmt.Errorf("apply finding dedup: %w", err)
			}

			if decision.Action == observe.FindingDedupActionSuppress {
				result.Suppressed++
				continue
			}
			if decision.Action == observe.FindingDedupActionReopen {
				result.Reopened++
			}

			woID = strings.TrimSpace(decision.Record.WOID)
			if woID == "" {
				woID = baseWOID
			}
		}

		woID = uniqueTaskID(woID, idCounts)
		entry, err := buildWorkOrderEntry(woID, findingHash, finding, cfg, registry)
		if err != nil {
			return nil, err
		}

		result.Payload.Tasks = append(result.Payload.Tasks, entry)
		result.Emitted++
	}

	return result, nil
}

func buildWorkOrderEntry(
	woID string,
	findingHash string,
	finding wo.Observation,
	cfg woTaskBuildConfig,
	registry *observe.WOTemplateRegistry,
) (tokencontrolTask, error) {
	scope := strings.TrimSpace(cfg.Scope)
	template := registry.Match(finding, cfg.Runbook)

	title := defaultWOTitle(finding, scope)
	prompt := defaultWOPrompt(finding, cfg.Runbook, scope)
	severity := resolveWOSeverity(finding.Severity, "")
	remediationType := observe.RemediationTypeManual
	terraformStub := ""

	if template != nil {
		context := observe.BuildWOTemplateContext(scope, cfg.Runbook, finding)

		renderedTitle, err := observe.RenderWOTemplateText(template.TitleTemplate, context)
		if err != nil {
			return tokencontrolTask{}, fmt.Errorf("render WO title for %q: %w", template.Name, err)
		}
		renderedDescription, err := observe.RenderWOTemplateText(
			template.DescriptionTemplate,
			context,
		)
		if err != nil {
			return tokencontrolTask{}, fmt.Errorf("render WO description for %q: %w", template.Name, err)
		}

		title = renderedTitle
		prompt = renderedDescription
		severity = resolveWOSeverity(finding.Severity, string(template.Severity))
		remediationType = template.RemediationType

		stub, err := renderTerraformStub(*template, finding, scope)
		if err != nil {
			return tokencontrolTask{}, fmt.Errorf("render terraform stub for %q: %w", template.Name, err)
		}
		terraformStub = stub
	}

	prompt = buildTaskPrompt(prompt, terraformStub)
	if prompt == "" {
		prompt = title
	}

	return tokencontrolTask{
		ID:         strings.TrimSpace(woID),
		Repo:       normalizeTaskRepo(cfg.Repo),
		Title:      title,
		Prompt:     prompt,
		Priority:   resolveTaskPriority(severity),
		Difficulty: taskDifficultySimple,
		Runner:     defaultTaskRunner,
		Metadata: tokencontrolTaskMeta{
			Source:          "nullbot",
			Runbook:         strings.TrimSpace(cfg.Runbook),
			FindingHash:     strings.TrimSpace(findingHash),
			Scope:           scope,
			Severity:        severity,
			RemediationType: remediationType,
		},
	}, nil
}

func renderTerraformStub(
	template observe.WOTemplate,
	finding wo.Observation,
	scope string,
) (string, error) {
	if strings.TrimSpace(template.TerraformFindingType) == "" {
		return "", nil
	}

	terraformContext := buildTerraformContext(template, finding, scope)
	outputName, rendered, err := observe.RenderTerraformForFinding(
		template.TerraformFindingType,
		terraformContext,
	)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("# %s\n%s", outputName, strings.TrimSpace(rendered)), nil
}

func buildTerraformContext(
	template observe.WOTemplate,
	finding wo.Observation,
	scope string,
) map[string]any {
	context := make(map[string]any, len(template.TerraformContext)+len(finding.Data)+8)
	for key, value := range template.TerraformContext {
		context[key] = value
	}
	for key, value := range finding.Data {
		context[key] = value
	}
	context["Scope"] = strings.TrimSpace(scope)

	if strings.EqualFold(template.TerraformFindingType, observe.FindingClickHouseMissingTTL) {
		applyMissingTTLTerraformDefaults(context, finding.Detail)
	}
	return context
}

func applyMissingTTLTerraformDefaults(context map[string]any, detail string) {
	database := coalesceString(
		stringValueFromMap(context, "database", "Database", "db"),
		"default",
	)
	table := coalesceString(
		stringValueFromMap(context, "table", "TableName", "table_name"),
		"events",
	)

	if parsedDatabase, parsedTable, ok := parseClickHouseTableReference(detail); ok {
		if database == "default" {
			database = parsedDatabase
		}
		if table == "events" {
			table = parsedTable
		}
	}

	context["Database"] = database
	context["TableName"] = table
	context["Engine"] = coalesceString(
		stringValueFromMap(context, "engine", "Engine"),
		"MergeTree()",
	)
	context["TTLColumn"] = coalesceString(
		stringValueFromMap(context, "ttl_column", "TTLColumn", "column"),
		"event_time",
	)

	retentionDays := intValueFromMap(context, "retention_days", "RetentionDays")
	if retentionDays <= 0 {
		retentionDays = 30
	}
	context["RetentionDays"] = retentionDays

	resourceName := coalesceString(
		stringValueFromMap(context, "resource_name", "ResourceName"),
		fmt.Sprintf("%s_%s_ttl", database, table),
	)
	context["ResourceName"] = sanitizeTerraformIdentifier(resourceName)
}

func parseClickHouseTableReference(detail string) (string, string, bool) {
	match := clickhouseTableRefPattern.FindStringSubmatch(detail)
	if len(match) != 3 {
		return "", "", false
	}
	return strings.TrimSpace(match[1]), strings.TrimSpace(match[2]), true
}

func sanitizeTerraformIdentifier(raw string) string {
	cleaned := terraformIdentifierSanitizer.ReplaceAllString(strings.TrimSpace(raw), "_")
	cleaned = strings.Trim(cleaned, "_")
	if cleaned == "" {
		return "ttl_policy"
	}
	if cleaned[0] >= '0' && cleaned[0] <= '9' {
		return "ttl_" + cleaned
	}
	return cleaned
}

func stringValueFromMap(values map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			trimmed := strings.TrimSpace(typed)
			if trimmed != "" {
				return trimmed
			}
		default:
			trimmed := strings.TrimSpace(fmt.Sprintf("%v", typed))
			if trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func intValueFromMap(values map[string]any, keys ...string) int {
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case int:
			return typed
		case int32:
			return int(typed)
		case int64:
			return int(typed)
		case float32:
			return int(typed)
		case float64:
			return int(typed)
		case string:
			trimmed := strings.TrimSpace(typed)
			if trimmed == "" {
				continue
			}
			parsed, err := strconv.Atoi(trimmed)
			if err == nil {
				return parsed
			}
		}
	}
	return 0
}

func coalesceString(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func defaultWOTitle(finding wo.Observation, scope string) string {
	findingType := strings.TrimSpace(string(finding.Type))
	if findingType == "" {
		findingType = "unknown_finding"
	}
	titleType := strings.ReplaceAll(findingType, "_", " ")
	if scope == "" {
		return fmt.Sprintf("Remediate %s", titleType)
	}
	return fmt.Sprintf("Remediate %s on %s", titleType, scope)
}

func defaultWOPrompt(finding wo.Observation, runbook, scope string) string {
	detail := strings.TrimSpace(finding.Detail)
	if detail == "" {
		detail = "No additional detail provided."
	}
	return fmt.Sprintf(
		"Runbook: %s\nScope: %s\nFinding type: %s\nDetail: %s",
		strings.TrimSpace(runbook),
		scope,
		strings.TrimSpace(string(finding.Type)),
		detail,
	)
}

func normalizeTaskRepo(repo string) string {
	normalized := strings.TrimSpace(repo)
	if normalized == "" {
		return defaultTaskRepo
	}
	return normalized
}

func buildTaskPrompt(basePrompt, terraformStub string) string {
	prompt := strings.TrimSpace(basePrompt)
	if strings.TrimSpace(terraformStub) == "" {
		return prompt
	}
	if prompt == "" {
		return strings.TrimSpace(terraformStub)
	}
	return fmt.Sprintf("%s\n\nTerraform stub:\n%s", prompt, strings.TrimSpace(terraformStub))
}

func resolveTaskPriority(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case string(wo.SeverityCritical):
		return taskPriorityCritical
	case string(wo.SeverityHigh):
		return taskPriorityHigh
	case string(wo.SeverityLow):
		return taskPriorityLow
	default:
		return taskPriorityMedium
	}
}

func resolveWOSeverity(severity wo.Severity, fallback string) string {
	normalized := strings.ToLower(strings.TrimSpace(string(severity)))
	switch normalized {
	case string(wo.SeverityCritical),
		string(wo.SeverityHigh),
		string(wo.SeverityMedium),
		string(wo.SeverityLow):
		return normalized
	}

	normalizedFallback := strings.ToLower(strings.TrimSpace(fallback))
	switch normalizedFallback {
	case string(wo.SeverityCritical),
		string(wo.SeverityHigh),
		string(wo.SeverityMedium),
		string(wo.SeverityLow):
		return normalizedFallback
	}
	return string(wo.SeverityMedium)
}

func stableWOIDFromHash(findingHash string) string {
	hash := strings.TrimSpace(findingHash)
	if len(hash) > 12 {
		hash = hash[:12]
	}
	return "wo-" + hash
}

func uniqueTaskID(base string, idCounts map[string]int) string {
	trimmed := strings.TrimSpace(base)
	if trimmed == "" {
		trimmed = "wo-unknown"
	}
	idCounts[trimmed]++
	if idCounts[trimmed] == 1 {
		return trimmed
	}
	return fmt.Sprintf("%s-%d", trimmed, idCounts[trimmed])
}
