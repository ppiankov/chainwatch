package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ppiankov/chainwatch/internal/model"
	"gopkg.in/yaml.v3"
)

func TestDefaultConfigValues(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Thresholds.AllowMax != 5 {
		t.Errorf("expected AllowMax=5, got %d", cfg.Thresholds.AllowMax)
	}
	if cfg.Thresholds.ApprovalMin != 11 {
		t.Errorf("expected ApprovalMin=11, got %d", cfg.Thresholds.ApprovalMin)
	}
	if cfg.SensitivityWeights.Low != 1 {
		t.Errorf("expected Low=1, got %d", cfg.SensitivityWeights.Low)
	}
	if cfg.SensitivityWeights.Medium != 3 {
		t.Errorf("expected Medium=3, got %d", cfg.SensitivityWeights.Medium)
	}
	if cfg.SensitivityWeights.High != 6 {
		t.Errorf("expected High=6, got %d", cfg.SensitivityWeights.High)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Purpose != "SOC_efficiency" {
		t.Errorf("expected SOC_efficiency rule, got %s", cfg.Rules[0].Purpose)
	}
	if cfg.Rules[0].ApprovalKey != "soc_salary_access" {
		t.Errorf("expected soc_salary_access, got %s", cfg.Rules[0].ApprovalKey)
	}
	if cfg.EnforcementMode != "guarded" {
		t.Errorf("expected EnforcementMode=guarded, got %s", cfg.EnforcementMode)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/path/policy.yaml")
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if cfg.Thresholds.AllowMax != 5 {
		t.Errorf("expected default AllowMax=5, got %d", cfg.Thresholds.AllowMax)
	}
}

func TestLoadConfigEmptyPath(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("expected no error for empty path, got %v", err)
	}
	// Should return defaults (no ~/.chainwatch/policy.yaml in test env)
	if cfg.Thresholds.AllowMax != 5 {
		t.Errorf("expected default AllowMax=5, got %d", cfg.Thresholds.AllowMax)
	}
}

func TestLoadConfigFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	content := `
thresholds:
  allow_max: 3
  approval_min: 8
sensitivity_weights:
  low: 2
  medium: 4
  high: 8
rules:
  - purpose: testing
    resource_pattern: "*secret*"
    decision: deny
    reason: "secrets blocked in test"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Thresholds.AllowMax != 3 {
		t.Errorf("expected AllowMax=3, got %d", cfg.Thresholds.AllowMax)
	}
	if cfg.Thresholds.ApprovalMin != 8 {
		t.Errorf("expected ApprovalMin=8, got %d", cfg.Thresholds.ApprovalMin)
	}
	if cfg.SensitivityWeights.High != 8 {
		t.Errorf("expected High=8, got %d", cfg.SensitivityWeights.High)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Purpose != "testing" {
		t.Errorf("expected purpose=testing, got %s", cfg.Rules[0].Purpose)
	}
}

func TestLoadConfigPartialYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	// Only override thresholds, weights and rules should retain defaults
	content := `
thresholds:
  allow_max: 7
  approval_min: 15
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Thresholds.AllowMax != 7 {
		t.Errorf("expected AllowMax=7, got %d", cfg.Thresholds.AllowMax)
	}
	// Weights should be defaults
	if cfg.SensitivityWeights.Low != 1 {
		t.Errorf("expected default Low=1, got %d", cfg.SensitivityWeights.Low)
	}
	// Rules should be defaults
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 default rule, got %d", len(cfg.Rules))
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	if err := os.WriteFile(path, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestMatchRuleExactPurpose(t *testing.T) {
	rule := Rule{Purpose: "SOC_efficiency", ResourcePattern: "*salary*"}
	if !matchRule(rule, "SOC_efficiency", "/data/salary.csv") {
		t.Error("expected match for exact purpose + matching resource")
	}
	if matchRule(rule, "other_purpose", "/data/salary.csv") {
		t.Error("expected no match for wrong purpose")
	}
}

func TestMatchRuleWildcardPurpose(t *testing.T) {
	rule := Rule{Purpose: "*", ResourcePattern: "*.env"}
	if !matchRule(rule, "any_purpose", "/project/.env") {
		t.Error("expected match for wildcard purpose")
	}
	if !matchRule(rule, "another", "/app/.env") {
		t.Error("expected match for wildcard purpose with different purpose string")
	}
}

func TestMatchRuleContainsPattern(t *testing.T) {
	rule := Rule{Purpose: "*", ResourcePattern: "*salary*"}
	if !matchRule(rule, "general", "/data/hr/salary_bands.csv") {
		t.Error("expected match for contains pattern")
	}
	if matchRule(rule, "general", "/data/hr/employees.csv") {
		t.Error("expected no match for non-matching resource")
	}
}

func TestMatchRuleSuffixPattern(t *testing.T) {
	rule := Rule{Purpose: "*", ResourcePattern: "*.env"}
	if !matchRule(rule, "general", "/project/.env") {
		t.Error("expected match for suffix pattern")
	}
	if matchRule(rule, "general", "/project/config.yaml") {
		t.Error("expected no match for wrong suffix")
	}
}

func TestMatchRulePrefixPattern(t *testing.T) {
	rule := Rule{Purpose: "*", ResourcePattern: "/data/*"}
	if !matchRule(rule, "general", "/data/secret.csv") {
		t.Error("expected match for prefix pattern")
	}
	if matchRule(rule, "general", "/other/file.txt") {
		t.Error("expected no match for wrong prefix")
	}
}

func TestMatchRuleCaseInsensitive(t *testing.T) {
	rule := Rule{Purpose: "soc_efficiency", ResourcePattern: "*SALARY*"}
	if !matchRule(rule, "SOC_efficiency", "/data/salary.csv") {
		t.Error("expected case-insensitive match")
	}
}

func TestMatchRuleNoMatch(t *testing.T) {
	rule := Rule{Purpose: "SOC_efficiency", ResourcePattern: "*salary*"}
	if matchRule(rule, "SOC_efficiency", "/data/readme.txt") {
		t.Error("expected no match")
	}
}

func TestParseDecision(t *testing.T) {
	tests := []struct {
		input string
		want  model.Decision
	}{
		{"allow", model.Allow},
		{"deny", model.Deny},
		{"allow_with_redaction", model.AllowWithRedaction},
		{"require_approval", model.RequireApproval},
		{"rewrite_output", model.RewriteOutput},
		{"unknown", model.Deny}, // fail-closed
		{"", model.Deny},
	}
	for _, tt := range tests {
		got := parseDecision(tt.input)
		if got != tt.want {
			t.Errorf("parseDecision(%q) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestRulePolicyID(t *testing.T) {
	rule := Rule{Purpose: "SOC_efficiency", ResourcePattern: "*salary*"}
	id := rulePolicyID(rule)
	if id != "purpose.SOC_efficiency.salary" {
		t.Errorf("expected purpose.SOC_efficiency.salary, got %s", id)
	}
}

func TestRulePolicyIDWildcard(t *testing.T) {
	rule := Rule{Purpose: "general", ResourcePattern: "*"}
	id := rulePolicyID(rule)
	if id != "purpose.general.all" {
		t.Errorf("expected purpose.general.all, got %s", id)
	}
}

func TestDefaultConfigYAMLRoundTrip(t *testing.T) {
	yamlStr := DefaultConfigYAML()

	var parsed PolicyConfig
	if err := yaml.Unmarshal([]byte(yamlStr), &parsed); err != nil {
		t.Fatalf("failed to parse DefaultConfigYAML: %v", err)
	}

	defaults := DefaultConfig()

	if parsed.Thresholds.AllowMax != defaults.Thresholds.AllowMax {
		t.Errorf("AllowMax mismatch: parsed=%d, default=%d", parsed.Thresholds.AllowMax, defaults.Thresholds.AllowMax)
	}
	if parsed.Thresholds.ApprovalMin != defaults.Thresholds.ApprovalMin {
		t.Errorf("ApprovalMin mismatch: parsed=%d, default=%d", parsed.Thresholds.ApprovalMin, defaults.Thresholds.ApprovalMin)
	}
	if parsed.SensitivityWeights.Low != defaults.SensitivityWeights.Low {
		t.Errorf("Low weight mismatch: parsed=%d, default=%d", parsed.SensitivityWeights.Low, defaults.SensitivityWeights.Low)
	}
	if parsed.SensitivityWeights.Medium != defaults.SensitivityWeights.Medium {
		t.Errorf("Medium weight mismatch")
	}
	if parsed.SensitivityWeights.High != defaults.SensitivityWeights.High {
		t.Errorf("High weight mismatch")
	}
	if len(parsed.Rules) != len(defaults.Rules) {
		t.Fatalf("Rules count mismatch: parsed=%d, default=%d", len(parsed.Rules), len(defaults.Rules))
	}
	if parsed.Rules[0].Purpose != defaults.Rules[0].Purpose {
		t.Errorf("Rule purpose mismatch")
	}
	if parsed.Rules[0].ResourcePattern != defaults.Rules[0].ResourcePattern {
		t.Errorf("Rule pattern mismatch")
	}
	if parsed.EnforcementMode != defaults.EnforcementMode {
		t.Errorf("EnforcementMode mismatch: parsed=%s, default=%s", parsed.EnforcementMode, defaults.EnforcementMode)
	}
}

func TestSensitivityWeightsWeightFor(t *testing.T) {
	sw := SensitivityWeights{Low: 1, Medium: 3, High: 6}
	if sw.WeightFor(model.SensLow) != 1 {
		t.Error("expected 1 for low")
	}
	if sw.WeightFor(model.SensMedium) != 3 {
		t.Error("expected 3 for medium")
	}
	if sw.WeightFor(model.SensHigh) != 6 {
		t.Error("expected 6 for high")
	}
	if sw.WeightFor("unknown") != 1 {
		t.Error("expected fallback to low weight for unknown")
	}
}

func TestEvaluateWithNilConfigMatchesDefault(t *testing.T) {
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/hr/salary_bands.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high", "egress": "internal"},
	}

	state1 := model.NewTraceState("test1")
	resultNil := Evaluate(action, state1, "SOC_efficiency", "", nil, nil)

	action2 := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/hr/salary_bands.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high", "egress": "internal"},
	}
	state2 := model.NewTraceState("test2")
	resultDefault := Evaluate(action2, state2, "SOC_efficiency", "", nil, DefaultConfig())

	if resultNil.Decision != resultDefault.Decision {
		t.Errorf("nil config decision=%s, default config decision=%s", resultNil.Decision, resultDefault.Decision)
	}
	if resultNil.PolicyID != resultDefault.PolicyID {
		t.Errorf("nil config policyID=%s, default config policyID=%s", resultNil.PolicyID, resultDefault.PolicyID)
	}
}

func TestCustomThresholdsChangeDecision(t *testing.T) {
	// With default config (AllowMax=5), high sensitivity (weight=6) → AllowWithRedaction
	// With custom config (AllowMax=10), high sensitivity (weight=6) → Allow
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/report.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high", "egress": "internal"},
	}

	state := model.NewTraceState("test")
	cfg := &PolicyConfig{
		Thresholds:         Thresholds{AllowMax: 10, ApprovalMin: 20},
		SensitivityWeights: SensitivityWeights{Low: 1, Medium: 3, High: 6},
		Rules:              []Rule{},
	}

	result := Evaluate(action, state, "general", "", nil, cfg)
	if result.Decision != model.Allow {
		t.Errorf("expected Allow with high AllowMax threshold, got %s (%s)", result.Decision, result.Reason)
	}
}
