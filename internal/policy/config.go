package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ppiankov/chainwatch/internal/model"
)

// Thresholds defines risk score boundaries for policy decisions.
type Thresholds struct {
	AllowMax    int `yaml:"allow_max"`
	ApprovalMin int `yaml:"approval_min"`
}

// SensitivityWeights maps sensitivity levels to risk score contributions.
type SensitivityWeights struct {
	Low    int `yaml:"low"`
	Medium int `yaml:"medium"`
	High   int `yaml:"high"`
}

// WeightFor returns the risk weight for a given sensitivity level.
func (sw SensitivityWeights) WeightFor(s model.Sensitivity) int {
	switch s {
	case model.SensLow:
		return sw.Low
	case model.SensMedium:
		return sw.Medium
	case model.SensHigh:
		return sw.High
	default:
		return sw.Low
	}
}

// Rule is a purpose-bound policy rule evaluated in order (first match wins).
type Rule struct {
	Purpose         string `yaml:"purpose"`
	ResourcePattern string `yaml:"resource_pattern"`
	Decision        string `yaml:"decision"`
	Reason          string `yaml:"reason"`
	ApprovalKey     string `yaml:"approval_key"`
}

// PolicyConfig holds all configurable policy parameters.
type PolicyConfig struct {
	Thresholds         Thresholds         `yaml:"thresholds"`
	SensitivityWeights SensitivityWeights `yaml:"sensitivity_weights"`
	Rules              []Rule             `yaml:"rules"`
}

// DefaultConfig returns the built-in policy config matching previous hardcoded values.
func DefaultConfig() *PolicyConfig {
	return &PolicyConfig{
		Thresholds: Thresholds{
			AllowMax:    5,
			ApprovalMin: 11,
		},
		SensitivityWeights: SensitivityWeights{
			Low:    1,
			Medium: 3,
			High:   6,
		},
		Rules: []Rule{
			{
				Purpose:         "SOC_efficiency",
				ResourcePattern: "*salary*",
				Decision:        "require_approval",
				Reason:          "access to salary data is not allowed for SOC efficiency tasks without approval",
				ApprovalKey:     "soc_salary_access",
			},
		},
	}
}

// LoadConfig loads policy configuration from a YAML file.
// Empty path falls back to ~/.chainwatch/policy.yaml.
// Missing file returns defaults. Invalid YAML returns an error.
func LoadConfig(path string) (*PolicyConfig, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return DefaultConfig(), nil
		}
		path = filepath.Join(home, ".chainwatch", "policy.yaml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to read policy config: %w", err)
	}

	// Start with defaults, YAML overwrites only specified fields
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse policy config: %w", err)
	}

	return cfg, nil
}

// LoadConfigWithHash loads policy configuration and returns its SHA-256 hash.
// The hash is computed over the raw YAML bytes on disk.
// When no file exists (defaults used), the hash is the SHA-256 of empty input.
func LoadConfigWithHash(path string) (*PolicyConfig, string, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			h := sha256.Sum256(nil)
			return DefaultConfig(), "sha256:" + hex.EncodeToString(h[:]), nil
		}
		path = filepath.Join(home, ".chainwatch", "policy.yaml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			h := sha256.Sum256(nil)
			return DefaultConfig(), "sha256:" + hex.EncodeToString(h[:]), nil
		}
		return nil, "", fmt.Errorf("failed to read policy config: %w", err)
	}

	h := sha256.Sum256(data)
	hash := "sha256:" + hex.EncodeToString(h[:])

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, "", fmt.Errorf("failed to parse policy config: %w", err)
	}

	return cfg, hash, nil
}

// matchRule checks if a rule applies to the given purpose and resource.
// Purpose: exact match or "*" for any.
// ResourcePattern: *x* for contains, *.ext for suffix, /prefix/* for prefix, exact otherwise.
// Matching is case-insensitive.
func matchRule(rule Rule, purpose, resource string) bool {
	// Check purpose
	if rule.Purpose != "*" && !strings.EqualFold(rule.Purpose, purpose) {
		return false
	}

	// Check resource pattern
	pattern := rule.ResourcePattern
	if pattern == "" || pattern == "*" {
		return true
	}

	lowerResource := strings.ToLower(resource)
	lowerPattern := strings.ToLower(pattern)

	// *x* — contains
	if strings.HasPrefix(lowerPattern, "*") && strings.HasSuffix(lowerPattern, "*") {
		inner := lowerPattern[1 : len(lowerPattern)-1]
		return strings.Contains(lowerResource, inner)
	}

	// *.ext — suffix
	if strings.HasPrefix(lowerPattern, "*") {
		suffix := lowerPattern[1:]
		return strings.HasSuffix(lowerResource, suffix)
	}

	// /prefix/* — prefix
	if strings.HasSuffix(lowerPattern, "*") {
		prefix := lowerPattern[:len(lowerPattern)-1]
		return strings.HasPrefix(lowerResource, prefix)
	}

	// Exact match
	return lowerResource == lowerPattern
}

// parseDecision maps a string to a Decision enum. Fail-closed: unknown → Deny.
func parseDecision(s string) model.Decision {
	switch s {
	case "allow":
		return model.Allow
	case "deny":
		return model.Deny
	case "allow_with_redaction":
		return model.AllowWithRedaction
	case "require_approval":
		return model.RequireApproval
	case "rewrite_output":
		return model.RewriteOutput
	default:
		return model.Deny
	}
}

// rulePolicyID generates a policy ID from a rule.
func rulePolicyID(rule Rule) string {
	pattern := rule.ResourcePattern
	pattern = strings.Trim(pattern, "*")
	pattern = strings.Trim(pattern, ".")
	if pattern == "" {
		pattern = "all"
	}
	return fmt.Sprintf("purpose.%s.%s", rule.Purpose, pattern)
}

// DefaultConfigYAML returns a commented YAML string for init-policy.
func DefaultConfigYAML() string {
	return `# chainwatch policy configuration
# Generated by: chainwatch init-policy
#
# Evaluation order (cannot be changed):
#   1. Denylist check -> deny
#   2. Zone escalation -> update state
#   3. Irreversibility check -> deny or require_approval
#   4. Risk scoring (uses thresholds and sensitivity_weights below)
#   5. Purpose-bound rules (uses rules below)

# Risk score thresholds for decision boundaries.
# risk <= allow_max -> allow
# allow_max < risk < approval_min -> allow_with_redaction
# risk >= approval_min -> require_approval
thresholds:
  allow_max: 5
  approval_min: 11

# Sensitivity weights used in risk score calculation.
# Higher weight = higher risk contribution.
sensitivity_weights:
  low: 1
  medium: 3
  high: 6

# Purpose-bound rules evaluated in order. First match wins.
# Fields:
#   purpose: exact match or "*" for any purpose
#   resource_pattern: glob pattern (*salary* = contains "salary")
#   decision: allow | deny | allow_with_redaction | require_approval
#   reason: human-readable reason (optional, auto-generated if omitted)
#   approval_key: key for approval workflow (required if decision is require_approval)
rules:
  - purpose: SOC_efficiency
    resource_pattern: "*salary*"
    decision: require_approval
    reason: "access to salary data is not allowed for SOC efficiency tasks without approval"
    approval_key: soc_salary_access
`
}
