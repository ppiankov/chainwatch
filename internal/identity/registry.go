package identity

import (
	"strings"

	"github.com/ppiankov/chainwatch/internal/model"
)

// AgentConfig defines the capabilities and constraints for a registered agent.
type AgentConfig struct {
	Purposes       []string          `yaml:"purposes" json:"purposes"`
	AllowResources []string          `yaml:"allow_resources" json:"allow_resources"`
	MaxSensitivity model.Sensitivity `yaml:"max_sensitivity" json:"max_sensitivity"`
	Rules          []AgentRule       `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// AgentRule is a per-agent policy rule evaluated in first-match-wins order.
type AgentRule struct {
	ResourcePattern string `yaml:"resource_pattern" json:"resource_pattern"`
	Decision        string `yaml:"decision" json:"decision"`
	Reason          string `yaml:"reason" json:"reason"`
	ApprovalKey     string `yaml:"approval_key,omitempty" json:"approval_key,omitempty"`
}

// Registry maps agent IDs to their configurations.
type Registry struct {
	agents map[string]*AgentConfig
}

// NewRegistry creates a Registry from an agents config map.
func NewRegistry(agents map[string]*AgentConfig) *Registry {
	if agents == nil {
		agents = make(map[string]*AgentConfig)
	}
	return &Registry{agents: agents}
}

// Lookup returns the AgentConfig for the given ID, or nil if not found.
func (r *Registry) Lookup(agentID string) *AgentConfig {
	return r.agents[agentID]
}

// IsRegistered returns true if the agent ID exists in the registry.
func (r *Registry) IsRegistered(agentID string) bool {
	_, ok := r.agents[agentID]
	return ok
}

// ValidatePurpose checks if the agent is allowed to use the given purpose.
// An empty purpose always passes. A wildcard "*" in purposes allows any purpose.
func (r *Registry) ValidatePurpose(agentID, purpose string) bool {
	cfg := r.agents[agentID]
	if cfg == nil {
		return false
	}
	if purpose == "" {
		return true
	}
	for _, p := range cfg.Purposes {
		if p == "*" || strings.EqualFold(p, purpose) {
			return true
		}
	}
	return false
}

// MatchResource checks if a resource matches any of the agent's allow_resources patterns.
// An empty AllowResources list allows all resources (no scope restriction).
func (r *Registry) MatchResource(agentID, resource string) bool {
	cfg := r.agents[agentID]
	if cfg == nil {
		return false
	}
	if len(cfg.AllowResources) == 0 {
		return true
	}
	for _, pattern := range cfg.AllowResources {
		if MatchPattern(pattern, resource) {
			return true
		}
	}
	return false
}

// MatchPattern checks if a value matches a glob-like pattern.
// Supports: *x* (contains), *.ext (suffix), /prefix/* (prefix), exact match.
// Matching is case-insensitive.
func MatchPattern(pattern, value string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}

	lowerValue := strings.ToLower(value)
	lowerPattern := strings.ToLower(pattern)

	// *x* — contains
	if strings.HasPrefix(lowerPattern, "*") && strings.HasSuffix(lowerPattern, "*") {
		inner := lowerPattern[1 : len(lowerPattern)-1]
		return strings.Contains(lowerValue, inner)
	}

	// *.ext — suffix
	if strings.HasPrefix(lowerPattern, "*") {
		suffix := lowerPattern[1:]
		return strings.HasSuffix(lowerValue, suffix)
	}

	// /prefix/* — prefix
	if strings.HasSuffix(lowerPattern, "*") {
		prefix := lowerPattern[:len(lowerPattern)-1]
		return strings.HasPrefix(lowerValue, prefix)
	}

	// Exact match
	return lowerValue == lowerPattern
}
