package policy

import (
	"testing"

	"github.com/ppiankov/chainwatch/internal/identity"
	"github.com/ppiankov/chainwatch/internal/model"
)

func agentConfig() *PolicyConfig {
	cfg := DefaultConfig()
	cfg.Agents = map[string]*identity.AgentConfig{
		"clawbot-prod": {
			Purposes:       []string{"SOC_efficiency", "compliance_check"},
			AllowResources: []string{"/hr/*", "/finance/*"},
			MaxSensitivity: model.SensHigh,
			Rules: []identity.AgentRule{
				{ResourcePattern: "*salary*", Decision: "allow", Reason: "prod authorized for salary"},
			},
		},
		"clawbot-staging": {
			Purposes:       []string{"testing"},
			AllowResources: []string{"/test/*"},
			MaxSensitivity: model.SensMedium,
		},
	}
	return cfg
}

func TestAgentRuleOverridesPurposeRule(t *testing.T) {
	cfg := agentConfig()
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/hr/salary_bands.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high"},
	}
	state := model.NewTraceState("test")

	// Without agent: purpose rule requires approval for salary
	result := Evaluate(action, state, "SOC_efficiency", "", nil, cfg)
	if result.Decision != model.RequireApproval {
		t.Errorf("expected RequireApproval without agent, got %s", result.Decision)
	}

	// With agent: agent rule allows salary access
	state2 := model.NewTraceState("test2")
	result2 := Evaluate(action, state2, "SOC_efficiency", "clawbot-prod", nil, cfg)
	if result2.Decision != model.Allow {
		t.Errorf("expected Allow with clawbot-prod agent rule, got %s (%s)", result2.Decision, result2.Reason)
	}
	if result2.PolicyID != "agent.clawbot-prod.rule.*salary*" {
		t.Errorf("expected agent policy ID, got %s", result2.PolicyID)
	}
}

func TestUnknownAgentDenied(t *testing.T) {
	cfg := agentConfig()
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/public/readme.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", "unknown-bot", nil, cfg)
	if result.Decision != model.Deny {
		t.Errorf("expected Deny for unknown agent, got %s", result.Decision)
	}
	if result.PolicyID != "agent.unknown" {
		t.Errorf("expected agent.unknown policy ID, got %s", result.PolicyID)
	}
}

func TestEmptyAgentFallsThrough(t *testing.T) {
	cfg := agentConfig()
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/public/readme.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	// Empty agentID skips agent enforcement entirely
	result := Evaluate(action, state, "general", "", nil, cfg)
	if result.Decision != model.Allow {
		t.Errorf("expected Allow for empty agent, got %s", result.Decision)
	}
}

func TestAgentResourceScopeDenied(t *testing.T) {
	cfg := agentConfig()
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/secret/keys.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "SOC_efficiency", "clawbot-prod", nil, cfg)
	if result.Decision != model.Deny {
		t.Errorf("expected Deny for out-of-scope resource, got %s", result.Decision)
	}
	if result.PolicyID != "agent.clawbot-prod.scope_denied" {
		t.Errorf("expected scope_denied policy ID, got %s", result.PolicyID)
	}
}

func TestAgentSensitivityCapEnforced(t *testing.T) {
	cfg := agentConfig()
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/test/sensitive.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high"},
	}
	state := model.NewTraceState("test")

	// clawbot-staging max_sensitivity=medium, action is high → deny
	result := Evaluate(action, state, "testing", "clawbot-staging", nil, cfg)
	if result.Decision != model.Deny {
		t.Errorf("expected Deny for sensitivity cap exceeded, got %s", result.Decision)
	}
	if result.PolicyID != "agent.clawbot-staging.sensitivity_denied" {
		t.Errorf("expected sensitivity_denied policy ID, got %s", result.PolicyID)
	}
}

func TestAgentPurposeValidationDenied(t *testing.T) {
	cfg := agentConfig()
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/hr/org_chart.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	// clawbot-prod does not have "testing" purpose
	result := Evaluate(action, state, "testing", "clawbot-prod", nil, cfg)
	if result.Decision != model.Deny {
		t.Errorf("expected Deny for unauthorized purpose, got %s", result.Decision)
	}
	if result.PolicyID != "agent.clawbot-prod.purpose_denied" {
		t.Errorf("expected purpose_denied policy ID, got %s", result.PolicyID)
	}
}

func TestNoAgentsConfigWithAgentIDDenied(t *testing.T) {
	cfg := DefaultConfig() // no agents configured
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/readme.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", "some-agent", nil, cfg)
	if result.Decision != model.Deny {
		t.Errorf("expected Deny when no agents configured, got %s", result.Decision)
	}
	if result.PolicyID != "agent.no_config" {
		t.Errorf("expected agent.no_config policy ID, got %s", result.PolicyID)
	}
}

func TestAgentRulesFirstMatchWins(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agents = map[string]*identity.AgentConfig{
		"multi-rule-agent": {
			Purposes:       []string{"*"},
			AllowResources: []string{},
			MaxSensitivity: model.SensHigh,
			Rules: []identity.AgentRule{
				{ResourcePattern: "*salary*", Decision: "deny", Reason: "salary blocked"},
				{ResourcePattern: "*salary*", Decision: "allow", Reason: "salary allowed"},
			},
		},
	}
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/salary.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", "multi-rule-agent", nil, cfg)
	if result.Decision != model.Deny {
		t.Errorf("expected first rule (Deny) to win, got %s", result.Decision)
	}
	if result.Reason != "salary blocked" {
		t.Errorf("expected 'salary blocked', got %s", result.Reason)
	}
}

func TestAgentIDSetOnTraceState(t *testing.T) {
	cfg := agentConfig()
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/hr/org_chart.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	Evaluate(action, state, "SOC_efficiency", "clawbot-prod", nil, cfg)
	if state.AgentID != "clawbot-prod" {
		t.Errorf("expected state.AgentID=clawbot-prod, got %q", state.AgentID)
	}
}
