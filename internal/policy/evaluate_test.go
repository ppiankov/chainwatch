package policy

import (
	"testing"

	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/model"
)

func TestLowRiskAllowed(t *testing.T) {
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/public/readme.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low", "egress": "internal"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", nil, nil)

	if result.Decision != model.Allow {
		t.Errorf("expected Allow for known-safe read, got %s", result.Decision)
	}
	if result.Tier != TierSafe {
		t.Errorf("expected tier 0 (safe), got %d", result.Tier)
	}
	if result.PolicyID != "tier.guarded.allow" {
		t.Errorf("expected tier.guarded.allow, got %s", result.PolicyID)
	}
}

func TestHighSensitivityElevated(t *testing.T) {
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/report.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high", "egress": "internal"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", nil, nil)

	// High sensitivity → not known-safe → tier 1 (elevated) → Allow in guarded mode
	if result.Decision != model.Allow {
		t.Errorf("expected Allow for tier 1 elevated action, got %s", result.Decision)
	}
	if result.Tier != TierElevated {
		t.Errorf("expected tier 1 (elevated), got %d", result.Tier)
	}
}

func TestSalaryBlockedForSOC(t *testing.T) {
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/hr/salary_bands.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high", "egress": "internal"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "SOC_efficiency", nil, nil)

	if result.Decision != model.RequireApproval {
		t.Errorf("expected RequireApproval for salary, got %s", result.Decision)
	}
	if result.ApprovalKey != "soc_salary_access" {
		t.Errorf("expected approval_key=soc_salary_access, got %s", result.ApprovalKey)
	}
	if result.PolicyID != "purpose.SOC_efficiency.salary" {
		t.Errorf("expected policy_id=purpose.SOC_efficiency.salary, got %s", result.PolicyID)
	}
}

func TestDenylistBlocksFirst(t *testing.T) {
	action := &model.Action{
		Tool:      "browser",
		Resource:  "https://stripe.com/v1/charges",
		Operation: "navigate",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")
	dl := denylist.NewDefault()

	result := Evaluate(action, state, "general", dl, nil)

	if result.Decision != model.Deny {
		t.Errorf("expected Deny for denylisted URL, got %s", result.Decision)
	}
	if result.PolicyID != "denylist.block" {
		t.Errorf("expected policy_id=denylist.block, got %s", result.PolicyID)
	}
	if result.Tier != TierCritical {
		t.Errorf("expected tier 3 (critical) for denylist, got %d", result.Tier)
	}
}

func TestIrreversibleZoneDenies(t *testing.T) {
	action := &model.Action{
		Tool:      "browser",
		Resource:  "https://store.example.com/checkout",
		Operation: "navigate",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", nil, nil)

	if result.Decision != model.Deny {
		t.Errorf("expected Deny for IRREVERSIBLE zone (checkout), got %s", result.Decision)
	}
	if result.Tier != TierCritical {
		t.Errorf("expected tier 3 (critical) for irreversible zone, got %d", result.Tier)
	}
}

func TestCommitmentZoneRequiresApproval(t *testing.T) {
	// First action: credential adjacent
	state := model.NewTraceState("test")
	state.ZonesEntered[model.ZoneCredentialAdjacent] = true

	// Second action: egress capable → combination triggers Commitment
	action := &model.Action{
		Tool:      "http",
		Resource:  "https://api.example.com/data",
		Operation: "get",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}

	result := Evaluate(action, state, "general", nil, nil)

	if result.Decision != model.RequireApproval {
		t.Errorf("expected RequireApproval for COMMITMENT zone, got %s", result.Decision)
	}
	if result.Tier != TierGuarded {
		t.Errorf("expected tier 2 (guarded) for commitment zone, got %d", result.Tier)
	}
}

func TestExternalEgressElevated(t *testing.T) {
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/report.csv",
		Operation: "read",
		RawMeta: map[string]any{
			"sensitivity": "high",
			"egress":      "external",
			"rows":        500,
		},
	}
	state := model.NewTraceState("test")
	state.SeenSources = append(state.SeenSources, "other_tool")

	result := Evaluate(action, state, "general", nil, nil)

	// /data/report.csv does not trigger any zone patterns.
	// high sensitivity → not known-safe → tier 1 (elevated) → Allow in guarded mode
	if result.Decision != model.Allow {
		t.Errorf("expected Allow for tier 1 elevated action, got %s (%s)", result.Decision, result.Reason)
	}
	if result.Tier != TierElevated {
		t.Errorf("expected tier 1, got %d", result.Tier)
	}
}

func TestZoneEscalationPersistsAcrossEvaluations(t *testing.T) {
	state := model.NewTraceState("test")

	// First: read HR data → enters SENSITIVE_DATA zone
	action1 := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/hr/employees.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high"},
	}
	Evaluate(action1, state, "general", nil, nil)

	// State should now have SENSITIVE_DATA zone
	if !state.ZonesEntered[model.ZoneSensitiveData] {
		t.Error("expected SENSITIVE_DATA zone after first evaluation")
	}

	// Second: read public file — zones should persist
	action2 := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/public/readme.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	Evaluate(action2, state, "general", nil, nil)

	// SENSITIVE_DATA zone should still be present
	if !state.ZonesEntered[model.ZoneSensitiveData] {
		t.Error("expected SENSITIVE_DATA zone to persist")
	}
}

func TestSelfTargetingActionDenied(t *testing.T) {
	action := &model.Action{
		Tool:      "command",
		Resource:  "rm /usr/local/bin/chainwatch",
		Operation: "execute",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", nil, nil)

	if result.Decision != model.Deny {
		t.Errorf("expected Deny for self-targeting action, got %s", result.Decision)
	}
	if result.Tier != TierCritical {
		t.Errorf("expected tier 3 for self-targeting, got %d", result.Tier)
	}
}

func TestKnownSafeActionTier0(t *testing.T) {
	action := &model.Action{
		Tool:      "command",
		Resource:  "ls /tmp",
		Operation: "execute",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", nil, nil)

	if result.Decision != model.Allow {
		t.Errorf("expected Allow for ls command, got %s", result.Decision)
	}
	if result.Tier != TierSafe {
		t.Errorf("expected tier 0 for ls, got %d", result.Tier)
	}
}

func TestUnknownActionDefaultsTier1(t *testing.T) {
	action := &model.Action{
		Tool:      "custom_tool",
		Resource:  "/some/resource",
		Operation: "process",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", nil, nil)

	if result.Tier != TierElevated {
		t.Errorf("expected tier 1 for unknown action, got %d", result.Tier)
	}
	if result.Decision != model.Allow {
		t.Errorf("expected Allow for tier 1 in guarded mode, got %s", result.Decision)
	}
}

func TestAdvisoryModeAllowsAll(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnforcementMode = "advisory"

	// Irreversible zone action → tier 3 → still allowed in advisory
	action := &model.Action{
		Tool:      "browser",
		Resource:  "https://store.example.com/checkout",
		Operation: "navigate",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", nil, cfg)

	if result.Decision != model.Allow {
		t.Errorf("expected Allow in advisory mode, got %s", result.Decision)
	}
	if result.Tier != TierCritical {
		t.Errorf("expected tier 3 for irreversible, got %d", result.Tier)
	}
}

func TestLockedModeDeniesAboveTier1(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnforcementMode = "locked"

	// Unknown action → tier 1 → RequireApproval in locked mode
	action := &model.Action{
		Tool:      "custom_tool",
		Resource:  "/resource",
		Operation: "process",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", nil, cfg)

	if result.Decision != model.RequireApproval {
		t.Errorf("expected RequireApproval for tier 1 in locked mode, got %s", result.Decision)
	}
	if result.Tier != TierElevated {
		t.Errorf("expected tier 1, got %d", result.Tier)
	}
}

func TestMinTierPromotesAction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinTier = TierGuarded

	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/public/readme.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", nil, cfg)

	// Known-safe action would be tier 0, but MinTier promotes to tier 2
	if result.Tier != TierGuarded {
		t.Errorf("expected tier 2 after MinTier promotion, got %d", result.Tier)
	}
	if result.Decision != model.RequireApproval {
		t.Errorf("expected RequireApproval for promoted tier 2, got %s", result.Decision)
	}
}

func TestTierFieldPresentInAllResults(t *testing.T) {
	state := model.NewTraceState("test")

	// Low risk
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/public/readme.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	result := Evaluate(action, state, "general", nil, nil)
	if result.Tier < 0 || result.Tier > 3 {
		t.Errorf("expected tier 0-3, got %d", result.Tier)
	}

	// Denylist
	dl := denylist.NewDefault()
	action2 := &model.Action{
		Tool:      "browser",
		Resource:  "https://stripe.com/v1/charges",
		Operation: "navigate",
	}
	state2 := model.NewTraceState("test2")
	result2 := Evaluate(action2, state2, "general", dl, nil)
	if result2.Tier != TierCritical {
		t.Errorf("expected tier 3 for denylist, got %d", result2.Tier)
	}
}
