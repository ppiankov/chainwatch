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

	result := Evaluate(action, state, "general", nil)

	if result.Decision != model.Allow {
		t.Errorf("expected Allow for low-risk action, got %s", result.Decision)
	}
}

func TestHighSensitivityRedacted(t *testing.T) {
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/report.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high", "egress": "internal"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", nil)

	if result.Decision != model.AllowWithRedaction {
		t.Errorf("expected AllowWithRedaction for high sensitivity, got %s", result.Decision)
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

	result := Evaluate(action, state, "SOC_efficiency", nil)

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

	result := Evaluate(action, state, "general", dl)

	if result.Decision != model.Deny {
		t.Errorf("expected Deny for denylisted URL, got %s", result.Decision)
	}
	if result.PolicyID != "denylist.block" {
		t.Errorf("expected policy_id=denylist.block, got %s", result.PolicyID)
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

	result := Evaluate(action, state, "general", nil)

	if result.Decision != model.Deny {
		t.Errorf("expected Deny for IRREVERSIBLE zone (checkout), got %s", result.Decision)
	}
	if result.PolicyID != "monotonic.irreversible" {
		t.Errorf("expected policy_id=monotonic.irreversible, got %s", result.PolicyID)
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

	result := Evaluate(action, state, "general", nil)

	if result.Decision != model.RequireApproval {
		t.Errorf("expected RequireApproval for COMMITMENT zone, got %s", result.Decision)
	}
	if result.PolicyID != "monotonic.commitment" {
		t.Errorf("expected policy_id=monotonic.commitment, got %s", result.PolicyID)
	}
}

func TestLegacyScoringStillWorks(t *testing.T) {
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/public/readme.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low", "egress": "internal"},
	}
	state := model.NewTraceState("test")

	result := Evaluate(action, state, "general", nil)

	if result.Decision != model.Allow {
		t.Errorf("expected Allow for low risk, got %s", result.Decision)
	}
	if result.PolicyID != "risk.low" {
		t.Errorf("expected risk.low policy, got %s", result.PolicyID)
	}
}

func TestExternalEgressHighRisk(t *testing.T) {
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

	result := Evaluate(action, state, "general", nil)

	// high=6 + external=6 + new_source=2 = 14 → RequireApproval
	if result.Decision != model.RequireApproval {
		t.Errorf("expected RequireApproval for high external risk, got %s (%s)", result.Decision, result.Reason)
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
	Evaluate(action1, state, "general", nil)

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
	Evaluate(action2, state, "general", nil)

	// SENSITIVE_DATA zone should still be present
	if !state.ZonesEntered[model.ZoneSensitiveData] {
		t.Error("expected SENSITIVE_DATA zone to persist")
	}
}
