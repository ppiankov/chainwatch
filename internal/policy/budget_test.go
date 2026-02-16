package policy

import (
	"testing"

	"github.com/ppiankov/chainwatch/internal/budget"
	"github.com/ppiankov/chainwatch/internal/model"
)

func budgetConfig() *PolicyConfig {
	cfg := DefaultConfig()
	cfg.Budgets = map[string]*budget.BudgetConfig{
		"clawbot": {MaxBytes: 1000},
		"*":       {MaxBytes: 500, MaxRows: 100},
	}
	return cfg
}

func TestBudgetExceededDeniesAction(t *testing.T) {
	cfg := budgetConfig()
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/report.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")
	state.VolumeBytes = 2000 // exceeds global "*" 500 limit

	result := Evaluate(action, state, "general", "", nil, cfg)
	if result.Decision != model.Deny {
		t.Errorf("expected Deny for budget exceeded, got %s (%s)", result.Decision, result.Reason)
	}
	if result.PolicyID != "budget.*.bytes_exceeded" {
		t.Errorf("expected budget.*.bytes_exceeded, got %s", result.PolicyID)
	}
}

func TestBudgetGlobalFallbackRows(t *testing.T) {
	cfg := budgetConfig()
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/report.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")
	state.VolumeRows = 200 // exceeds global "*" 100 row limit

	result := Evaluate(action, state, "general", "", nil, cfg)
	if result.Decision != model.Deny {
		t.Errorf("expected Deny for rows exceeded, got %s (%s)", result.Decision, result.Reason)
	}
	if result.PolicyID != "budget.*.rows_exceeded" {
		t.Errorf("expected budget.*.rows_exceeded, got %s", result.PolicyID)
	}
}

func TestNoBudgetsNormalEvaluation(t *testing.T) {
	cfg := DefaultConfig() // no budgets
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/report.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")
	state.VolumeBytes = 999999 // huge volume but no budget configured

	result := Evaluate(action, state, "general", "", nil, cfg)
	if result.Decision != model.Allow {
		t.Errorf("expected Allow with no budgets configured, got %s (%s)", result.Decision, result.Reason)
	}
}

func TestBudgetSkippedWhenWithinLimits(t *testing.T) {
	cfg := budgetConfig()
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/report.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")
	state.VolumeBytes = 100 // within global 500 limit
	state.VolumeRows = 10   // within global 100 limit

	result := Evaluate(action, state, "general", "", nil, cfg)
	if result.Decision == model.Deny {
		t.Errorf("expected non-Deny when within budget, got %s (%s)", result.Decision, result.Reason)
	}
}

func TestNewSessionResetsBudget(t *testing.T) {
	cfg := budgetConfig()
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/report.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}

	// First session: exceeded
	state1 := model.NewTraceState("session-1")
	state1.VolumeBytes = 2000
	result1 := Evaluate(action, state1, "general", "", nil, cfg)
	if result1.Decision != model.Deny {
		t.Errorf("expected Deny for exceeded budget, got %s", result1.Decision)
	}

	// New session: fresh state, within limits
	state2 := model.NewTraceState("session-2")
	result2 := Evaluate(action, state2, "general", "", nil, cfg)
	if result2.Decision == model.Deny {
		t.Errorf("expected non-Deny for fresh session, got %s (%s)", result2.Decision, result2.Reason)
	}
}
