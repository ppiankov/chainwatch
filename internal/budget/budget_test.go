package budget

import (
	"testing"
	"time"

	"github.com/ppiankov/chainwatch/internal/model"
)

// --- Config tests ---

func TestHasLimitsZero(t *testing.T) {
	cfg := BudgetConfig{}
	if cfg.HasLimits() {
		t.Error("expected zero config to have no limits")
	}
}

func TestHasLimitsNonZero(t *testing.T) {
	tests := []BudgetConfig{
		{MaxBytes: 100},
		{MaxRows: 100},
		{MaxDuration: time.Minute},
		{MaxBytes: 100, MaxRows: 50, MaxDuration: time.Hour},
	}
	for _, cfg := range tests {
		if !cfg.HasLimits() {
			t.Errorf("expected HasLimits=true for %+v", cfg)
		}
	}
}

// --- Tracker tests ---

func TestSnapshotReadsFromState(t *testing.T) {
	state := model.NewTraceState("test")
	state.VolumeBytes = 1024
	state.VolumeRows = 50

	usage := Snapshot(state)
	if usage.Bytes != 1024 {
		t.Errorf("expected 1024 bytes, got %d", usage.Bytes)
	}
	if usage.Rows != 50 {
		t.Errorf("expected 50 rows, got %d", usage.Rows)
	}
}

func TestSnapshotDuration(t *testing.T) {
	state := model.NewTraceState("test")
	state.StartedAt = time.Now().UTC().Add(-5 * time.Minute)

	usage := Snapshot(state)
	if usage.Duration < 4*time.Minute || usage.Duration > 6*time.Minute {
		t.Errorf("expected ~5m duration, got %s", usage.Duration)
	}
}

// --- Check tests ---

func TestCheckBytesExceeded(t *testing.T) {
	usage := Usage{Bytes: 1000, Rows: 0, Duration: 0}
	cfg := BudgetConfig{MaxBytes: 1000}

	result := Check(usage, cfg)
	if !result.Exceeded {
		t.Error("expected bytes exceeded")
	}
	if result.Dimension != "bytes" {
		t.Errorf("expected dimension=bytes, got %s", result.Dimension)
	}
}

func TestCheckBytesWithinLimit(t *testing.T) {
	usage := Usage{Bytes: 999, Rows: 0, Duration: 0}
	cfg := BudgetConfig{MaxBytes: 1000}

	result := Check(usage, cfg)
	if result.Exceeded {
		t.Error("expected bytes within limit")
	}
}

func TestCheckRowsExceeded(t *testing.T) {
	usage := Usage{Bytes: 0, Rows: 500, Duration: 0}
	cfg := BudgetConfig{MaxRows: 500}

	result := Check(usage, cfg)
	if !result.Exceeded {
		t.Error("expected rows exceeded")
	}
	if result.Dimension != "rows" {
		t.Errorf("expected dimension=rows, got %s", result.Dimension)
	}
}

func TestCheckDurationExceeded(t *testing.T) {
	usage := Usage{Bytes: 0, Rows: 0, Duration: 10 * time.Minute}
	cfg := BudgetConfig{MaxDuration: 5 * time.Minute}

	result := Check(usage, cfg)
	if !result.Exceeded {
		t.Error("expected duration exceeded")
	}
	if result.Dimension != "duration" {
		t.Errorf("expected dimension=duration, got %s", result.Dimension)
	}
}

func TestCheckNoLimitsNeverTriggers(t *testing.T) {
	usage := Usage{Bytes: 999999, Rows: 999999, Duration: 999 * time.Hour}
	cfg := BudgetConfig{} // all zeros

	result := Check(usage, cfg)
	if result.Exceeded {
		t.Error("expected no trigger with zero limits")
	}
}

func TestCheckFirstDimensionReported(t *testing.T) {
	// All dimensions exceeded — bytes should be reported first
	usage := Usage{Bytes: 1000, Rows: 1000, Duration: 10 * time.Minute}
	cfg := BudgetConfig{MaxBytes: 500, MaxRows: 500, MaxDuration: 5 * time.Minute}

	result := Check(usage, cfg)
	if result.Dimension != "bytes" {
		t.Errorf("expected bytes first, got %s", result.Dimension)
	}
}

// --- Evaluate tests ---

func TestEvaluateNoBudgets(t *testing.T) {
	state := model.NewTraceState("test")
	_, handled := Evaluate("agent", state, nil, 0)
	if handled {
		t.Error("expected skip when no budgets configured")
	}

	_, handled = Evaluate("agent", state, map[string]*BudgetConfig{}, 0)
	if handled {
		t.Error("expected skip when empty budgets map")
	}
}

func TestEvaluateAgentBudgetFound(t *testing.T) {
	state := model.NewTraceState("test")
	state.VolumeBytes = 2000

	budgets := map[string]*BudgetConfig{
		"clawbot": {MaxBytes: 1000},
	}

	result, handled := Evaluate("clawbot", state, budgets, 1)
	if !handled {
		t.Fatal("expected budget to be checked")
	}
	if result.Decision != model.Deny {
		t.Errorf("expected Deny, got %s", result.Decision)
	}
	if result.PolicyID != "budget.clawbot.bytes_exceeded" {
		t.Errorf("expected budget.clawbot.bytes_exceeded, got %s", result.PolicyID)
	}
}

func TestEvaluateGlobalFallback(t *testing.T) {
	state := model.NewTraceState("test")
	state.VolumeRows = 500

	budgets := map[string]*BudgetConfig{
		"*": {MaxRows: 100},
	}

	result, handled := Evaluate("unknown-agent", state, budgets, 0)
	if !handled {
		t.Fatal("expected global fallback to apply")
	}
	if result.Decision != model.Deny {
		t.Errorf("expected Deny, got %s", result.Decision)
	}
}

func TestEvaluateNoBudgetForAgent(t *testing.T) {
	state := model.NewTraceState("test")
	state.VolumeBytes = 999999

	budgets := map[string]*BudgetConfig{
		"other-agent": {MaxBytes: 100},
	}

	_, handled := Evaluate("clawbot", state, budgets, 0)
	if handled {
		t.Error("expected skip when no budget for this agent and no global fallback")
	}
}

func TestEvaluateBudgetExceeded(t *testing.T) {
	state := model.NewTraceState("test")
	state.VolumeBytes = 2000

	budgets := map[string]*BudgetConfig{
		"clawbot": {MaxBytes: 1000},
	}

	result, handled := Evaluate("clawbot", state, budgets, 2)
	if !handled {
		t.Fatal("expected exceeded")
	}
	if result.Decision != model.Deny {
		t.Errorf("expected Deny, got %s", result.Decision)
	}
	if result.Tier != 2 {
		t.Errorf("expected tier 2, got %d", result.Tier)
	}
}

func TestEvaluateWithinLimits(t *testing.T) {
	state := model.NewTraceState("test")
	state.VolumeBytes = 500

	budgets := map[string]*BudgetConfig{
		"clawbot": {MaxBytes: 1000},
	}

	_, handled := Evaluate("clawbot", state, budgets, 0)
	if handled {
		t.Error("expected within limits to pass through")
	}
}
