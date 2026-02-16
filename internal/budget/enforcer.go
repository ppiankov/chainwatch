package budget

import (
	"fmt"

	"github.com/ppiankov/chainwatch/internal/model"
)

// CheckResult is the outcome of a budget check.
type CheckResult struct {
	Exceeded  bool
	Dimension string // "bytes", "rows", "duration"
	Current   int64
	Limit     int64
	Reason    string
}

// Check compares current usage against budget limits.
// Checks bytes, then rows, then duration — returns the first exceeded dimension.
func Check(usage Usage, cfg BudgetConfig) CheckResult {
	if cfg.MaxBytes > 0 && usage.Bytes >= cfg.MaxBytes {
		return CheckResult{
			Exceeded:  true,
			Dimension: "bytes",
			Current:   usage.Bytes,
			Limit:     cfg.MaxBytes,
			Reason:    fmt.Sprintf("budget exceeded: %d bytes >= %d max_bytes", usage.Bytes, cfg.MaxBytes),
		}
	}
	if cfg.MaxRows > 0 && usage.Rows >= cfg.MaxRows {
		return CheckResult{
			Exceeded:  true,
			Dimension: "rows",
			Current:   usage.Rows,
			Limit:     cfg.MaxRows,
			Reason:    fmt.Sprintf("budget exceeded: %d rows >= %d max_rows", usage.Rows, cfg.MaxRows),
		}
	}
	if cfg.MaxDuration > 0 && usage.Duration >= cfg.MaxDuration {
		return CheckResult{
			Exceeded:  true,
			Dimension: "duration",
			Current:   int64(usage.Duration),
			Limit:     int64(cfg.MaxDuration),
			Reason:    fmt.Sprintf("budget exceeded: %s duration >= %s max_duration", usage.Duration, cfg.MaxDuration),
		}
	}
	return CheckResult{}
}

// Evaluate looks up the agent's budget and checks usage against limits.
// Returns (result, true) if budget exceeded (terminal deny).
// Returns (zero, false) if within budget or no budget configured.
//
// Lookup order: budgets[agentID] → budgets["*"] → skip.
func Evaluate(agentID string, state *model.TraceState, budgets map[string]*BudgetConfig, tier int) (model.PolicyResult, bool) {
	if len(budgets) == 0 {
		return model.PolicyResult{}, false
	}

	cfg := budgets[agentID]
	if cfg == nil {
		cfg = budgets["*"]
	}
	if cfg == nil || !cfg.HasLimits() {
		return model.PolicyResult{}, false
	}

	usage := Snapshot(state)
	result := Check(usage, *cfg)
	if !result.Exceeded {
		return model.PolicyResult{}, false
	}

	policyAgent := agentID
	if policyAgent == "" {
		policyAgent = "global"
	}

	return model.PolicyResult{
		Decision: model.Deny,
		Tier:     tier,
		Reason:   result.Reason,
		PolicyID: fmt.Sprintf("budget.%s.%s_exceeded", policyAgent, result.Dimension),
	}, true
}
