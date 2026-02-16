package ratelimit

import (
	"fmt"
	"time"

	"github.com/ppiankov/chainwatch/internal/model"
)

// CheckResult is the outcome of a rate limit check.
type CheckResult struct {
	Exceeded     bool
	ToolCategory string
	Current      int
	Limit        int
	Reason       string
}

// Check compares the current count against the rate limit.
func Check(count int, limit *ToolRateLimit) CheckResult {
	if limit == nil || limit.MaxRequests <= 0 || limit.Window <= 0 {
		return CheckResult{}
	}
	if count >= limit.MaxRequests {
		return CheckResult{
			Exceeded: true,
			Current:  count,
			Limit:    limit.MaxRequests,
			Reason: fmt.Sprintf("rate limit exceeded: %d/%d requests in %s window",
				count, limit.MaxRequests, limit.Window),
		}
	}
	return CheckResult{}
}

// Evaluate looks up the agent's rate limit for the action's tool category
// and checks whether the limit is exceeded.
// Returns (result, true) if rate limit exceeded (terminal deny).
// Returns (zero, false) if within limit or no rate limit configured.
//
// Lookup order: rateLimits[agentID] → rateLimits["*"] → skip.
// When the check passes, the counter is incremented.
func Evaluate(agentID, toolCategory string, state *model.TraceState, rateLimits map[string]RateLimitConfig, now time.Time) (model.PolicyResult, bool) {
	if len(rateLimits) == 0 {
		return model.PolicyResult{}, false
	}

	cfg := rateLimits[agentID]
	if cfg == nil {
		cfg = rateLimits["*"]
	}
	if cfg == nil || !cfg.HasLimits() {
		return model.PolicyResult{}, false
	}

	toolLimit := cfg[toolCategory]
	if toolLimit == nil || toolLimit.MaxRequests <= 0 {
		return model.PolicyResult{}, false
	}

	count := Snapshot(state, toolCategory, toolLimit.Window, now)
	result := Check(count, toolLimit)
	if !result.Exceeded {
		Increment(state, toolCategory)
		return model.PolicyResult{}, false
	}

	policyAgent := agentID
	if policyAgent == "" {
		policyAgent = "global"
	}

	return model.PolicyResult{
		Decision: model.Deny,
		Tier:     0,
		Reason:   result.Reason,
		PolicyID: fmt.Sprintf("ratelimit.%s.%s_exceeded", policyAgent, toolCategory),
	}, true
}
