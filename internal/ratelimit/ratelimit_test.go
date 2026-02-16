package ratelimit

import (
	"testing"
	"time"

	"github.com/ppiankov/chainwatch/internal/model"
)

// --- Config tests ---

func TestHasLimitsEmpty(t *testing.T) {
	cfg := RateLimitConfig{}
	if cfg.HasLimits() {
		t.Error("expected empty config to have no limits")
	}
}

func TestHasLimitsConfigured(t *testing.T) {
	cfg := RateLimitConfig{
		"command": {MaxRequests: 10, Window: time.Minute},
	}
	if !cfg.HasLimits() {
		t.Error("expected HasLimits=true for configured limit")
	}
}

func TestHasLimitsZeroMaxRequests(t *testing.T) {
	cfg := RateLimitConfig{
		"command": {MaxRequests: 0, Window: time.Minute},
	}
	if cfg.HasLimits() {
		t.Error("expected HasLimits=false for zero MaxRequests")
	}
}

func TestHasLimitsZeroWindow(t *testing.T) {
	cfg := RateLimitConfig{
		"command": {MaxRequests: 10, Window: 0},
	}
	if cfg.HasLimits() {
		t.Error("expected HasLimits=false for zero Window")
	}
}

// --- Tracker tests ---

func TestSnapshotInitializesNilMap(t *testing.T) {
	state := model.NewTraceState("test")
	state.ToolCallCounts = nil

	now := time.Now().UTC()
	count := Snapshot(state, "command", time.Minute, now)
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
	if state.ToolCallCounts == nil {
		t.Error("expected map to be initialized")
	}
}

func TestSnapshotReturnsCount(t *testing.T) {
	state := model.NewTraceState("test")
	state.ToolCallCounts["command"] = 5

	now := state.RateLimitWindowStart.Add(30 * time.Second)
	count := Snapshot(state, "command", time.Minute, now)
	if count != 5 {
		t.Errorf("expected 5, got %d", count)
	}
}

func TestSnapshotResetsOnWindowExpiry(t *testing.T) {
	state := model.NewTraceState("test")
	state.ToolCallCounts["command"] = 10

	now := state.RateLimitWindowStart.Add(2 * time.Minute)
	count := Snapshot(state, "command", time.Minute, now)
	if count != 0 {
		t.Errorf("expected 0 after window reset, got %d", count)
	}
}

func TestSnapshotPreservesWithinWindow(t *testing.T) {
	state := model.NewTraceState("test")
	state.ToolCallCounts["command"] = 7

	now := state.RateLimitWindowStart.Add(30 * time.Second)
	count := Snapshot(state, "command", time.Minute, now)
	if count != 7 {
		t.Errorf("expected 7, got %d", count)
	}
}

func TestIncrementUpdatesCount(t *testing.T) {
	state := model.NewTraceState("test")
	Increment(state, "command")
	Increment(state, "command")
	Increment(state, "http_request")

	if state.ToolCallCounts["command"] != 2 {
		t.Errorf("expected command=2, got %d", state.ToolCallCounts["command"])
	}
	if state.ToolCallCounts["http_request"] != 1 {
		t.Errorf("expected http_request=1, got %d", state.ToolCallCounts["http_request"])
	}
}

// --- Check tests ---

func TestCheckWithinLimit(t *testing.T) {
	limit := &ToolRateLimit{MaxRequests: 10, Window: time.Minute}
	result := Check(5, limit)
	if result.Exceeded {
		t.Error("expected within limit")
	}
}

func TestCheckAtLimit(t *testing.T) {
	limit := &ToolRateLimit{MaxRequests: 10, Window: time.Minute}
	result := Check(10, limit)
	if !result.Exceeded {
		t.Error("expected exceeded at limit")
	}
	if result.Limit != 10 {
		t.Errorf("expected limit=10, got %d", result.Limit)
	}
}

func TestCheckAboveLimit(t *testing.T) {
	limit := &ToolRateLimit{MaxRequests: 10, Window: time.Minute}
	result := Check(15, limit)
	if !result.Exceeded {
		t.Error("expected exceeded above limit")
	}
}

func TestCheckNilLimit(t *testing.T) {
	result := Check(100, nil)
	if result.Exceeded {
		t.Error("expected not exceeded for nil limit")
	}
}

func TestCheckZeroMaxRequests(t *testing.T) {
	limit := &ToolRateLimit{MaxRequests: 0, Window: time.Minute}
	result := Check(5, limit)
	if result.Exceeded {
		t.Error("expected not exceeded for zero MaxRequests")
	}
}

// --- Evaluate tests ---

func TestEvaluateNoRateLimits(t *testing.T) {
	state := model.NewTraceState("test")
	_, handled := Evaluate("agent", "command", state, nil, time.Now())
	if handled {
		t.Error("expected skip when no rate limits configured")
	}

	_, handled = Evaluate("agent", "command", state, map[string]RateLimitConfig{}, time.Now())
	if handled {
		t.Error("expected skip when empty rate limits map")
	}
}

func TestEvaluateBurstWithinLimit(t *testing.T) {
	state := model.NewTraceState("test")
	now := state.RateLimitWindowStart
	limits := map[string]RateLimitConfig{
		"*": {"command": {MaxRequests: 5, Window: time.Minute}},
	}

	for i := 0; i < 5; i++ {
		_, handled := Evaluate("agent", "command", state, limits, now)
		if handled {
			t.Errorf("call %d: expected within limit", i+1)
		}
	}
}

func TestEvaluateExceedingRateDenied(t *testing.T) {
	state := model.NewTraceState("test")
	now := state.RateLimitWindowStart
	limits := map[string]RateLimitConfig{
		"*": {"command": {MaxRequests: 3, Window: time.Minute}},
	}

	// First 3 calls pass
	for i := 0; i < 3; i++ {
		_, handled := Evaluate("agent", "command", state, limits, now)
		if handled {
			t.Fatalf("call %d: expected within limit", i+1)
		}
	}

	// 4th call denied
	result, handled := Evaluate("agent", "command", state, limits, now)
	if !handled {
		t.Fatal("expected rate limit exceeded")
	}
	if result.Decision != model.Deny {
		t.Errorf("expected Deny, got %s", result.Decision)
	}
}

func TestEvaluateDifferentCategoriesIndependent(t *testing.T) {
	state := model.NewTraceState("test")
	now := state.RateLimitWindowStart
	limits := map[string]RateLimitConfig{
		"*": {
			"command":      {MaxRequests: 2, Window: time.Minute},
			"http_request": {MaxRequests: 2, Window: time.Minute},
		},
	}

	// Exhaust command limit
	Evaluate("agent", "command", state, limits, now)
	Evaluate("agent", "command", state, limits, now)
	_, handled := Evaluate("agent", "command", state, limits, now)
	if !handled {
		t.Fatal("expected command rate limited")
	}

	// http_request should still work
	_, handled = Evaluate("agent", "http_request", state, limits, now)
	if handled {
		t.Error("expected http_request independent of command limit")
	}
}

func TestEvaluateRateResetsAfterWindow(t *testing.T) {
	state := model.NewTraceState("test")
	now := state.RateLimitWindowStart
	limits := map[string]RateLimitConfig{
		"*": {"command": {MaxRequests: 2, Window: time.Minute}},
	}

	// Exhaust limit
	Evaluate("agent", "command", state, limits, now)
	Evaluate("agent", "command", state, limits, now)
	_, handled := Evaluate("agent", "command", state, limits, now)
	if !handled {
		t.Fatal("expected rate limited")
	}

	// Advance past window
	later := now.Add(2 * time.Minute)
	_, handled = Evaluate("agent", "command", state, limits, later)
	if handled {
		t.Error("expected rate to reset after window expiry")
	}
}

func TestEvaluateAgentLookupOrder(t *testing.T) {
	state := model.NewTraceState("test")
	now := state.RateLimitWindowStart
	limits := map[string]RateLimitConfig{
		"clawbot": {"command": {MaxRequests: 1, Window: time.Minute}},
		"*":       {"command": {MaxRequests: 100, Window: time.Minute}},
	}

	// First call passes
	_, handled := Evaluate("clawbot", "command", state, limits, now)
	if handled {
		t.Fatal("first call should pass")
	}

	// Second call denied (clawbot limit is 1, not global 100)
	_, handled = Evaluate("clawbot", "command", state, limits, now)
	if !handled {
		t.Error("expected agent-specific limit (1) to apply, not global (100)")
	}
}

func TestEvaluateGlobalFallback(t *testing.T) {
	state := model.NewTraceState("test")
	now := state.RateLimitWindowStart
	limits := map[string]RateLimitConfig{
		"*": {"command": {MaxRequests: 1, Window: time.Minute}},
	}

	// First call passes
	_, handled := Evaluate("unknown-agent", "command", state, limits, now)
	if handled {
		t.Fatal("first call should pass")
	}

	// Second call denied via global fallback
	result, handled := Evaluate("unknown-agent", "command", state, limits, now)
	if !handled {
		t.Error("expected global fallback to apply")
	}
	if result.Decision != model.Deny {
		t.Errorf("expected Deny, got %s", result.Decision)
	}
}

func TestEvaluateNoMatchingConfig(t *testing.T) {
	state := model.NewTraceState("test")
	state.ToolCallCounts["command"] = 999
	limits := map[string]RateLimitConfig{
		"other-agent": {"command": {MaxRequests: 1, Window: time.Minute}},
	}

	_, handled := Evaluate("clawbot", "command", state, limits, time.Now())
	if handled {
		t.Error("expected skip when no matching config and no global fallback")
	}
}

func TestEvaluatePolicyID(t *testing.T) {
	state := model.NewTraceState("test")
	now := state.RateLimitWindowStart
	limits := map[string]RateLimitConfig{
		"clawbot": {"command": {MaxRequests: 1, Window: time.Minute}},
	}

	Evaluate("clawbot", "command", state, limits, now)
	result, handled := Evaluate("clawbot", "command", state, limits, now)
	if !handled {
		t.Fatal("expected rate limited")
	}
	if result.PolicyID != "ratelimit.clawbot.command_exceeded" {
		t.Errorf("expected ratelimit.clawbot.command_exceeded, got %s", result.PolicyID)
	}
}
