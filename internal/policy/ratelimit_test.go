package policy

import (
	"testing"
	"time"

	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/ratelimit"
)

func rateLimitConfig() *PolicyConfig {
	cfg := DefaultConfig()
	cfg.RateLimits = map[string]ratelimit.RateLimitConfig{
		"*": {
			"command": &ratelimit.ToolRateLimit{MaxRequests: 2, Window: time.Minute},
		},
	}
	return cfg
}

func TestRateLimitExceededDeniesAction(t *testing.T) {
	cfg := rateLimitConfig()
	action := &model.Action{
		Tool:      "command",
		Resource:  "/bin/ls",
		Operation: "exec",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	// First 2 calls pass
	for i := 0; i < 2; i++ {
		result := Evaluate(action, state, "general", "", nil, cfg)
		if result.Decision == model.Deny {
			t.Fatalf("call %d: expected non-Deny, got %s (%s)", i+1, result.Decision, result.Reason)
		}
	}

	// 3rd call denied
	result := Evaluate(action, state, "general", "", nil, cfg)
	if result.Decision != model.Deny {
		t.Errorf("expected Deny for rate limit exceeded, got %s (%s)", result.Decision, result.Reason)
	}
	if result.PolicyID != "ratelimit.*.command_exceeded" {
		t.Errorf("expected ratelimit.*.command_exceeded, got %s", result.PolicyID)
	}
}

func TestRateLimitWithinLimitProceeds(t *testing.T) {
	cfg := rateLimitConfig()
	action := &model.Action{
		Tool:      "command",
		Resource:  "/bin/ls",
		Operation: "exec",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	// Single call within limit proceeds to normal evaluation
	result := Evaluate(action, state, "general", "", nil, cfg)
	if result.Decision == model.Deny {
		t.Errorf("expected non-Deny within rate limit, got %s (%s)", result.Decision, result.Reason)
	}
}

func TestNoRateLimitsNormalEvaluation(t *testing.T) {
	cfg := DefaultConfig() // no rate limits
	action := &model.Action{
		Tool:      "command",
		Resource:  "/bin/ls",
		Operation: "exec",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	// Even with many calls, no rate limit configured means no denial
	for i := 0; i < 100; i++ {
		result := Evaluate(action, state, "general", "", nil, cfg)
		if result.Decision == model.Deny {
			t.Fatalf("call %d: expected non-Deny with no rate limits, got %s", i+1, result.Decision)
		}
	}
}

func TestRateLimitFiresBeforeDenylist(t *testing.T) {
	cfg := rateLimitConfig()

	// Also set up a denylist that would block this resource
	dl := denylist.New(denylist.Patterns{
		Commands: []string{"/bin/ls"},
	})

	action := &model.Action{
		Tool:      "command",
		Resource:  "/bin/ls",
		Operation: "exec",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	// Exhaust rate limit first
	Evaluate(action, state, "general", "", dl, cfg)
	Evaluate(action, state, "general", "", dl, cfg)

	// 3rd call: rate limit fires first (step 0.5), not denylist (step 1)
	result := Evaluate(action, state, "general", "", dl, cfg)
	if result.Decision != model.Deny {
		t.Fatal("expected Deny")
	}
	// Rate limit policyID, not denylist.block
	if result.PolicyID != "ratelimit.*.command_exceeded" {
		t.Errorf("expected rate limit policy ID, got %s (denylist would be 'denylist.block')", result.PolicyID)
	}
}
