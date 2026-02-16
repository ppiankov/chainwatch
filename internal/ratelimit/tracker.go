package ratelimit

import (
	"time"

	"github.com/ppiankov/chainwatch/internal/model"
)

// Snapshot reads the current tool call count for a given category from TraceState.
// If the window has expired, all counters and the window start are reset.
func Snapshot(state *model.TraceState, toolCategory string, window time.Duration, now time.Time) int {
	if state.ToolCallCounts == nil {
		state.ToolCallCounts = make(map[string]int)
	}
	if now.Sub(state.RateLimitWindowStart) >= window {
		state.ToolCallCounts = make(map[string]int)
		state.RateLimitWindowStart = now
	}
	return state.ToolCallCounts[toolCategory]
}

// Increment records a tool call for the given category.
func Increment(state *model.TraceState, toolCategory string) {
	if state.ToolCallCounts == nil {
		state.ToolCallCounts = make(map[string]int)
	}
	state.ToolCallCounts[toolCategory]++
}
