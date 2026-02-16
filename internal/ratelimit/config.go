package ratelimit

import "time"

// ToolRateLimit defines the rate limit for a single tool category.
// Zero values mean no limit for that category.
type ToolRateLimit struct {
	MaxRequests int           `yaml:"max_requests"`
	Window      time.Duration `yaml:"window"`
}

// RateLimitConfig maps tool categories to their rate limits for one agent.
type RateLimitConfig map[string]*ToolRateLimit

// HasLimits returns true if any tool category has a configured limit.
func (c RateLimitConfig) HasLimits() bool {
	for _, trl := range c {
		if trl != nil && trl.MaxRequests > 0 && trl.Window > 0 {
			return true
		}
	}
	return false
}
