package budget

import "time"

// BudgetConfig defines per-session resource limits for an agent.
// Zero values mean unlimited (no enforcement for that dimension).
type BudgetConfig struct {
	MaxBytes    int64         `yaml:"max_bytes"`
	MaxRows     int64         `yaml:"max_rows"`
	MaxDuration time.Duration `yaml:"max_duration"`
}

// HasLimits returns true if any limit is configured (non-zero).
func (b BudgetConfig) HasLimits() bool {
	return b.MaxBytes > 0 || b.MaxRows > 0 || b.MaxDuration > 0
}
