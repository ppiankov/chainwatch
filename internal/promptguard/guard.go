package promptguard

import (
	"context"
	"time"
)

// Decision is the classification result.
type Decision string

const (
	Benign      Decision = "benign"
	Malicious   Decision = "malicious"
	Unavailable Decision = "unavailable"
)

// Result holds the classification output.
type Result struct {
	Decision Decision `json:"decision"`
	Score    float64  `json:"score,omitempty"`
	Model    string   `json:"model,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// Config controls the guard behavior.
type Config struct {
	Enabled       bool          `yaml:"enabled"`
	Model         string        `yaml:"model"`          // "22m" or "86m"
	Python        string        `yaml:"python"`         // path to python binary
	Timeout       time.Duration `yaml:"timeout"`        // per-classification timeout
	OnUnavailable string        `yaml:"on_unavailable"` // "warn" or "deny"
	ScriptPath    string        `yaml:"script_path"`    // override path to classify.py
}

// DefaultConfig returns a config with guard disabled.
func DefaultConfig() Config {
	return Config{
		Enabled:       false,
		Model:         "22m",
		Python:        "python3",
		Timeout:       5 * time.Second,
		OnUnavailable: "warn",
	}
}

// Guard classifies text inputs for prompt injection.
type Guard interface {
	// Classify returns the classification decision for the given text.
	Classify(ctx context.Context, text string) (Result, error)

	// Available reports whether the guard runtime is present.
	Available() bool
}

// New creates a Guard based on config. Returns NoopGuard if disabled.
func New(cfg Config) Guard {
	if !cfg.Enabled {
		return &NoopGuard{}
	}
	return NewPythonRunner(cfg)
}
