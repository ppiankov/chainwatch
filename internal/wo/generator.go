package wo

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// GeneratorConfig holds parameters for WO generation.
type GeneratorConfig struct {
	IncidentID    string
	Host          string
	Scope         string
	RedactionMode string   // "local" or "cloud"
	TokenMapRef   string   // path to token map file (cloud mode)
	MaxSteps      int      // default 10
	AllowPaths    []string // paths the remediation agent may touch
	DenyPaths     []string // paths the remediation agent must not touch
	Network       bool     // whether network access is allowed
	Sudo          bool     // whether sudo is allowed
}

// Generate creates a new WorkOrder from observations and config.
func Generate(cfg GeneratorConfig, observations []Observation, goals []string) (*WorkOrder, error) {
	if cfg.IncidentID == "" {
		return nil, fmt.Errorf("incident_id is required")
	}
	if cfg.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if cfg.Scope == "" {
		return nil, fmt.Errorf("scope is required")
	}
	if len(observations) == 0 {
		return nil, fmt.Errorf("at least one observation is required")
	}
	if len(goals) == 0 {
		return nil, fmt.Errorf("at least one goal is required")
	}

	maxSteps := cfg.MaxSteps
	if maxSteps <= 0 {
		maxSteps = 10
	}

	woID, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("generate ID: %w", err)
	}

	w := &WorkOrder{
		WOVersion:  Version,
		ID:         woID,
		CreatedAt:  time.Now().UTC(),
		IncidentID: cfg.IncidentID,
		Target: Target{
			Host:  cfg.Host,
			Scope: cfg.Scope,
		},
		Observations: observations,
		Constraints: Constraints{
			AllowPaths: cfg.AllowPaths,
			DenyPaths:  cfg.DenyPaths,
			Network:    cfg.Network,
			Sudo:       cfg.Sudo,
			MaxSteps:   maxSteps,
		},
		ProposedGoals: goals,
		RedactionMode: cfg.RedactionMode,
		TokenMapRef:   cfg.TokenMapRef,
	}

	if err := Validate(w); err != nil {
		return nil, fmt.Errorf("generated WO is invalid: %w", err)
	}

	return w, nil
}

// generateID creates a random WO ID like "wo-a1b2c3d4".
func generateID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "wo-" + hex.EncodeToString(b), nil
}
