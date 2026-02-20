// Package ingest defines the IngestPayload — the handoff artifact between
// nullbot (local observer) and runforge (cloud executor). The payload is a
// strict subset of a WorkOrder: it strips raw evidence data so that cloud
// agents only see typed observations, not raw command output.
package ingest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ppiankov/chainwatch/internal/wo"
)

// PayloadVersion is the current IngestPayload schema version.
const PayloadVersion = "1"

// IngestPayload is the handoff from nullbot approve to runforge ingest.
type IngestPayload struct {
	Version       string              `json:"version"`
	WOID          string              `json:"wo_id"`
	IncidentID    string              `json:"incident_id"`
	CreatedAt     time.Time           `json:"created_at"`
	ApprovedAt    time.Time           `json:"approved_at"`
	Target        IngestTarget        `json:"target"`
	Observations  []IngestObservation `json:"observations"`
	Constraints   IngestConstraints   `json:"constraints"`
	ProposedGoals []string            `json:"proposed_goals"`
}

// IngestTarget identifies the system under remediation.
type IngestTarget struct {
	Host  string `json:"host"`
	Scope string `json:"scope"`
}

// IngestObservation is a finding stripped of raw evidence data.
type IngestObservation struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

// IngestConstraints define what the remediation agent is allowed to do.
type IngestConstraints struct {
	AllowPaths []string `json:"allow_paths"`
	DenyPaths  []string `json:"deny_paths"`
	Network    bool     `json:"network"`
	Sudo       bool     `json:"sudo"`
	MaxSteps   int      `json:"max_steps"`
}

// Build creates an IngestPayload from an approved WorkOrder.
// It strips raw evidence data (Observation.Data) and populates ApprovedAt.
func Build(w *wo.WorkOrder) *IngestPayload {
	obs := make([]IngestObservation, len(w.Observations))
	for i, o := range w.Observations {
		obs[i] = IngestObservation{
			Type:     string(o.Type),
			Severity: string(o.Severity),
			Detail:   o.Detail,
		}
	}
	return &IngestPayload{
		Version:    PayloadVersion,
		WOID:       w.ID,
		IncidentID: w.IncidentID,
		CreatedAt:  w.CreatedAt,
		ApprovedAt: time.Now().UTC(),
		Target: IngestTarget{
			Host:  w.Target.Host,
			Scope: w.Target.Scope,
		},
		Observations:  obs,
		Constraints:   constraintsFromWO(w.Constraints),
		ProposedGoals: w.ProposedGoals,
	}
}

// constraintsFromWO converts WO constraints to ingest constraints.
func constraintsFromWO(c wo.Constraints) IngestConstraints {
	return IngestConstraints{
		AllowPaths: c.AllowPaths,
		DenyPaths:  c.DenyPaths,
		Network:    c.Network,
		Sudo:       c.Sudo,
		MaxSteps:   c.MaxSteps,
	}
}

// Validate checks that a payload has all required fields.
func Validate(p *IngestPayload) error {
	if p.WOID == "" {
		return fmt.Errorf("wo_id is required")
	}
	if p.IncidentID == "" {
		return fmt.Errorf("incident_id is required")
	}
	if p.Target.Host == "" {
		return fmt.Errorf("target host is required")
	}
	if p.Target.Scope == "" {
		return fmt.Errorf("target scope is required")
	}
	if len(p.Observations) == 0 {
		return fmt.Errorf("at least one observation is required")
	}
	if len(p.ProposedGoals) == 0 {
		return fmt.Errorf("at least one proposed goal is required")
	}
	return nil
}

// Write atomically writes a payload to dir/{wo_id}.json.
func Write(p *IngestPayload, dir string) error {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	dst := filepath.Join(dir, p.WOID+".json")
	tmp := dst + ".tmp"

	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename to final: %w", err)
	}
	return nil
}
