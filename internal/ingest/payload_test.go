package ingest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ppiankov/chainwatch/internal/wo"
)

func testWO() *wo.WorkOrder {
	return &wo.WorkOrder{
		WOVersion:  wo.Version,
		ID:         "wo-a1b2c3d4",
		CreatedAt:  time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC),
		IncidentID: "job-001",
		Target: wo.Target{
			Host:  "web-01.example.com",
			Scope: "/var/www/site",
		},
		Observations: []wo.Observation{
			{
				Type:     wo.SuspiciousCode,
				Severity: wo.SeverityHigh,
				Detail:   "eval/base64_decode found in wp-content/mu-plugins/loader.php",
				Data:     map[string]interface{}{"file": "/var/www/site/wp-content/mu-plugins/loader.php", "line": 42},
			},
			{
				Type:     wo.FileHashMismatch,
				Severity: wo.SeverityMedium,
				Detail:   "wp-login.php modified from upstream hash",
				Data:     map[string]interface{}{"expected_hash": "abc123", "actual_hash": "def456"},
			},
		},
		Constraints: wo.Constraints{
			AllowPaths: []string{"/var/www/site"},
			DenyPaths:  []string{"/etc", "/root"},
			Network:    false,
			Sudo:       false,
			MaxSteps:   10,
		},
		ProposedGoals: []string{
			"Investigate and remediate: eval/base64_decode found in mu-plugins",
			"Investigate and remediate: wp-login.php modified from upstream hash",
		},
		RedactionMode: "local",
	}
}

func TestBuildStripsData(t *testing.T) {
	w := testWO()
	p := Build(w)

	for i, obs := range p.Observations {
		// IngestObservation has no Data field — verify the JSON lacks it.
		data, _ := json.Marshal(obs)
		var m map[string]interface{}
		_ = json.Unmarshal(data, &m)
		if _, hasData := m["data"]; hasData {
			t.Errorf("observation %d should not have 'data' field", i)
		}
	}
}

func TestBuildPreservesFields(t *testing.T) {
	w := testWO()
	p := Build(w)

	if p.Version != PayloadVersion {
		t.Errorf("Version = %q, want %q", p.Version, PayloadVersion)
	}
	if p.WOID != w.ID {
		t.Errorf("WOID = %q, want %q", p.WOID, w.ID)
	}
	if p.IncidentID != w.IncidentID {
		t.Errorf("IncidentID = %q, want %q", p.IncidentID, w.IncidentID)
	}
	if p.Target.Host != w.Target.Host {
		t.Errorf("Target.Host = %q, want %q", p.Target.Host, w.Target.Host)
	}
	if p.Target.Scope != w.Target.Scope {
		t.Errorf("Target.Scope = %q, want %q", p.Target.Scope, w.Target.Scope)
	}
	if len(p.Observations) != len(w.Observations) {
		t.Fatalf("Observations count = %d, want %d", len(p.Observations), len(w.Observations))
	}
	if p.Observations[0].Type != string(w.Observations[0].Type) {
		t.Errorf("Observations[0].Type = %q, want %q", p.Observations[0].Type, w.Observations[0].Type)
	}
	if p.Observations[0].Severity != string(w.Observations[0].Severity) {
		t.Errorf("Observations[0].Severity = %q, want %q", p.Observations[0].Severity, w.Observations[0].Severity)
	}
	if p.Observations[0].Detail != w.Observations[0].Detail {
		t.Errorf("Observations[0].Detail mismatch")
	}
	if p.Constraints.MaxSteps != w.Constraints.MaxSteps {
		t.Errorf("Constraints.MaxSteps = %d, want %d", p.Constraints.MaxSteps, w.Constraints.MaxSteps)
	}
	if p.Constraints.Network != w.Constraints.Network {
		t.Errorf("Constraints.Network = %v, want %v", p.Constraints.Network, w.Constraints.Network)
	}
	if p.Constraints.Sudo != w.Constraints.Sudo {
		t.Errorf("Constraints.Sudo = %v, want %v", p.Constraints.Sudo, w.Constraints.Sudo)
	}
	if len(p.ProposedGoals) != len(w.ProposedGoals) {
		t.Errorf("ProposedGoals count = %d, want %d", len(p.ProposedGoals), len(w.ProposedGoals))
	}
	if p.ApprovedAt.IsZero() {
		t.Error("ApprovedAt should be set")
	}
}

func TestWriteRoundTrip(t *testing.T) {
	w := testWO()
	p := Build(w)

	dir := t.TempDir()
	if err := Write(p, dir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	path := filepath.Join(dir, p.WOID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}

	var loaded IngestPayload
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if loaded.WOID != p.WOID {
		t.Errorf("loaded WOID = %q, want %q", loaded.WOID, p.WOID)
	}
	if loaded.IncidentID != p.IncidentID {
		t.Errorf("loaded IncidentID = %q, want %q", loaded.IncidentID, p.IncidentID)
	}
	if len(loaded.Observations) != len(p.Observations) {
		t.Errorf("loaded Observations count = %d, want %d", len(loaded.Observations), len(p.Observations))
	}
}

func TestWriteAtomicNoTmpLeftover(t *testing.T) {
	w := testWO()
	p := Build(w)

	dir := t.TempDir()
	if err := Write(p, dir); err != nil {
		t.Fatal(err)
	}

	// No .tmp file should remain.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*IngestPayload)
		wantErr string
	}{
		{"valid", func(p *IngestPayload) {}, ""},
		{"missing wo_id", func(p *IngestPayload) { p.WOID = "" }, "wo_id is required"},
		{"missing incident_id", func(p *IngestPayload) { p.IncidentID = "" }, "incident_id is required"},
		{"missing host", func(p *IngestPayload) { p.Target.Host = "" }, "target host is required"},
		{"missing scope", func(p *IngestPayload) { p.Target.Scope = "" }, "target scope is required"},
		{"no observations", func(p *IngestPayload) { p.Observations = nil }, "at least one observation is required"},
		{"no goals", func(p *IngestPayload) { p.ProposedGoals = nil }, "at least one proposed goal is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Build(testWO())
			tt.modify(p)
			err := Validate(p)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q", tt.wantErr)
				} else if err.Error() != tt.wantErr {
					t.Errorf("error = %q, want %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}
