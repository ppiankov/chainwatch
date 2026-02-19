package wo

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateValid(t *testing.T) {
	cfg := GeneratorConfig{
		IncidentID:    "job-test",
		Host:          "<<HOST_1>>",
		Scope:         "<<PATH_1>>",
		RedactionMode: "local",
		MaxSteps:      8,
		AllowPaths:    []string{"<<PATH_1>>"},
		DenyPaths:     []string{"/etc"},
	}

	obs := []Observation{
		{Type: SuspiciousCode, Severity: SeverityHigh, Detail: "eval(base64_decode in <<PATH_2>>"},
		{Type: UnauthorizedUser, Severity: SeverityCritical, Detail: "rogue user wpadmin2"},
	}

	goals := []string{"remove malicious files", "remove unauthorized user"}

	w, err := Generate(cfg, obs, goals)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	if w.WOVersion != Version {
		t.Errorf("version: got %s, want %s", w.WOVersion, Version)
	}
	if !strings.HasPrefix(w.ID, "wo-") {
		t.Errorf("ID should start with wo-: %s", w.ID)
	}
	if w.IncidentID != "job-test" {
		t.Errorf("incident_id: got %s, want job-test", w.IncidentID)
	}
	if len(w.Observations) != 2 {
		t.Errorf("observations: got %d, want 2", len(w.Observations))
	}
	if w.Constraints.MaxSteps != 8 {
		t.Errorf("max_steps: got %d, want 8", w.Constraints.MaxSteps)
	}
	if w.RedactionMode != "local" {
		t.Errorf("redaction_mode: got %s, want local", w.RedactionMode)
	}
}

func TestGenerateCloudMode(t *testing.T) {
	cfg := GeneratorConfig{
		IncidentID:    "job-cloud",
		Host:          "<<HOST_1>>",
		Scope:         "<<PATH_1>>",
		RedactionMode: "cloud",
		TokenMapRef:   "state/tokens/job-cloud.json",
		AllowPaths:    []string{"<<PATH_1>>"},
	}

	obs := []Observation{
		{Type: RedirectDetected, Severity: SeverityHigh, Detail: "mobile redirect to casino domain"},
	}

	w, err := Generate(cfg, obs, []string{"remove redirect"})
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	if w.RedactionMode != "cloud" {
		t.Error("expected cloud mode")
	}
	if w.TokenMapRef != "state/tokens/job-cloud.json" {
		t.Error("token_map_ref not set")
	}
}

func TestGenerateDefaultMaxSteps(t *testing.T) {
	cfg := GeneratorConfig{
		IncidentID:    "job-default",
		Host:          "<<HOST_1>>",
		Scope:         "<<PATH_1>>",
		RedactionMode: "local",
		// MaxSteps not set — should default to 10.
	}

	obs := []Observation{
		{Type: CronAnomaly, Severity: SeverityMedium, Detail: "suspicious cron entry"},
	}

	w, err := Generate(cfg, obs, []string{"remove cron entry"})
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	if w.Constraints.MaxSteps != 10 {
		t.Errorf("default max_steps: got %d, want 10", w.Constraints.MaxSteps)
	}
}

func TestGenerateMissingHost(t *testing.T) {
	cfg := GeneratorConfig{
		IncidentID:    "job-test",
		Scope:         "<<PATH_1>>",
		RedactionMode: "local",
	}
	obs := []Observation{{Type: SuspiciousCode, Severity: SeverityHigh, Detail: "test"}}

	_, err := Generate(cfg, obs, []string{"fix"})
	if err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestGenerateNoObservations(t *testing.T) {
	cfg := GeneratorConfig{
		IncidentID:    "job-test",
		Host:          "<<HOST_1>>",
		Scope:         "<<PATH_1>>",
		RedactionMode: "local",
	}

	_, err := Generate(cfg, nil, []string{"fix"})
	if err == nil {
		t.Fatal("expected error for no observations")
	}
}

func TestGenerateNoGoals(t *testing.T) {
	cfg := GeneratorConfig{
		IncidentID:    "job-test",
		Host:          "<<HOST_1>>",
		Scope:         "<<PATH_1>>",
		RedactionMode: "local",
	}
	obs := []Observation{{Type: SuspiciousCode, Severity: SeverityHigh, Detail: "test"}}

	_, err := Generate(cfg, obs, nil)
	if err == nil {
		t.Fatal("expected error for no goals")
	}
}

func TestGenerateUniqueIDs(t *testing.T) {
	cfg := GeneratorConfig{
		IncidentID:    "job-test",
		Host:          "<<HOST_1>>",
		Scope:         "<<PATH_1>>",
		RedactionMode: "local",
	}
	obs := []Observation{{Type: SuspiciousCode, Severity: SeverityHigh, Detail: "test"}}
	goals := []string{"fix"}

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		w, err := Generate(cfg, obs, goals)
		if err != nil {
			t.Fatalf("generate failed on iteration %d: %v", i, err)
		}
		if ids[w.ID] {
			t.Fatalf("duplicate ID on iteration %d: %s", i, w.ID)
		}
		ids[w.ID] = true
	}
}

func TestGenerateJSONRoundTrip(t *testing.T) {
	cfg := GeneratorConfig{
		IncidentID:    "job-json",
		Host:          "<<HOST_1>>",
		Scope:         "<<PATH_1>>",
		RedactionMode: "cloud",
		TokenMapRef:   "state/tokens/job-json.json",
		MaxSteps:      6,
		AllowPaths:    []string{"<<PATH_1>>"},
		DenyPaths:     []string{"/etc", "/root"},
	}

	obs := []Observation{
		{
			Type:     FileHashMismatch,
			Severity: SeverityHigh,
			Detail:   "header.php hash mismatch",
			Data:     map[string]interface{}{"expected": "sha256:abc", "actual": "sha256:def"},
		},
		{
			Type:     UnauthorizedUser,
			Severity: SeverityCritical,
			Detail:   "rogue admin wpadmin2",
			Data:     map[string]interface{}{"username": "wpadmin2", "uid": float64(0)},
		},
	}

	goals := []string{"restore header.php", "remove wpadmin2"}

	w, err := Generate(cfg, obs, goals)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var w2 WorkOrder
	if err := json.Unmarshal(data, &w2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if w2.ID != w.ID {
		t.Errorf("ID mismatch: %s vs %s", w2.ID, w.ID)
	}
	if len(w2.Observations) != 2 {
		t.Errorf("observations count: got %d, want 2", len(w2.Observations))
	}
	if w2.Constraints.MaxSteps != 6 {
		t.Errorf("max_steps: got %d, want 6", w2.Constraints.MaxSteps)
	}
	if w2.RedactionMode != "cloud" {
		t.Errorf("redaction_mode: got %s, want cloud", w2.RedactionMode)
	}

	// Validate deserialized WO.
	if err := Validate(&w2); err != nil {
		t.Errorf("deserialized WO is invalid: %v", err)
	}
}
