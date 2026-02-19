package wo

import (
	"strings"
	"testing"
	"time"
)

func validWO() *WorkOrder {
	return &WorkOrder{
		WOVersion:  Version,
		ID:         "wo-test123",
		CreatedAt:  time.Now().UTC(),
		IncidentID: "job-abc",
		Target:     Target{Host: "<<HOST_1>>", Scope: "<<PATH_1>>"},
		Observations: []Observation{
			{Type: SuspiciousCode, Severity: SeverityHigh, Detail: "eval(base64_decode found in <<PATH_2>>"},
		},
		Constraints: Constraints{
			AllowPaths: []string{"<<PATH_1>>"},
			DenyPaths:  []string{"/etc", "/root"},
			MaxSteps:   10,
		},
		ProposedGoals: []string{"remove malicious files"},
		RedactionMode: "local",
	}
}

func TestValidateValid(t *testing.T) {
	if err := Validate(validWO()); err != nil {
		t.Errorf("expected valid WO, got: %v", err)
	}
}

func TestValidateCloudMode(t *testing.T) {
	w := validWO()
	w.RedactionMode = "cloud"
	w.TokenMapRef = "state/tokens/job-abc.json"
	if err := Validate(w); err != nil {
		t.Errorf("expected valid cloud WO, got: %v", err)
	}
}

func TestValidateCloudModeNoTokenRef(t *testing.T) {
	w := validWO()
	w.RedactionMode = "cloud"
	w.TokenMapRef = ""
	err := Validate(w)
	if err == nil {
		t.Fatal("expected validation error for cloud mode without token_map_ref")
	}
	if !strings.Contains(err.Error(), "token_map_ref") {
		t.Errorf("error should mention token_map_ref: %v", err)
	}
}

func TestValidateMissingID(t *testing.T) {
	w := validWO()
	w.ID = ""
	err := Validate(w)
	if err == nil {
		t.Fatal("expected validation error for missing ID")
	}
	if !strings.Contains(err.Error(), "id is required") {
		t.Errorf("error should mention id: %v", err)
	}
}

func TestValidateMissingIncidentID(t *testing.T) {
	w := validWO()
	w.IncidentID = ""
	err := Validate(w)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "incident_id") {
		t.Errorf("error should mention incident_id: %v", err)
	}
}

func TestValidateNoObservations(t *testing.T) {
	w := validWO()
	w.Observations = nil
	err := Validate(w)
	if err == nil {
		t.Fatal("expected validation error for no observations")
	}
	if !strings.Contains(err.Error(), "observation") {
		t.Errorf("error should mention observation: %v", err)
	}
}

func TestValidateInvalidObservationType(t *testing.T) {
	w := validWO()
	w.Observations = []Observation{
		{Type: "bogus_type", Severity: SeverityHigh, Detail: "some detail"},
	}
	err := Validate(w)
	if err == nil {
		t.Fatal("expected validation error for invalid type")
	}
	if !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("error should mention unknown type: %v", err)
	}
}

func TestValidateInvalidSeverity(t *testing.T) {
	w := validWO()
	w.Observations = []Observation{
		{Type: SuspiciousCode, Severity: "urgent", Detail: "some detail"},
	}
	err := Validate(w)
	if err == nil {
		t.Fatal("expected validation error for invalid severity")
	}
	if !strings.Contains(err.Error(), "invalid severity") {
		t.Errorf("error should mention severity: %v", err)
	}
}

func TestValidateEmptyDetail(t *testing.T) {
	w := validWO()
	w.Observations = []Observation{
		{Type: SuspiciousCode, Severity: SeverityHigh, Detail: ""},
	}
	err := Validate(w)
	if err == nil {
		t.Fatal("expected validation error for empty detail")
	}
	if !strings.Contains(err.Error(), "detail is required") {
		t.Errorf("error should mention detail: %v", err)
	}
}

func TestValidateZeroMaxSteps(t *testing.T) {
	w := validWO()
	w.Constraints.MaxSteps = 0
	err := Validate(w)
	if err == nil {
		t.Fatal("expected validation error for zero max_steps")
	}
	if !strings.Contains(err.Error(), "max_steps") {
		t.Errorf("error should mention max_steps: %v", err)
	}
}

func TestValidateNoGoals(t *testing.T) {
	w := validWO()
	w.ProposedGoals = nil
	err := Validate(w)
	if err == nil {
		t.Fatal("expected validation error for no goals")
	}
	if !strings.Contains(err.Error(), "goal") {
		t.Errorf("error should mention goal: %v", err)
	}
}

func TestValidateInvalidRedactionMode(t *testing.T) {
	w := validWO()
	w.RedactionMode = "hybrid"
	err := Validate(w)
	if err == nil {
		t.Fatal("expected validation error for invalid redaction mode")
	}
	if !strings.Contains(err.Error(), "redaction_mode") {
		t.Errorf("error should mention redaction_mode: %v", err)
	}
}

func TestValidateBadVersion(t *testing.T) {
	w := validWO()
	w.WOVersion = "99"
	err := Validate(w)
	if err == nil {
		t.Fatal("expected validation error for bad version")
	}
	if !strings.Contains(err.Error(), "wo_version") {
		t.Errorf("error should mention wo_version: %v", err)
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	w := &WorkOrder{}
	err := Validate(w)
	if err == nil {
		t.Fatal("expected validation errors for empty WO")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	// Empty WO should have many validation errors.
	if len(ve.Errors) < 5 {
		t.Errorf("expected at least 5 validation errors, got %d: %v", len(ve.Errors), ve.Errors)
	}
}

func TestValidateMissingTarget(t *testing.T) {
	w := validWO()
	w.Target.Host = ""
	w.Target.Scope = ""
	err := Validate(w)
	if err == nil {
		t.Fatal("expected validation error for missing target")
	}
	if !strings.Contains(err.Error(), "host") || !strings.Contains(err.Error(), "scope") {
		t.Errorf("error should mention host and scope: %v", err)
	}
}
