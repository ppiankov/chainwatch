package model

import "testing"

func TestNewTraceStateDefaults(t *testing.T) {
	state := NewTraceState("test-123")

	if state.TraceID != "test-123" {
		t.Errorf("expected trace_id=test-123, got %s", state.TraceID)
	}
	if state.Zone != Safe {
		t.Errorf("expected zone=Safe, got %v", state.Zone)
	}
	if len(state.ZonesEntered) != 0 {
		t.Errorf("expected empty zones_entered, got %v", state.ZonesEntered)
	}
	if state.MaxSensitivity != SensLow {
		t.Errorf("expected max_sensitivity=low, got %s", state.MaxSensitivity)
	}
	if state.Egress != EgressInternal {
		t.Errorf("expected egress=internal, got %s", state.Egress)
	}
}

func TestEscalateLevelMonotonic(t *testing.T) {
	state := NewTraceState("test")

	// Advance to Sensitive
	state.EscalateLevel(Sensitive)
	if state.Zone != Sensitive {
		t.Errorf("expected Sensitive, got %v", state.Zone)
	}

	// Try to retreat to Safe — should be no-op
	state.EscalateLevel(Safe)
	if state.Zone != Sensitive {
		t.Errorf("expected Sensitive (no retreat), got %v", state.Zone)
	}

	// Advance to Commitment
	state.EscalateLevel(Commitment)
	if state.Zone != Commitment {
		t.Errorf("expected Commitment, got %v", state.Zone)
	}

	// Advance to Irreversible
	state.EscalateLevel(Irreversible)
	if state.Zone != Irreversible {
		t.Errorf("expected Irreversible, got %v", state.Zone)
	}

	// Try to retreat — should stay at Irreversible
	state.EscalateLevel(Safe)
	if state.Zone != Irreversible {
		t.Errorf("expected Irreversible (no retreat), got %v", state.Zone)
	}
}

func TestResultMetaFromMapDefensive(t *testing.T) {
	// nil map → safe defaults
	rm := ResultMetaFromMap(nil)
	if rm.Sensitivity != SensLow {
		t.Errorf("expected low, got %s", rm.Sensitivity)
	}
	if rm.Egress != EgressInternal {
		t.Errorf("expected internal, got %s", rm.Egress)
	}

	// Invalid sensitivity → defaults to low
	rm = ResultMetaFromMap(map[string]any{"sensitivity": "invalid"})
	if rm.Sensitivity != SensLow {
		t.Errorf("expected low for invalid, got %s", rm.Sensitivity)
	}

	// Valid values
	rm = ResultMetaFromMap(map[string]any{
		"sensitivity": "high",
		"egress":      "external",
		"rows":        1000,
		"bytes":       5000,
		"tags":        []any{"PII", "HR"},
		"destination": "api.example.com",
	})
	if rm.Sensitivity != SensHigh {
		t.Errorf("expected high, got %s", rm.Sensitivity)
	}
	if rm.Egress != EgressExternal {
		t.Errorf("expected external, got %s", rm.Egress)
	}
	if rm.Rows != 1000 {
		t.Errorf("expected 1000 rows, got %d", rm.Rows)
	}
	if len(rm.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(rm.Tags))
	}
}

func TestHasSource(t *testing.T) {
	state := NewTraceState("test")
	state.SeenSources = append(state.SeenSources, "file_read")

	if !state.HasSource("file_read") {
		t.Error("expected HasSource(file_read) to be true")
	}
	if state.HasSource("http") {
		t.Error("expected HasSource(http) to be false")
	}
}

func TestBoundaryZoneString(t *testing.T) {
	tests := []struct {
		zone BoundaryZone
		want string
	}{
		{Safe, "SAFE"},
		{Sensitive, "SENSITIVE"},
		{Commitment, "COMMITMENT"},
		{Irreversible, "IRREVERSIBLE"},
	}
	for _, tt := range tests {
		if got := tt.zone.String(); got != tt.want {
			t.Errorf("BoundaryZone(%d).String() = %q, want %q", tt.zone, got, tt.want)
		}
	}
}

func TestInstructionContextCrossesTrustBoundary(t *testing.T) {
	// Direct user — no crossing
	ctx := InstructionContext{Origin: "direct_user_interface"}
	if ctx.CrossesTrustBoundary() {
		t.Error("direct_user_interface should not cross trust boundary")
	}

	// Proxied — crosses
	ctx = InstructionContext{Origin: "direct_user_interface", IsProxied: true}
	if !ctx.CrossesTrustBoundary() {
		t.Error("proxied should cross trust boundary")
	}

	// Network origin — crosses
	ctx = InstructionContext{Origin: "network"}
	if !ctx.CrossesTrustBoundary() {
		t.Error("network origin should cross trust boundary")
	}
}

func TestActionNormalizeMeta(t *testing.T) {
	action := Action{
		Tool:      "file_read",
		Resource:  "/tmp/test.csv",
		Operation: "read",
		RawMeta: map[string]any{
			"sensitivity": "high",
			"tags":        []any{"HR"},
		},
	}

	action.NormalizeMeta()
	meta := action.NormalizedMeta()

	if meta.Sensitivity != SensHigh {
		t.Errorf("expected high, got %s", meta.Sensitivity)
	}
	if len(meta.Tags) != 1 || meta.Tags[0] != "HR" {
		t.Errorf("expected [HR], got %v", meta.Tags)
	}
}
