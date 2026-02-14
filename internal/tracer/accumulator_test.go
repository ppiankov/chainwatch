package tracer

import (
	"strings"
	"testing"

	"github.com/ppiankov/chainwatch/internal/model"
)

func TestNewTraceIDFormat(t *testing.T) {
	id := NewTraceID()
	if !strings.HasPrefix(id, "t-") {
		t.Errorf("expected t- prefix, got %s", id)
	}
	// t- + 12 hex chars = 14
	if len(id) != 14 {
		t.Errorf("expected length 14, got %d: %s", len(id), id)
	}
}

func TestNewSpanIDFormat(t *testing.T) {
	id := NewSpanID()
	if !strings.HasPrefix(id, "s-") {
		t.Errorf("expected s- prefix, got %s", id)
	}
	// s- + 8 hex chars = 10
	if len(id) != 10 {
		t.Errorf("expected length 10, got %d: %s", len(id), id)
	}
}

func TestAccumulatorStateInitialization(t *testing.T) {
	acc := NewAccumulator("test-123")

	if acc.State.TraceID != "test-123" {
		t.Errorf("expected trace_id=test-123, got %s", acc.State.TraceID)
	}
	if acc.State.Zone != model.Safe {
		t.Errorf("expected Safe zone, got %v", acc.State.Zone)
	}
	if len(acc.Events) != 0 {
		t.Errorf("expected no events, got %d", len(acc.Events))
	}
}

func TestUpdateStateFromAction(t *testing.T) {
	acc := NewAccumulator("test")

	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/report.csv",
		Operation: "read",
		RawMeta: map[string]any{
			"sensitivity": "medium",
			"tags":        []any{"security"},
			"rows":        500,
			"bytes":       10000,
			"egress":      "internal",
		},
	}

	meta := acc.UpdateStateFromAction(action)

	if meta.Sensitivity != model.SensMedium {
		t.Errorf("expected medium, got %s", meta.Sensitivity)
	}
	if acc.State.MaxSensitivity != model.SensMedium {
		t.Errorf("expected state max_sensitivity=medium, got %s", acc.State.MaxSensitivity)
	}
	if acc.State.VolumeRows != 500 {
		t.Errorf("expected 500 rows, got %d", acc.State.VolumeRows)
	}
	if acc.State.VolumeBytes != 10000 {
		t.Errorf("expected 10000 bytes, got %d", acc.State.VolumeBytes)
	}
	if !acc.State.HasSource("file_read") {
		t.Error("expected file_read in seen_sources")
	}
}

func TestSensitivityEscalatesMonotonically(t *testing.T) {
	acc := NewAccumulator("test")

	// Low sensitivity
	acc.UpdateStateFromAction(&model.Action{
		Tool:      "file_read",
		Resource:  "/data/public.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	})
	if acc.State.MaxSensitivity != model.SensLow {
		t.Errorf("expected low, got %s", acc.State.MaxSensitivity)
	}

	// High sensitivity
	acc.UpdateStateFromAction(&model.Action{
		Tool:      "file_read",
		Resource:  "/data/hr/salary.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high"},
	})
	if acc.State.MaxSensitivity != model.SensHigh {
		t.Errorf("expected high, got %s", acc.State.MaxSensitivity)
	}

	// Low again — should stay high
	acc.UpdateStateFromAction(&model.Action{
		Tool:      "file_read",
		Resource:  "/data/readme.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	})
	if acc.State.MaxSensitivity != model.SensHigh {
		t.Errorf("expected high (no retreat), got %s", acc.State.MaxSensitivity)
	}
}

func TestZoneAdvancementInState(t *testing.T) {
	acc := NewAccumulator("test")

	// Read an HR file — should enter SENSITIVE_DATA zone
	acc.UpdateStateFromAction(&model.Action{
		Tool:      "file_read",
		Resource:  "/data/hr/employees.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high"},
	})

	if !acc.State.ZonesEntered[model.ZoneSensitiveData] {
		t.Error("expected SENSITIVE_DATA zone after HR file read")
	}
}

func TestZoneEscalationAcrossActions(t *testing.T) {
	acc := NewAccumulator("test")

	// First: read sensitive data
	acc.UpdateStateFromAction(&model.Action{
		Tool:      "file_read",
		Resource:  "/data/hr/employees.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high"},
	})

	// Second: access an external URL (egress_capable)
	acc.UpdateStateFromAction(&model.Action{
		Tool:      "http",
		Resource:  "https://api.example.com/data",
		Operation: "get",
		RawMeta:   map[string]any{"sensitivity": "low"},
	})

	// Should have both zones accumulated
	if !acc.State.ZonesEntered[model.ZoneSensitiveData] {
		t.Error("expected SENSITIVE_DATA zone")
	}
	if !acc.State.ZonesEntered[model.ZoneEgressCapable] {
		t.Error("expected EGRESS_CAPABLE zone")
	}

	// Combination: sensitive_data + egress_capable → SENSITIVE level
	if acc.State.Zone < model.Sensitive {
		t.Errorf("expected at least Sensitive, got %v", acc.State.Zone)
	}
}

func TestRecordAction(t *testing.T) {
	acc := NewAccumulator("test")

	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/report.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}

	ev := acc.RecordAction(
		map[string]any{"user_id": "test"},
		"SOC_efficiency",
		action,
		map[string]any{"result": "allow"},
		"",
	)

	if len(acc.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(acc.Events))
	}
	if ev.TraceID != "test" {
		t.Errorf("expected trace_id=test, got %s", ev.TraceID)
	}
	if ev.Purpose != "SOC_efficiency" {
		t.Errorf("expected purpose=SOC_efficiency, got %s", ev.Purpose)
	}
}

func TestEventIncludesZoneInfo(t *testing.T) {
	acc := NewAccumulator("test")

	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/hr/employees.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high"},
	}

	ev := acc.RecordAction(
		map[string]any{"user_id": "test"},
		"SOC_efficiency",
		action,
		map[string]any{"result": "allow"},
		"",
	)

	// Event data should include zone information
	if ev.Data["irreversibility_level"] == nil {
		t.Error("expected irreversibility_level in event data")
	}
	if ev.Data["zones_entered"] == nil {
		t.Error("expected zones_entered in event data")
	}
}

func TestToJSON(t *testing.T) {
	acc := NewAccumulator("test-export")

	acc.UpdateStateFromAction(&model.Action{
		Tool:      "file_read",
		Resource:  "/data/hr/salary.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high"},
	})

	snapshot := acc.ToJSON()

	state, ok := snapshot["trace_state"].(map[string]any)
	if !ok {
		t.Fatal("expected trace_state in snapshot")
	}
	if state["trace_id"] != "test-export" {
		t.Errorf("expected trace_id=test-export, got %v", state["trace_id"])
	}
	if state["zone"] == nil {
		t.Error("expected zone in trace_state")
	}
}
