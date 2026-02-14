package zone

import (
	"testing"

	"github.com/ppiankov/chainwatch/internal/model"
)

func TestDetectZonesSensitiveData(t *testing.T) {
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/hr/employees.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "high"},
	}
	state := model.NewTraceState("test")

	zones := DetectZones(action, state)

	if !zones[model.ZoneSensitiveData] {
		t.Error("expected SENSITIVE_DATA zone for HR file")
	}
}

func TestDetectZonesCredentialAdjacent(t *testing.T) {
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/home/user/.env",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	zones := DetectZones(action, state)

	if !zones[model.ZoneCredentialAdjacent] {
		t.Error("expected CREDENTIAL_ADJACENT zone for .env file")
	}
	// Reading a credential-adjacent file also triggers CREDENTIAL_EXPOSED
	if !zones[model.ZoneCredentialExposed] {
		t.Error("expected CREDENTIAL_EXPOSED zone for .env read")
	}
}

func TestDetectZonesCredentialAdjacentSSH(t *testing.T) {
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/home/user/.ssh/id_rsa",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	zones := DetectZones(action, state)

	if !zones[model.ZoneCredentialAdjacent] {
		t.Error("expected CREDENTIAL_ADJACENT for .ssh file")
	}
	if !zones[model.ZoneCredentialExposed] {
		t.Error("expected CREDENTIAL_EXPOSED for .ssh file read")
	}
}

func TestDetectZonesCommercialCommitment(t *testing.T) {
	action := &model.Action{
		Tool:      "browser",
		Resource:  "https://store.example.com/checkout",
		Operation: "navigate",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	zones := DetectZones(action, state)

	if !zones[model.ZoneCommercialCommitment] {
		t.Error("expected COMMERCIAL_COMMITMENT for checkout URL")
	}
}

func TestDetectZonesCommercialIntent(t *testing.T) {
	action := &model.Action{
		Tool:      "browser",
		Resource:  "https://store.example.com/products",
		Operation: "navigate",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	zones := DetectZones(action, state)

	if !zones[model.ZoneCommercialIntent] {
		t.Error("expected COMMERCIAL_INTENT for products URL")
	}
}

func TestDetectZonesEgressCapable(t *testing.T) {
	action := &model.Action{
		Tool:      "http",
		Resource:  "https://api.example.com/data",
		Operation: "get",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	zones := DetectZones(action, state)

	if !zones[model.ZoneEgressCapable] {
		t.Error("expected EGRESS_CAPABLE for https URL")
	}
}

func TestDetectZonesEgressActive(t *testing.T) {
	action := &model.Action{
		Tool:      "http",
		Resource:  "https://api.example.com/data",
		Operation: "post",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	zones := DetectZones(action, state)

	if !zones[model.ZoneEgressActive] {
		t.Error("expected EGRESS_ACTIVE for POST to external URL")
	}
}

func TestDetectZonesHighVolume(t *testing.T) {
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/big_dump.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low", "bytes": 5_000_000},
	}
	// State already has 6MB accumulated
	state := model.NewTraceState("test")
	state.VolumeBytes = 6_000_000

	zones := DetectZones(action, state)

	if !zones[model.ZoneHighVolume] {
		t.Error("expected HIGH_VOLUME zone when total exceeds 10MB")
	}
}

func TestDetectZonesHighVolumeNotTriggered(t *testing.T) {
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/small.csv",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low", "bytes": 1000},
	}
	state := model.NewTraceState("test")

	zones := DetectZones(action, state)

	if zones[model.ZoneHighVolume] {
		t.Error("expected no HIGH_VOLUME zone for small file")
	}
}

func TestDetectZonesSafeAction(t *testing.T) {
	action := &model.Action{
		Tool:      "file_read",
		Resource:  "/data/public/readme.txt",
		Operation: "read",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	state := model.NewTraceState("test")

	zones := DetectZones(action, state)

	if len(zones) != 0 {
		t.Errorf("expected no zones for safe action, got %v", zones)
	}
}
