package zone

import (
	"testing"

	"github.com/ppiankov/chainwatch/internal/model"
)

func TestComputeIrreversibilityLevelSafe(t *testing.T) {
	zones := map[model.Zone]bool{}
	level := ComputeIrreversibilityLevel(zones)
	if level != model.Safe {
		t.Errorf("expected Safe for no zones, got %v", level)
	}
}

func TestComputeIrreversibilityLevelSensitive(t *testing.T) {
	zones := map[model.Zone]bool{
		model.ZoneSensitiveData: true,
		model.ZoneEgressCapable: true,
	}
	level := ComputeIrreversibilityLevel(zones)
	if level != model.Sensitive {
		t.Errorf("expected Sensitive for sensitive_data+egress_capable, got %v", level)
	}
}

func TestComputeIrreversibilityLevelCommitmentCredentials(t *testing.T) {
	zones := map[model.Zone]bool{
		model.ZoneCredentialAdjacent: true,
		model.ZoneEgressCapable:      true,
	}
	level := ComputeIrreversibilityLevel(zones)
	if level != model.Commitment {
		t.Errorf("expected Commitment for credential_adjacent+egress_capable, got %v", level)
	}
}

func TestComputeIrreversibilityLevelCommitmentCommercial(t *testing.T) {
	zones := map[model.Zone]bool{
		model.ZoneCommercialIntent:     true,
		model.ZoneCommercialCommitment: true,
	}
	level := ComputeIrreversibilityLevel(zones)
	// CommercialCommitment alone → Irreversible (highest rule matches)
	if level != model.Irreversible {
		t.Errorf("expected Irreversible for commercial_intent+commercial_commit, got %v", level)
	}
}

func TestComputeIrreversibilityLevelIrreversiblePayment(t *testing.T) {
	zones := map[model.Zone]bool{
		model.ZoneCommercialCommitment: true,
	}
	level := ComputeIrreversibilityLevel(zones)
	if level != model.Irreversible {
		t.Errorf("expected Irreversible for commercial_commit alone, got %v", level)
	}
}

func TestComputeIrreversibilityLevelIrreversibleExfiltration(t *testing.T) {
	zones := map[model.Zone]bool{
		model.ZoneCredentialExposed: true,
		model.ZoneEgressActive:      true,
	}
	level := ComputeIrreversibilityLevel(zones)
	if level != model.Irreversible {
		t.Errorf("expected Irreversible for credential_exposed+egress_active, got %v", level)
	}
}

func TestComputeIrreversibilityLevelIrreversibleHighVolumeExfil(t *testing.T) {
	zones := map[model.Zone]bool{
		model.ZoneSensitiveData: true,
		model.ZoneHighVolume:    true,
		model.ZoneEgressActive:  true,
	}
	level := ComputeIrreversibilityLevel(zones)
	if level != model.Irreversible {
		t.Errorf("expected Irreversible for sensitive+high_volume+egress_active, got %v", level)
	}
}

func TestMonotonicityInvariant(t *testing.T) {
	// Adding zones can only increase level, never decrease
	zones := map[model.Zone]bool{
		model.ZoneSensitiveData: true,
		model.ZoneEgressCapable: true,
	}
	level1 := ComputeIrreversibilityLevel(zones)
	if level1 != model.Sensitive {
		t.Fatalf("expected Sensitive, got %v", level1)
	}

	// Adding a "safe" zone (commercial_intent) — level should not decrease
	zones[model.ZoneCommercialIntent] = true
	level2 := ComputeIrreversibilityLevel(zones)
	if level2 < level1 {
		t.Errorf("monotonicity violated: %v < %v after adding zone", level2, level1)
	}

	// Adding credential_adjacent elevates to Commitment
	zones[model.ZoneCredentialAdjacent] = true
	level3 := ComputeIrreversibilityLevel(zones)
	if level3 < level2 {
		t.Errorf("monotonicity violated: %v < %v after adding credential_adjacent", level3, level2)
	}
	if level3 < model.Commitment {
		t.Errorf("expected at least Commitment, got %v", level3)
	}
}
