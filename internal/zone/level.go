package zone

import "github.com/ppiankov/chainwatch/internal/model"

// zoneSet is a helper type for zone combination keys.
type zoneSet []model.Zone

// irreversibilityRule maps a required zone combination to an irreversibility level.
type irreversibilityRule struct {
	Required []model.Zone
	Level    model.BoundaryZone
}

// IrreversibilityRules defines the zone combination → irreversibility level mappings.
// If all zones in Required are present in the accumulated set, the level applies.
// The highest matching level wins (monotonic).
var IrreversibilityRules = []irreversibilityRule{
	// Payment boundaries — commercial commitment alone is irreversible
	{Required: []model.Zone{model.ZoneCommercialCommitment}, Level: model.Irreversible},

	// Credential exfiltration — exposed credentials + active egress
	{Required: []model.Zone{model.ZoneCredentialExposed, model.ZoneEgressActive}, Level: model.Irreversible},

	// High-volume exfiltration — sensitive data + high volume + active egress
	{Required: []model.Zone{model.ZoneSensitiveData, model.ZoneHighVolume, model.ZoneEgressActive}, Level: model.Irreversible},

	// Commitment zone — commercial intent + commitment (shopping → checkout)
	{Required: []model.Zone{model.ZoneCommercialIntent, model.ZoneCommercialCommitment}, Level: model.Commitment},

	// Credential proximity + network = elevated risk
	{Required: []model.Zone{model.ZoneCredentialAdjacent, model.ZoneEgressCapable}, Level: model.Commitment},

	// Sensitive data + network = elevated risk
	{Required: []model.Zone{model.ZoneSensitiveData, model.ZoneEgressCapable}, Level: model.Sensitive},
}

// ComputeIrreversibilityLevel computes the highest irreversibility level
// for a given set of accumulated zones.
//
// INVARIANT: Adding zones can only increase level, never decrease.
func ComputeIrreversibilityLevel(zones map[model.Zone]bool) model.BoundaryZone {
	maxLevel := model.Safe

	for _, rule := range IrreversibilityRules {
		if allPresent(zones, rule.Required) && rule.Level > maxLevel {
			maxLevel = rule.Level
		}
	}

	return maxLevel
}

func allPresent(zones map[model.Zone]bool, required []model.Zone) bool {
	for _, z := range required {
		if !zones[z] {
			return false
		}
	}
	return true
}
