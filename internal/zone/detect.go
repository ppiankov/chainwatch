package zone

import (
	"strings"

	"github.com/ppiankov/chainwatch/internal/model"
)

// HighVolumeThreshold is the byte threshold for HIGH_VOLUME zone (10MB).
const HighVolumeThreshold = 10_000_000

// zoneRule defines pattern-based detection for a single zone.
type zoneRule struct {
	URLPatterns     []string
	FilePatterns    []string
	CommandPatterns []string
}

// zoneDetectionRules maps each Zone to its detection patterns.
// Deterministic pattern matching — no ML, no heuristics.
var zoneDetectionRules = map[model.Zone]zoneRule{
	model.ZoneCommercialIntent: {
		URLPatterns:  []string{"/pricing", "/products", "/shop", "/store"},
		FilePatterns: []string{"pricing", "catalog"},
	},
	model.ZoneCommercialCommitment: {
		URLPatterns: []string{"/cart", "/checkout", "/payment", "/billing",
			"stripe.com", "paypal.com", "paddle.com"},
	},
	model.ZoneCredentialAdjacent: {
		FilePatterns: []string{".ssh/", ".aws/", ".config/gcloud/",
			".env", "secrets.", "credentials."},
	},
	model.ZoneSensitiveData: {
		FilePatterns: []string{"/hr/", "/employee/", "/salary/",
			"/payroll/", "/pii/",
			"hr_", "employee", "salary", "payroll", "pii", "ssn", "passport"},
	},
	model.ZoneEgressCapable: {
		URLPatterns:     []string{"http://", "https://"},
		CommandPatterns: []string{"curl", "wget", "nc", "telnet"},
	},
	model.ZoneEgressActive: {
		// Triggered by POST/PUT to external URL or SMTP commands.
		// Detected via action operation + resource, not just patterns.
		CommandPatterns: []string{"smtp", "sendmail"},
	},
}

// DetectZones examines an action and current state to determine which
// zones the action touches. Returns a set of newly detected zones.
func DetectZones(action *model.Action, state *model.TraceState) map[model.Zone]bool {
	zones := make(map[model.Zone]bool)
	resource := strings.ToLower(action.Resource)
	tool := strings.ToLower(action.Tool)
	operation := strings.ToLower(action.Operation)

	for z, rule := range zoneDetectionRules {
		if matchesPatterns(resource, tool, operation, rule) {
			zones[z] = true
		}
	}

	// CREDENTIAL_EXPOSED: credential-adjacent file that was READ
	if zones[model.ZoneCredentialAdjacent] && isReadOperation(operation, tool) {
		zones[model.ZoneCredentialExposed] = true
	}

	// Also check if we already had credential_adjacent and this is a read
	if state.ZonesEntered[model.ZoneCredentialAdjacent] && isReadOperation(operation, tool) {
		if isCredentialResource(resource) {
			zones[model.ZoneCredentialExposed] = true
		}
	}

	// EGRESS_ACTIVE: POST/PUT to external URL
	if isWriteHTTPOperation(operation) && isExternalURL(resource) {
		zones[model.ZoneEgressActive] = true
	}

	// HIGH_VOLUME: accumulated bytes exceed threshold
	meta := action.NormalizedMeta()
	totalBytes := state.VolumeBytes + meta.Bytes
	if totalBytes > HighVolumeThreshold {
		zones[model.ZoneHighVolume] = true
	}

	return zones
}

func matchesPatterns(resource, tool, operation string, rule zoneRule) bool {
	for _, p := range rule.URLPatterns {
		if strings.Contains(resource, strings.ToLower(p)) {
			return true
		}
	}
	for _, p := range rule.FilePatterns {
		if strings.Contains(resource, strings.ToLower(p)) {
			return true
		}
	}
	for _, p := range rule.CommandPatterns {
		if strings.Contains(tool, strings.ToLower(p)) || strings.Contains(resource, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func isReadOperation(operation, tool string) bool {
	return operation == "read" || tool == "file_read"
}

func isCredentialResource(resource string) bool {
	patterns := []string{".ssh/", ".aws/", ".config/gcloud/", ".env", "secrets.", "credentials."}
	for _, p := range patterns {
		if strings.Contains(resource, p) {
			return true
		}
	}
	return false
}

func isWriteHTTPOperation(operation string) bool {
	return operation == "post" || operation == "put" || operation == "delete"
}

func isExternalURL(resource string) bool {
	return strings.HasPrefix(resource, "http://") || strings.HasPrefix(resource, "https://")
}
