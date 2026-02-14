package model

// BoundaryZone represents the monotonic irreversibility level.
// Can only advance (increase), never retreat.
type BoundaryZone int

const (
	Safe         BoundaryZone = 0
	Sensitive    BoundaryZone = 1
	Commitment   BoundaryZone = 2
	Irreversible BoundaryZone = 3
)

func (z BoundaryZone) String() string {
	switch z {
	case Safe:
		return "SAFE"
	case Sensitive:
		return "SENSITIVE"
	case Commitment:
		return "COMMITMENT"
	case Irreversible:
		return "IRREVERSIBLE"
	default:
		return "UNKNOWN"
	}
}

// Zone represents a fine-grained structural category indicating
// proximity to irreversibility. Zones accumulate — once entered, never left.
type Zone string

const (
	ZoneCommercialIntent     Zone = "commercial_intent"
	ZoneCommercialCommitment Zone = "commercial_commit"
	ZoneCredentialAdjacent   Zone = "credential_adjacent"
	ZoneCredentialExposed    Zone = "credential_exposed"
	ZoneEgressCapable        Zone = "egress_capable"
	ZoneEgressActive         Zone = "egress_active"
	ZoneSensitiveData        Zone = "sensitive_data"
	ZoneHighVolume           Zone = "high_volume"
)

// AuthorityBoundary represents a type of trust boundary crossing
// detected at instruction ingress (Stage 1).
type AuthorityBoundary string

const (
	AuthProxyRelay        AuthorityBoundary = "proxy_relay"
	AuthContextCrossing   AuthorityBoundary = "context_crossing"
	AuthTemporalViolation AuthorityBoundary = "temporal_violation"
	AuthInjectionDetected AuthorityBoundary = "injection_detected"
)
