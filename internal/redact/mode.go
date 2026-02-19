package redact

import "strings"

// Mode determines whether redaction is applied.
type Mode string

const (
	ModeLocal Mode = "local" // no redaction — LLM is on localhost
	ModeCloud Mode = "cloud" // mandatory redaction — LLM is remote
)

// DetectMode infers the redaction mode from the API URL.
// Localhost and 127.0.0.1 are local; everything else is cloud.
func DetectMode(apiURL string) Mode {
	lower := strings.ToLower(apiURL)
	if strings.Contains(lower, "localhost") || strings.Contains(lower, "127.0.0.1") {
		return ModeLocal
	}
	return ModeCloud
}

// ResolveMode determines the redaction mode from the API URL and an optional
// environment override (NULLBOT_REDACT). The override takes precedence:
//   - "always" → cloud (force redaction)
//   - "never"  → local (skip redaction)
//   - ""       → auto-detect from URL
func ResolveMode(apiURL, envOverride string) Mode {
	switch strings.ToLower(strings.TrimSpace(envOverride)) {
	case "always":
		return ModeCloud
	case "never":
		return ModeLocal
	default:
		return DetectMode(apiURL)
	}
}
