package wo

import (
	"fmt"
	"strings"
)

// ValidationError collects all validation failures for a WO.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("WO validation failed: %s", strings.Join(e.Errors, "; "))
}

// add appends an error message.
func (e *ValidationError) add(msg string) {
	e.Errors = append(e.Errors, msg)
}

// Validate checks a WorkOrder for completeness and correctness.
// Returns nil if valid, or a *ValidationError listing all problems.
func Validate(w *WorkOrder) error {
	ve := &ValidationError{}

	// Required fields.
	if w.WOVersion == "" {
		ve.add("wo_version is required")
	} else if w.WOVersion != Version {
		ve.add(fmt.Sprintf("wo_version %q is not supported (expected %q)", w.WOVersion, Version))
	}

	if w.ID == "" {
		ve.add("id is required")
	}

	if w.IncidentID == "" {
		ve.add("incident_id is required")
	}

	if w.Target.Host == "" {
		ve.add("target.host is required")
	}

	if w.Target.Scope == "" {
		ve.add("target.scope is required")
	}

	// Observations.
	if len(w.Observations) == 0 {
		ve.add("at least one observation is required")
	}
	for i, obs := range w.Observations {
		prefix := fmt.Sprintf("observations[%d]", i)
		if !IsValidType(obs.Type) {
			ve.add(fmt.Sprintf("%s: unknown type %q", prefix, obs.Type))
		}
		if !IsValidSeverity(obs.Severity) {
			ve.add(fmt.Sprintf("%s: invalid severity %q", prefix, obs.Severity))
		}
		if obs.Detail == "" {
			ve.add(fmt.Sprintf("%s: detail is required", prefix))
		}
	}

	// Constraints.
	if w.Constraints.MaxSteps <= 0 {
		ve.add("constraints.max_steps must be > 0")
	}

	// Proposed goals.
	if len(w.ProposedGoals) == 0 {
		ve.add("at least one proposed goal is required")
	}

	// Redaction mode.
	if w.RedactionMode != "local" && w.RedactionMode != "cloud" {
		ve.add(fmt.Sprintf("redaction_mode %q is not valid (expected local or cloud)", w.RedactionMode))
	}

	// Cloud mode must have token map ref.
	if w.RedactionMode == "cloud" && w.TokenMapRef == "" {
		ve.add("token_map_ref is required when redaction_mode is cloud")
	}

	if len(ve.Errors) > 0 {
		return ve
	}
	return nil
}
