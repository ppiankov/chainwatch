package enforce

import (
	"fmt"

	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/redact"
)

// EnforcementError is raised when a policy decision blocks execution.
type EnforcementError struct {
	Decision    model.Decision
	Reason      string
	ApprovalKey string
}

func (e *EnforcementError) Error() string {
	if e.ApprovalKey != "" {
		return fmt.Sprintf("enforcement blocked (%s): %s [approval_key=%s]", e.Decision, e.Reason, e.ApprovalKey)
	}
	return fmt.Sprintf("enforcement blocked (%s): %s", e.Decision, e.Reason)
}

// Enforce applies a policy decision to data.
// Returns the (possibly modified) data, or an error if blocked.
func Enforce(result model.PolicyResult, data any) (any, error) {
	switch result.Decision {
	case model.Deny:
		return nil, &EnforcementError{
			Decision: result.Decision,
			Reason:   result.Reason,
		}

	case model.RequireApproval:
		return nil, &EnforcementError{
			Decision:    result.Decision,
			Reason:      result.Reason,
			ApprovalKey: result.ApprovalKey,
		}

	case model.AllowWithRedaction:
		return redactData(result, data), nil

	case model.Allow:
		return data, nil

	case model.RewriteOutput:
		if s, ok := data.(string); ok {
			if result.OutputRewrite != "" {
				return result.OutputRewrite, nil
			}
			_ = s
			return "", nil
		}
		return data, nil

	default:
		return data, nil
	}
}

func redactData(result model.PolicyResult, data any) any {
	var extraKeys []string
	if result.Redactions != nil {
		if ek, ok := result.Redactions["extra_keys"].([]string); ok {
			extraKeys = ek
		}
	}

	switch d := data.(type) {
	case map[string]any:
		return redact.RedactAuto(d, extraKeys)
	case []map[string]any:
		return redact.RedactRecords(d, append(redact.DefaultPIIKeys, extraKeys...))
	default:
		return data
	}
}
