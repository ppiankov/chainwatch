package authority

import "github.com/ppiankov/chainwatch/internal/model"

// CheckAdmission checks if an instruction crosses any authority boundary.
// This is Stage 1 — called BEFORE instruction enters the execution chain.
// If the instruction crosses a boundary, it is NOT admitted.
func CheckAdmission(ctx model.InstructionContext) model.AdmissionResult {
	// Control character injection — hard deny
	if ctx.HasControlChars {
		return model.AdmissionResult{
			Admitted:     false,
			Decision:     model.Deny,
			Reason:       "control character injection detected in instruction",
			BoundaryType: model.AuthInjectionDetected,
		}
	}

	// Proxy relay — instruction origin crosses trust boundary
	if ctx.IsProxied || ctx.IsRelayed {
		return model.AdmissionResult{
			Admitted:     false,
			Decision:     model.RequireApproval,
			Reason:       "instruction origin crosses trust boundary (proxied/relayed)",
			BoundaryType: model.AuthProxyRelay,
		}
	}

	// Non-direct origin — untrusted
	if ctx.Origin != "" && ctx.Origin != "direct_user_interface" {
		return model.AdmissionResult{
			Admitted:     false,
			Decision:     model.RequireApproval,
			Reason:       "instruction origin is not direct user interface",
			BoundaryType: model.AuthContextCrossing,
		}
	}

	// All checks passed — instruction admitted
	return model.AdmissionResult{Admitted: true}
}
