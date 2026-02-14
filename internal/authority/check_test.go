package authority

import (
	"testing"

	"github.com/ppiankov/chainwatch/internal/model"
)

func TestDirectUserAdmitted(t *testing.T) {
	ctx := model.InstructionContext{
		Origin:          "direct_user_interface",
		SecurityContext: "user_terminal",
		SessionID:       "session-1",
	}

	result := CheckAdmission(ctx)

	if !result.Admitted {
		t.Error("expected direct user instruction to be admitted")
	}
}

func TestProxyRelayBlocked(t *testing.T) {
	ctx := model.InstructionContext{
		Origin:          "network",
		SecurityContext: "web_interface",
		IsProxied:       true,
		SessionID:       "session-1",
	}

	result := CheckAdmission(ctx)

	if result.Admitted {
		t.Error("expected proxied instruction to be blocked")
	}
	if result.Decision != model.RequireApproval {
		t.Errorf("expected RequireApproval, got %s", result.Decision)
	}
	if result.BoundaryType != model.AuthProxyRelay {
		t.Errorf("expected ProxyRelay boundary, got %s", result.BoundaryType)
	}
}

func TestRelayedBlocked(t *testing.T) {
	ctx := model.InstructionContext{
		Origin:    "direct_user_interface",
		IsRelayed: true,
		SessionID: "session-1",
	}

	result := CheckAdmission(ctx)

	if result.Admitted {
		t.Error("expected relayed instruction to be blocked")
	}
}

func TestInjectionDetected(t *testing.T) {
	ctx := model.InstructionContext{
		Origin:          "direct_user_interface",
		SecurityContext: "user_terminal",
		HasControlChars: true,
		SessionID:       "session-1",
	}

	result := CheckAdmission(ctx)

	if result.Admitted {
		t.Error("expected instruction with control chars to be blocked")
	}
	if result.Decision != model.Deny {
		t.Errorf("expected Deny for injection, got %s", result.Decision)
	}
	if result.BoundaryType != model.AuthInjectionDetected {
		t.Errorf("expected InjectionDetected, got %s", result.BoundaryType)
	}
}

func TestNetworkOriginBlocked(t *testing.T) {
	ctx := model.InstructionContext{
		Origin:          "network",
		SecurityContext: "api_endpoint",
		SessionID:       "session-1",
	}

	result := CheckAdmission(ctx)

	if result.Admitted {
		t.Error("expected network origin to be blocked")
	}
	if result.BoundaryType != model.AuthContextCrossing {
		t.Errorf("expected ContextCrossing, got %s", result.BoundaryType)
	}
}

func TestEmptyOriginAdmitted(t *testing.T) {
	ctx := model.InstructionContext{
		SecurityContext: "user_terminal",
		SessionID:       "session-1",
	}

	result := CheckAdmission(ctx)

	if !result.Admitted {
		t.Error("expected empty origin to be admitted (default safe)")
	}
}
