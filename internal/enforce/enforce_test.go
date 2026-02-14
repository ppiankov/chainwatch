package enforce

import (
	"errors"
	"testing"

	"github.com/ppiankov/chainwatch/internal/model"
)

func TestAllowPassesThrough(t *testing.T) {
	result := model.PolicyResult{Decision: model.Allow, Reason: "low risk"}
	data := map[string]any{"name": "Alice", "role": "engineer"}

	out, err := Enforce(result, data)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatal("expected map output")
	}
	if m["name"] != "Alice" {
		t.Errorf("expected name=Alice, got %v", m["name"])
	}
}

func TestDenyRaisesError(t *testing.T) {
	result := model.PolicyResult{Decision: model.Deny, Reason: "denylisted"}

	_, err := Enforce(result, "anything")

	if err == nil {
		t.Fatal("expected error for Deny")
	}
	var enfErr *EnforcementError
	if !errors.As(err, &enfErr) {
		t.Fatalf("expected EnforcementError, got %T", err)
	}
	if enfErr.Decision != model.Deny {
		t.Errorf("expected Deny decision, got %s", enfErr.Decision)
	}
}

func TestRequireApprovalRaisesError(t *testing.T) {
	result := model.PolicyResult{
		Decision:    model.RequireApproval,
		Reason:      "salary access",
		ApprovalKey: "soc_salary_access",
	}

	_, err := Enforce(result, "anything")

	if err == nil {
		t.Fatal("expected error for RequireApproval")
	}
	var enfErr *EnforcementError
	if !errors.As(err, &enfErr) {
		t.Fatalf("expected EnforcementError, got %T", err)
	}
	if enfErr.ApprovalKey != "soc_salary_access" {
		t.Errorf("expected approval_key=soc_salary_access, got %s", enfErr.ApprovalKey)
	}
}

func TestAllowWithRedactionRedactsMap(t *testing.T) {
	result := model.PolicyResult{
		Decision:   model.AllowWithRedaction,
		Reason:     "moderate risk",
		Redactions: map[string]any{"auto": true},
	}
	data := map[string]any{
		"name":  "Alice",
		"email": "alice@example.com",
		"role":  "engineer",
	}

	out, err := Enforce(result, data)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatal("expected map output")
	}
	// name and email should be redacted (in DefaultPIIKeys)
	if m["name"] != "***" {
		t.Errorf("expected name redacted, got %v", m["name"])
	}
	if m["email"] != "***" {
		t.Errorf("expected email redacted, got %v", m["email"])
	}
	// role should be preserved
	if m["role"] != "engineer" {
		t.Errorf("expected role=engineer, got %v", m["role"])
	}
}

func TestRewriteOutputString(t *testing.T) {
	result := model.PolicyResult{
		Decision:      model.RewriteOutput,
		Reason:        "output rewrite",
		OutputRewrite: "redacted output",
	}

	out, err := Enforce(result, "original sensitive output")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out != "redacted output" {
		t.Errorf("expected 'redacted output', got %v", out)
	}
}

func TestRewriteOutputNoRewriteReturnsEmpty(t *testing.T) {
	result := model.PolicyResult{
		Decision: model.RewriteOutput,
		Reason:   "output rewrite",
	}

	out, err := Enforce(result, "original")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out != "" {
		t.Errorf("expected empty string, got %v", out)
	}
}

func TestEnforcementErrorMessage(t *testing.T) {
	err := &EnforcementError{
		Decision:    model.RequireApproval,
		Reason:      "salary access",
		ApprovalKey: "soc_salary_access",
	}

	msg := err.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
	// Should include approval key
	if !containsStr(msg, "soc_salary_access") {
		t.Errorf("expected approval_key in message, got %s", msg)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstr(s, sub))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
