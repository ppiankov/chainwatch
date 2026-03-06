package profile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateSeccompJSONDefaultValid(t *testing.T) {
	data, err := GenerateSeccompJSON(nil)
	if err != nil {
		t.Fatalf("GenerateSeccompJSON(nil) failed: %v", err)
	}

	if err := ValidateSeccompJSON(data); err != nil {
		t.Fatalf("ValidateSeccompJSON failed: %v", err)
	}

	names := seccompRuleNames(t, data)
	for _, syscallName := range []string{"ptrace", "mount", "reboot"} {
		if !names[syscallName] {
			t.Errorf("expected default seccomp profile to block %q", syscallName)
		}
	}
}

func TestGenerateSeccompJSONClawbotAddsPrivilegeAndNetworkRestrictions(t *testing.T) {
	p, err := Load("clawbot")
	if err != nil {
		t.Fatalf("Load(clawbot) failed: %v", err)
	}

	data, err := GenerateSeccompJSON(p)
	if err != nil {
		t.Fatalf("GenerateSeccompJSON(clawbot) failed: %v", err)
	}

	names := seccompRuleNames(t, data)
	for _, syscallName := range []string{"setuid", "setgid", "socket", "connect"} {
		if !names[syscallName] {
			t.Errorf("expected clawbot seccomp profile to block %q", syscallName)
		}
	}
}

func TestGenerateSeccompJSONResearchAgentAddsFileMutationRestrictions(t *testing.T) {
	p, err := Load("research-agent")
	if err != nil {
		t.Fatalf("Load(research-agent) failed: %v", err)
	}

	data, err := GenerateSeccompJSON(p)
	if err != nil {
		t.Fatalf("GenerateSeccompJSON(research-agent) failed: %v", err)
	}

	names := seccompRuleNames(t, data)
	for _, syscallName := range []string{"unlink", "rename", "chmod"} {
		if !names[syscallName] {
			t.Errorf("expected research-agent seccomp profile to block %q", syscallName)
		}
	}
}

func TestGenerateSeccompJSONDeterministic(t *testing.T) {
	p, err := Load("sre-infra")
	if err != nil {
		t.Fatalf("Load(sre-infra) failed: %v", err)
	}

	first, err := GenerateSeccompJSON(p)
	if err != nil {
		t.Fatalf("first GenerateSeccompJSON failed: %v", err)
	}

	second, err := GenerateSeccompJSON(p)
	if err != nil {
		t.Fatalf("second GenerateSeccompJSON failed: %v", err)
	}

	if string(first) != string(second) {
		t.Fatal("generated seccomp JSON should be deterministic")
	}
}

func TestValidateSeccompJSONRejectsInvalidData(t *testing.T) {
	err := ValidateSeccompJSON([]byte(`{"defaultAction":"","syscalls":[]}`))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "defaultAction") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func seccompRuleNames(t *testing.T, data []byte) map[string]bool {
	t.Helper()

	var profile SeccompProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("failed to unmarshal seccomp JSON: %v", err)
	}

	names := make(map[string]bool)
	for _, entry := range profile.Syscalls {
		for _, syscallName := range entry.Names {
			names[syscallName] = true
		}
	}

	return names
}
