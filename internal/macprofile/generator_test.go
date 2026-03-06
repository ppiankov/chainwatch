package macprofile

import (
	"strings"
	"testing"
)

func TestLoadRestrictionsAppliesProfileBoundaries(t *testing.T) {
	r, err := LoadRestrictions("coding-agent", "")
	if err != nil {
		t.Fatalf("LoadRestrictions returned error: %v", err)
	}

	if len(r.URLPatterns) == 0 || len(r.FilePatterns) == 0 || len(r.CommandPatterns) == 0 {
		t.Fatalf("expected non-empty effective restrictions: %+v", r)
	}

	contains := func(values []string, want string) bool {
		for _, value := range values {
			if value == want {
				return true
			}
		}
		return false
	}

	// From coding-agent profile.
	if !contains(r.CommandPatterns, "terraform apply") {
		t.Fatalf("expected profile command pattern in effective restrictions, got %v", r.CommandPatterns)
	}

	// From default denylist.
	if !contains(r.FilePatterns, "~/.ssh/id_rsa") {
		t.Fatalf("expected default file pattern in effective restrictions, got %v", r.FilePatterns)
	}
}

func TestGenerateAppArmorMappings(t *testing.T) {
	r := &Restrictions{
		ProfileName:     "test-profile",
		URLPatterns:     []string{"stripe.com/*"},
		FilePatterns:    []string{"~/.ssh/*", "**/.env"},
		CommandPatterns: []string{"sudo su", "curl | sh"},
	}

	content, err := GenerateAppArmor("My Profile", r)
	if err != nil {
		t.Fatalf("GenerateAppArmor returned error: %v", err)
	}

	checks := []string{
		"profile My-Profile",
		"deny @{HOME}/.ssh/* rwklx,",
		"deny /**/.ssh/* rwklx,",
		"deny /**/.env rwklx,",
		"deny /usr/bin/sudo x,",
		"deny /usr/bin/sh x,",
		"deny network inet stream,",
		"deny network inet6 dgram,",
	}
	for _, want := range checks {
		if !strings.Contains(content, want) {
			t.Errorf("generated AppArmor profile missing %q", want)
		}
	}
}

func TestGenerateSELinuxMappings(t *testing.T) {
	r := &Restrictions{
		ProfileName:     "test-profile",
		URLPatterns:     []string{"stripe.com/*"},
		FilePatterns:    []string{"~/.aws/credentials", "**/.env"},
		CommandPatterns: []string{"sudo su"},
	}

	content, err := GenerateSELinux("Test Module", r)
	if err != nil {
		t.Fatalf("GenerateSELinux returned error: %v", err)
	}

	checks := []string{
		"module test_module 1.0;",
		"type test_module_agent_t;",
		"type test_module_blocked_file_t;",
		"type test_module_blocked_exec_t;",
		"neverallow test_module_agent_t test_module_blocked_file_t:file",
		"neverallow test_module_agent_t test_module_blocked_exec_t:file",
		"neverallow test_module_agent_t self:tcp_socket name_connect;",
		"semanage fcontext -a -t test_module_blocked_file_t '/home/[^/]+/\\.aws/credentials'",
		"semanage fcontext -a -t test_module_blocked_exec_t '/usr/bin/sudo'",
	}
	for _, want := range checks {
		if !strings.Contains(content, want) {
			t.Errorf("generated SELinux module missing %q", want)
		}
	}
}

func TestGenerateRejectsNilRestrictions(t *testing.T) {
	if _, err := GenerateAppArmor("name", nil); err == nil {
		t.Fatal("expected error for nil restrictions in GenerateAppArmor")
	}
	if _, err := GenerateSELinux("name", nil); err == nil {
		t.Fatal("expected error for nil restrictions in GenerateSELinux")
	}
}
