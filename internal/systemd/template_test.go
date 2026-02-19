package systemd

import (
	"strings"
	"testing"
)

func TestGuardedTemplate(t *testing.T) {
	tmpl := GuardedTemplate()

	// Must be a valid systemd unit with required sections.
	for _, section := range []string{"[Unit]", "[Service]", "[Install]"} {
		if !strings.Contains(tmpl, section) {
			t.Errorf("template missing section %s", section)
		}
	}

	// Must use %i instance specifier for agent name.
	if !strings.Contains(tmpl, "%i") {
		t.Error("template missing %i instance specifier")
	}

	// Must reference chainwatch exec.
	if !strings.Contains(tmpl, "chainwatch exec --profile %i") {
		t.Error("template missing chainwatch exec command")
	}

	// Must have security hardening directives.
	for _, directive := range []string{"NoNewPrivileges=true", "PrivateTmp=true", "ProtectSystem=strict"} {
		if !strings.Contains(tmpl, directive) {
			t.Errorf("template missing security directive %s", directive)
		}
	}
}
