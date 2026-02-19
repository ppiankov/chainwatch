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

func TestDaemonTemplate(t *testing.T) {
	tmpl := DaemonTemplate()

	// Must be a valid systemd unit with required sections.
	for _, section := range []string{"[Unit]", "[Service]", "[Install]"} {
		if !strings.Contains(tmpl, section) {
			t.Errorf("template missing section %s", section)
		}
	}

	// Must run as nullbot user.
	if !strings.Contains(tmpl, "User=nullbot") {
		t.Error("template missing User=nullbot")
	}

	// Must reference nullbot daemon command.
	if !strings.Contains(tmpl, "nullbot daemon") {
		t.Error("template missing nullbot daemon command")
	}

	// Must have ReadWritePaths for inbox/outbox/state.
	for _, dir := range []string{"inbox", "outbox", "state"} {
		if !strings.Contains(tmpl, "/home/nullbot/"+dir) {
			t.Errorf("template missing ReadWritePaths for %s", dir)
		}
	}

	// Must have security hardening directives.
	for _, directive := range []string{
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ProtectHome=read-only",
		"ProtectKernelTunables=true",
		"RestrictNamespaces=true",
		"MemoryDenyWriteExecute=true",
	} {
		if !strings.Contains(tmpl, directive) {
			t.Errorf("template missing security directive %s", directive)
		}
	}

	// Must have resource limits.
	for _, limit := range []string{"CPUQuota=30%", "MemoryMax=512M", "TasksMax=50"} {
		if !strings.Contains(tmpl, limit) {
			t.Errorf("template missing resource limit %s", limit)
		}
	}
}
