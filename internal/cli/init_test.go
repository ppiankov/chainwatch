package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInit_UserMode(t *testing.T) {
	tmpDir := t.TempDir()

	// Override mode and config dir by setting home.
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", origHome) }()

	// Reset flags.
	initMode = "user"
	initProfile = ""
	initInstallSystemd = false
	initForce = false

	err := runInit(nil, nil)
	if err != nil {
		t.Fatalf("runInit failed: %v", err)
	}

	configDir := filepath.Join(tmpDir, ".chainwatch")

	// Check directory structure.
	if _, err := os.Stat(filepath.Join(configDir, "profiles")); err != nil {
		t.Error("profiles directory not created")
	}

	// Check policy.yaml exists.
	policyPath := filepath.Join(configDir, "policy.yaml")
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("policy.yaml not created: %v", err)
	}
	if !strings.Contains(string(data), "enforcement_mode") {
		t.Error("policy.yaml missing enforcement_mode")
	}

	// Check denylist.yaml exists.
	denylistPath := filepath.Join(configDir, "denylist.yaml")
	data, err = os.ReadFile(denylistPath)
	if err != nil {
		t.Fatalf("denylist.yaml not created: %v", err)
	}
	if !strings.Contains(string(data), "urls:") {
		t.Error("denylist.yaml missing urls section")
	}
}

func TestRunInit_NoOverwriteWithoutForce(t *testing.T) {
	tmpDir := t.TempDir()

	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", origHome) }()

	configDir := filepath.Join(tmpDir, ".chainwatch")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Pre-create policy.yaml with sentinel content.
	sentinel := "# sentinel content\n"
	policyPath := filepath.Join(configDir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(sentinel), 0o644); err != nil {
		t.Fatal(err)
	}

	initMode = "user"
	initProfile = ""
	initInstallSystemd = false
	initForce = false

	if err := runInit(nil, nil); err != nil {
		t.Fatalf("runInit failed: %v", err)
	}

	// policy.yaml should NOT be overwritten.
	data, _ := os.ReadFile(policyPath)
	if string(data) != sentinel {
		t.Error("policy.yaml was overwritten without --force")
	}
}

func TestRunInit_ForceOverwrites(t *testing.T) {
	tmpDir := t.TempDir()

	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", origHome) }()

	configDir := filepath.Join(tmpDir, ".chainwatch")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Pre-create policy.yaml with sentinel content.
	sentinel := "# sentinel content\n"
	policyPath := filepath.Join(configDir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(sentinel), 0o644); err != nil {
		t.Fatal(err)
	}

	initMode = "user"
	initProfile = ""
	initInstallSystemd = false
	initForce = true

	if err := runInit(nil, nil); err != nil {
		t.Fatalf("runInit failed: %v", err)
	}

	// policy.yaml SHOULD be overwritten.
	data, _ := os.ReadFile(policyPath)
	if string(data) == sentinel {
		t.Error("policy.yaml was NOT overwritten with --force")
	}
}

func TestRunInit_InvalidMode(t *testing.T) {
	initMode = "invalid"
	initProfile = ""
	initInstallSystemd = false
	initForce = false

	err := runInit(nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), "unknown mode") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestInitConfigDir(t *testing.T) {
	tmpDir := t.TempDir()

	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", origHome) }()

	tests := []struct {
		mode    string
		want    string
		wantErr bool
	}{
		{"user", filepath.Join(tmpDir, ".chainwatch"), false},
		{"system", "/etc/chainwatch", false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		initMode = tt.mode
		got, err := initConfigDir()
		if tt.wantErr {
			if err == nil {
				t.Errorf("mode=%q: expected error", tt.mode)
			}
			continue
		}
		if err != nil {
			t.Errorf("mode=%q: unexpected error: %v", tt.mode, err)
			continue
		}
		if got != tt.want {
			t.Errorf("mode=%q: got %q, want %q", tt.mode, got, tt.want)
		}
	}
}

func TestWriteIfMissing(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.txt")

	// First write should succeed.
	initForce = false
	wrote, err := writeIfMissing(path, "hello")
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if !wrote {
		t.Error("first write should return true")
	}

	// Second write without force should skip.
	wrote, err = writeIfMissing(path, "world")
	if err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	if wrote {
		t.Error("second write should return false without force")
	}

	// Content should still be original.
	data, _ := os.ReadFile(path)
	if string(data) != "hello" {
		t.Errorf("content changed without force: %q", string(data))
	}

	// With force, should overwrite.
	initForce = true
	wrote, err = writeIfMissing(path, "world")
	if err != nil {
		t.Fatalf("force write failed: %v", err)
	}
	if !wrote {
		t.Error("force write should return true")
	}
	data, _ = os.ReadFile(path)
	if string(data) != "world" {
		t.Errorf("force write didn't overwrite: %q", string(data))
	}
}

func TestDefaultDenylistYAML(t *testing.T) {
	content, err := defaultDenylistYAML()
	if err != nil {
		t.Fatalf("defaultDenylistYAML failed: %v", err)
	}

	// Should have header comments.
	if !strings.HasPrefix(content, "# Chainwatch denylist") {
		t.Error("missing header comment")
	}

	// Should have all three sections.
	for _, section := range []string{"urls:", "files:", "commands:"} {
		if !strings.Contains(content, section) {
			t.Errorf("missing section %q", section)
		}
	}
}
