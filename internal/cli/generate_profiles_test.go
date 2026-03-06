package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGenerateAppArmor(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "agent.apparmor")

	generateAppArmorProfile = "coding-agent"
	generateAppArmorOutput = outPath
	generateAppArmorDenylist = ""
	generateAppArmorName = "coding-agent-os"

	if err := runGenerateAppArmor(nil, nil); err != nil {
		t.Fatalf("runGenerateAppArmor returned error: %v", err)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read generated profile: %v", err)
	}

	text := string(content)
	if !strings.Contains(text, "profile coding-agent-os") {
		t.Fatalf("generated AppArmor profile missing name, got: %s", text)
	}
	if !strings.Contains(text, "deny network inet stream,") {
		t.Fatalf("generated AppArmor profile missing URL network mapping: %s", text)
	}
}

func TestRunGenerateSELinux(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "agent.te")

	generateSELinuxProfile = "coding-agent"
	generateSELinuxOutput = outPath
	generateSELinuxDenylist = ""
	generateSELinuxModule = "chainwatch_coding_agent"

	if err := runGenerateSELinux(nil, nil); err != nil {
		t.Fatalf("runGenerateSELinux returned error: %v", err)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read generated module: %v", err)
	}

	text := string(content)
	if !strings.Contains(text, "module chainwatch_coding_agent 1.0;") {
		t.Fatalf("generated SELinux module missing header, got: %s", text)
	}
	if !strings.Contains(text, "neverallow chainwatch_coding_agent_agent_t") {
		t.Fatalf("generated SELinux module missing restrictions: %s", text)
	}
}

func TestWriteGeneratedProfileEmptyPath(t *testing.T) {
	if err := writeGeneratedProfile("", "data"); err == nil {
		t.Fatal("expected error for empty output path")
	}
}
