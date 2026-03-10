package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookSettingsPath_Project(t *testing.T) {
	hookInstallGlobal = false
	path, err := hookSettingsPath()
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(".claude", "settings.local.json") {
		t.Errorf("got %q, want .claude/settings.local.json", path)
	}
}

func TestHookSettingsPath_Global(t *testing.T) {
	hookInstallGlobal = true
	path, err := hookSettingsPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, filepath.Join(".claude", "settings.json")) {
		t.Errorf("got %q, want suffix .claude/settings.json", path)
	}
}

func TestBuildHookCommand_Bare(t *testing.T) {
	hookInstallProfile = ""
	hookInstallPreset = ""
	cmd := buildHookCommand()
	if !strings.Contains(cmd, "chainwatch hook --event PreToolUse") {
		t.Errorf("unexpected command: %s", cmd)
	}
	if strings.Contains(cmd, "--profile") {
		t.Error("should not have --profile when empty")
	}
}

func TestBuildHookCommand_WithProfile(t *testing.T) {
	hookInstallProfile = "coding-agent"
	hookInstallPreset = ""
	cmd := buildHookCommand()
	if !strings.Contains(cmd, "--profile coding-agent") {
		t.Errorf("missing profile in command: %s", cmd)
	}
}

func TestBuildHookCommand_WithPreset(t *testing.T) {
	hookInstallProfile = ""
	hookInstallPreset = "supply-chain"
	cmd := buildHookCommand()
	if !strings.Contains(cmd, "--preset supply-chain") {
		t.Errorf("missing preset in command: %s", cmd)
	}
}

func TestBuildHookCommand_WithBoth(t *testing.T) {
	hookInstallProfile = "sre-infra"
	hookInstallPreset = "supply-chain"
	cmd := buildHookCommand()
	if !strings.Contains(cmd, "--profile sre-infra") || !strings.Contains(cmd, "--preset supply-chain") {
		t.Errorf("missing flags in command: %s", cmd)
	}
}

func TestRunHookInstall_FreshSettings(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	hookInstallGlobal = false
	hookInstallProfile = "coding-agent"
	hookInstallPreset = ""

	if err := runHookInstall(nil, nil); err != nil {
		t.Fatalf("runHookInstall failed: %v", err)
	}

	settingsPath := filepath.Join(tmpDir, ".claude", "settings.local.json")
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("settings file not created: %v", err)
	}

	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		t.Fatal("missing hooks key")
	}

	preToolUse, ok := hooks["PreToolUse"].([]any)
	if !ok {
		t.Fatal("missing PreToolUse key")
	}

	if len(preToolUse) != 1 {
		t.Fatalf("expected 1 hook entry, got %d", len(preToolUse))
	}

	entry := preToolUse[0].(map[string]any)
	if entry["matcher"] != "Bash|Write|Edit|WebFetch|mcp__.*" {
		t.Errorf("unexpected matcher: %v", entry["matcher"])
	}
}

func TestRunHookInstall_MergesExisting(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	// Pre-create settings with existing hooks.
	claudeDir := filepath.Join(tmpDir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `{
  "permissions": {"allow": ["Bash(*)"]},
  "hooks": {
    "Stop": [{"matcher": ".*", "hooks": [{"type": "command", "command": "echo done"}]}]
  }
}`
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.local.json"), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	hookInstallGlobal = false
	hookInstallProfile = ""
	hookInstallPreset = ""

	if err := runHookInstall(nil, nil); err != nil {
		t.Fatalf("runHookInstall failed: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(claudeDir, "settings.local.json"))
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}

	// Existing permissions preserved.
	if _, ok := settings["permissions"]; !ok {
		t.Error("existing permissions key lost")
	}

	// Existing Stop hook preserved.
	hooks := settings["hooks"].(map[string]any)
	if _, ok := hooks["Stop"]; !ok {
		t.Error("existing Stop hook lost")
	}

	// New PreToolUse hook added.
	if _, ok := hooks["PreToolUse"]; !ok {
		t.Error("PreToolUse hook not added")
	}
}

func TestReplaceChainwatchHook_Replaces(t *testing.T) {
	existing := []any{
		map[string]any{
			"matcher": "Bash",
			"hooks": []any{
				map[string]any{"type": "command", "command": "chainwatch hook --event PreToolUse --profile old"},
			},
		},
	}
	newEntry := map[string]any{
		"matcher": "Bash|Write|Edit|WebFetch|mcp__.*",
		"hooks": []any{
			map[string]any{"type": "command", "command": "chainwatch hook --event PreToolUse --profile new"},
		},
	}

	result := replaceChainwatchHook(existing, newEntry)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry after replace, got %d", len(result))
	}
	entry := result[0].(map[string]any)
	if entry["matcher"] != "Bash|Write|Edit|WebFetch|mcp__.*" {
		t.Errorf("matcher not updated: %v", entry["matcher"])
	}
}

func TestReplaceChainwatchHook_Appends(t *testing.T) {
	existing := []any{
		map[string]any{
			"matcher": "Bash",
			"hooks": []any{
				map[string]any{"type": "command", "command": "other-tool check"},
			},
		},
	}
	newEntry := map[string]any{
		"matcher": "Bash|Write|Edit|WebFetch|mcp__.*",
		"hooks": []any{
			map[string]any{"type": "command", "command": "chainwatch hook --event PreToolUse"},
		},
	}

	result := replaceChainwatchHook(existing, newEntry)
	if len(result) != 2 {
		t.Fatalf("expected 2 entries after append, got %d", len(result))
	}
}

func TestEnsurePreToolUseList_Missing(t *testing.T) {
	hooks := map[string]any{}
	result := ensurePreToolUseList(hooks)
	if result != nil {
		t.Error("expected nil for missing key")
	}
}

func TestEnsurePreToolUseList_Present(t *testing.T) {
	hooks := map[string]any{
		"PreToolUse": []any{map[string]any{"matcher": "Bash"}},
	}
	result := ensurePreToolUseList(hooks)
	if len(result) != 1 {
		t.Errorf("expected 1 entry, got %d", len(result))
	}
}
