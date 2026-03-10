package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	hookInstallGlobal  bool
	hookInstallProfile string
	hookInstallPreset  string
)

func init() {
	hookInstallCmd.Flags().BoolVar(&hookInstallGlobal, "global", false, "Install to ~/.claude/settings.json (default: .claude/settings.local.json)")
	hookInstallCmd.Flags().StringVar(&hookInstallProfile, "profile", "", "Safety profile to apply (e.g., coding-agent)")
	hookInstallCmd.Flags().StringVar(&hookInstallPreset, "preset", "", "Denylist preset (e.g., supply-chain)")
}

var hookInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install chainwatch as a Claude Code PreToolUse hook",
	Long: `Writes hook configuration to Claude Code settings.

By default, writes to .claude/settings.local.json (project-scoped, gitignored).
Use --global to write to ~/.claude/settings.json instead.

Merges with existing settings non-destructively.`,
	RunE: runHookInstall,
}

func runHookInstall(cmd *cobra.Command, args []string) error {
	settingsPath, err := hookSettingsPath()
	if err != nil {
		return err
	}

	// Load existing settings.
	settings := make(map[string]any)
	if data, err := os.ReadFile(settingsPath); err == nil {
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("parse existing settings %s: %w", settingsPath, err)
		}
	}

	// Build the hook command.
	hookCommand := buildHookCommand()

	// Build the hook entry.
	hookEntry := map[string]any{
		"matcher": "Bash|Write|Edit|WebFetch|mcp__.*",
		"hooks": []any{
			map[string]any{
				"type":    "command",
				"command": hookCommand,
			},
		},
	}

	// Merge into settings.
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = make(map[string]any)
	}

	// Replace or add PreToolUse chainwatch entry.
	preToolUse := ensurePreToolUseList(hooks)
	preToolUse = replaceChainwatchHook(preToolUse, hookEntry)
	hooks["PreToolUse"] = preToolUse
	settings["hooks"] = hooks

	// Write settings.
	dir := filepath.Dir(settingsPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(settingsPath, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", settingsPath, err)
	}

	fmt.Printf("Installed chainwatch hook to %s\n", settingsPath)
	fmt.Printf("Command: %s\n", hookCommand)
	fmt.Println()
	fmt.Println("Verify:")
	fmt.Printf("  echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls\"}}' | %s\n", hookCommand)
	return nil
}

func hookSettingsPath() (string, error) {
	if hookInstallGlobal {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		return filepath.Join(home, ".claude", "settings.json"), nil
	}
	return filepath.Join(".claude", "settings.local.json"), nil
}

func buildHookCommand() string {
	// Find chainwatch binary path.
	binPath := "chainwatch"
	if resolved, err := exec.LookPath("chainwatch"); err == nil {
		binPath = resolved
	}

	cmd := binPath + " hook --event PreToolUse"
	if hookInstallProfile != "" {
		cmd += " --profile " + hookInstallProfile
	}
	if hookInstallPreset != "" {
		cmd += " --preset " + hookInstallPreset
	}
	return cmd
}

// ensurePreToolUseList extracts or creates the PreToolUse hook list.
func ensurePreToolUseList(hooks map[string]any) []any {
	existing, ok := hooks["PreToolUse"]
	if !ok {
		return nil
	}
	list, ok := existing.([]any)
	if ok {
		return list
	}
	return nil
}

// replaceChainwatchHook replaces an existing chainwatch entry or appends a new one.
func replaceChainwatchHook(list []any, entry map[string]any) []any {
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		innerHooks, _ := m["hooks"].([]any)
		for _, h := range innerHooks {
			hm, _ := h.(map[string]any)
			cmd, _ := hm["command"].(string)
			if contains(cmd, "chainwatch hook") {
				list[i] = entry
				return list
			}
		}
	}
	return append(list, entry)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstring(s, substr))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
