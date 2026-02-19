package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/policy"
	"github.com/ppiankov/chainwatch/internal/profile"
	"github.com/ppiankov/chainwatch/internal/systemd"
)

var (
	initProfile        string
	initMode           string
	initInstallSystemd bool
	initForce          bool
)

func init() {
	initCmd.Flags().StringVar(&initProfile, "profile", "", "Built-in profile to apply (e.g., clawbot, coding-agent)")
	initCmd.Flags().StringVar(&initMode, "mode", "user", "Config location: user (~/.chainwatch) or system (/etc/chainwatch)")
	initCmd.Flags().BoolVar(&initInstallSystemd, "install-systemd", false, "Install systemd guarded@ template unit (requires root)")
	initCmd.Flags().BoolVar(&initForce, "force", false, "Overwrite existing config files")
	rootCmd.AddCommand(initCmd)
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Bootstrap chainwatch configuration and optional systemd integration",
	Long: `Creates config directory, default policy, denylist, and profile directory.

User mode (default):  writes to ~/.chainwatch/
System mode:          writes to /etc/chainwatch/ (requires root)

With --install-systemd: installs a chainwatch-guarded@.service template
so any agent can run under enforcement via:
  systemctl enable --now chainwatch-guarded@<agent-name>`,
	RunE: runInit,
}

func runInit(cmd *cobra.Command, args []string) error {
	configDir, err := initConfigDir()
	if err != nil {
		return err
	}

	var created []string

	// Create directory structure.
	profilesDir := filepath.Join(configDir, "profiles")
	if err := os.MkdirAll(profilesDir, 0o755); err != nil {
		return fmt.Errorf("create profiles directory: %w", err)
	}

	// Write policy.yaml.
	policyPath := filepath.Join(configDir, "policy.yaml")
	if wrote, err := writeIfMissing(policyPath, policy.DefaultConfigYAML()); err != nil {
		return err
	} else if wrote {
		created = append(created, policyPath)
	}

	// Write denylist.yaml.
	denylistPath := filepath.Join(configDir, "denylist.yaml")
	denylistContent, err := defaultDenylistYAML()
	if err != nil {
		return fmt.Errorf("generate default denylist: %w", err)
	}
	if wrote, err := writeIfMissing(denylistPath, denylistContent); err != nil {
		return err
	} else if wrote {
		created = append(created, denylistPath)
	}

	// Apply profile if requested.
	if initProfile != "" {
		profPath := filepath.Join(profilesDir, initProfile+".yaml")
		// Try loading built-in profile first.
		prof, loadErr := profile.Load(initProfile)
		if loadErr != nil {
			return fmt.Errorf("unknown profile %q: %w", initProfile, loadErr)
		}
		_ = prof // profile loads OK — write the template
		content := profile.InitProfile(initProfile)
		if wrote, err := writeIfMissing(profPath, content); err != nil {
			return err
		} else if wrote {
			created = append(created, profPath)
		}
	}

	// Install systemd template if requested.
	if initInstallSystemd {
		if runtime.GOOS != "linux" {
			return fmt.Errorf("--install-systemd is only supported on Linux")
		}
		if os.Geteuid() != 0 {
			return fmt.Errorf("--install-systemd requires root; run with sudo")
		}

		unitPath := "/etc/systemd/system/chainwatch-guarded@.service"
		content := systemd.GuardedTemplate()
		if err := os.WriteFile(unitPath, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write systemd unit: %w", err)
		}
		created = append(created, unitPath)

		// Reload systemd.
		if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: systemctl daemon-reload failed: %v\n", err)
		}
	}

	// Print summary.
	fmt.Println("chainwatch init complete.")
	fmt.Println()
	if len(created) > 0 {
		fmt.Println("Created:")
		for _, path := range created {
			fmt.Printf("  %s\n", path)
		}
		fmt.Println()
	} else {
		fmt.Println("All files already exist (use --force to overwrite).")
		fmt.Println()
	}

	// Print next steps.
	fmt.Println("Verify:")
	fmt.Println("  chainwatch doctor")
	fmt.Println()
	fmt.Println("Run a command under enforcement:")
	if initProfile != "" {
		fmt.Printf("  chainwatch exec --profile %s -- <command>\n", initProfile)
	} else {
		fmt.Println("  chainwatch exec -- <command>")
	}

	if initInstallSystemd {
		fmt.Println()
		fmt.Println("Enable systemd guard for an agent:")
		fmt.Println("  sudo systemctl enable --now chainwatch-guarded@<agent-name>")
	}

	return nil
}

// initConfigDir returns the configuration directory based on mode.
func initConfigDir() (string, error) {
	switch initMode {
	case "system":
		return "/etc/chainwatch", nil
	case "user", "":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		return filepath.Join(home, ".chainwatch"), nil
	default:
		return "", fmt.Errorf("unknown mode %q: use 'user' or 'system'", initMode)
	}
}

// writeIfMissing writes content to path if it doesn't exist or --force is set.
// Returns true if the file was written.
func writeIfMissing(path, content string) (bool, error) {
	if !initForce {
		if _, err := os.Stat(path); err == nil {
			return false, nil
		}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("create directory %s: %w", dir, err)
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}

// defaultDenylistYAML generates a commented default denylist.yaml.
func defaultDenylistYAML() (string, error) {
	data, err := yaml.Marshal(denylist.DefaultPatterns)
	if err != nil {
		return "", err
	}
	header := "# Chainwatch denylist — irreversible boundaries.\n" +
		"# Patterns are matched against tool calls at runtime.\n" +
		"# URLs: regex patterns. Files: glob patterns. Commands: substring match.\n" +
		"#\n" +
		"# Edit this file to customize what chainwatch blocks.\n" +
		"# See: chainwatch exec --help\n\n"
	return header + string(data), nil
}
