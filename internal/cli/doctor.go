package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/profile"
)

func init() {
	rootCmd.AddCommand(doctorCmd)
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system readiness and diagnose configuration issues",
	RunE:  runDoctor,
}

type checkResult struct {
	label  string
	ok     bool
	detail string
	fix    string
}

func runDoctor(cmd *cobra.Command, args []string) error {
	var checks []checkResult

	// 1. Binary location and version.
	execPath, _ := os.Executable()
	if execPath != "" {
		checks = append(checks, checkResult{
			label:  "chainwatch binary",
			ok:     true,
			detail: fmt.Sprintf("%s (v%s)", execPath, version),
		})
	} else {
		checks = append(checks, checkResult{
			label:  "chainwatch binary",
			ok:     false,
			detail: "cannot determine executable path",
		})
	}

	// 2. Config directory.
	home, homeErr := os.UserHomeDir()
	configDir := ""
	if homeErr == nil {
		configDir = filepath.Join(home, ".chainwatch")
	}

	if configDir != "" {
		if info, err := os.Stat(configDir); err == nil && info.IsDir() {
			checks = append(checks, checkResult{
				label:  "config directory",
				ok:     true,
				detail: configDir,
			})
		} else {
			checks = append(checks, checkResult{
				label:  "config directory",
				ok:     false,
				detail: "missing",
				fix:    "chainwatch init",
			})
		}
	} else {
		checks = append(checks, checkResult{
			label:  "config directory",
			ok:     false,
			detail: "cannot determine home directory",
		})
	}

	// 3. policy.yaml.
	if configDir != "" {
		policyPath := filepath.Join(configDir, "policy.yaml")
		if _, err := os.Stat(policyPath); err == nil {
			checks = append(checks, checkResult{
				label:  "policy.yaml",
				ok:     true,
				detail: "exists",
			})
		} else {
			checks = append(checks, checkResult{
				label:  "policy.yaml",
				ok:     false,
				detail: "missing",
				fix:    "chainwatch init",
			})
		}
	}

	// 4. denylist.yaml.
	if configDir != "" {
		denylistPath := filepath.Join(configDir, "denylist.yaml")
		if _, err := os.Stat(denylistPath); err == nil {
			checks = append(checks, checkResult{
				label:  "denylist.yaml",
				ok:     true,
				detail: "exists",
			})
		} else {
			checks = append(checks, checkResult{
				label:  "denylist.yaml",
				ok:     false,
				detail: "missing",
				fix:    "chainwatch init",
			})
		}
	}

	// 5. Profiles.
	profiles := profile.List()
	if len(profiles) > 0 {
		checks = append(checks, checkResult{
			label:  "profiles",
			ok:     true,
			detail: fmt.Sprintf("%d available", len(profiles)),
		})
	} else {
		checks = append(checks, checkResult{
			label:  "profiles",
			ok:     false,
			detail: "none found",
			fix:    "chainwatch init --profile <name>",
		})
	}

	// 6. systemd (Linux only).
	if runtime.GOOS == "linux" {
		unitPath := "/etc/systemd/system/chainwatch-guarded@.service"
		if _, err := os.Stat(unitPath); err == nil {
			checks = append(checks, checkResult{
				label:  "guarded@ template",
				ok:     true,
				detail: "installed",
			})
		} else {
			checks = append(checks, checkResult{
				label:  "guarded@ template",
				ok:     false,
				detail: "not installed",
				fix:    "sudo chainwatch init --install-systemd",
			})
		}
	}

	// Print results.
	hasFailures := false
	for _, c := range checks {
		mark := "\u2713" // ✓
		if !c.ok {
			mark = "\u2717" // ✗
			hasFailures = true
		}
		line := fmt.Sprintf("%s %-20s %s", mark, c.label+":", c.detail)
		if !c.ok && c.fix != "" {
			line += fmt.Sprintf("  ->  %s", c.fix)
		}
		fmt.Println(line)
	}

	if hasFailures {
		fmt.Println()
		fmt.Println("Some checks failed. Run the suggested commands to fix.")
		return fmt.Errorf("doctor found issues")
	}

	fmt.Println()
	fmt.Println("All checks passed.")
	return nil
}
