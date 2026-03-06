package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/profile"
)

var seccompOutput string

func init() {
	profileCmd.AddCommand(profileSeccompCmd)
	profileSeccompCmd.Flags().StringVarP(&seccompOutput, "output", "o", "", "Output path for seccomp JSON (default: stdout)")
}

var profileSeccompCmd = &cobra.Command{
	Use:   "seccomp [name]",
	Short: "Generate a Docker-compatible seccomp profile from chainwatch policy",
	Long: "Generates seccomp JSON using chainwatch default command boundaries and,\n" +
		"if provided, the selected profile execution boundaries.",
	Args: cobra.MaximumNArgs(1),
	RunE: runProfileSeccomp,
}

func runProfileSeccomp(cmd *cobra.Command, args []string) error {
	var p *profile.Profile
	var err error

	if len(args) == 1 {
		p, err = profile.Load(args[0])
		if err != nil {
			return fmt.Errorf("failed to load profile %q: %w", args[0], err)
		}
	}

	data, err := profile.GenerateSeccompJSON(p)
	if err != nil {
		return err
	}

	if seccompOutput == "" {
		fmt.Println(string(data))
		return nil
	}

	outDir := filepath.Dir(seccompOutput)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(seccompOutput, data, 0o644); err != nil {
		return fmt.Errorf("write seccomp profile: %w", err)
	}

	if len(args) == 1 {
		fmt.Printf("Generated seccomp profile for %q: %s\n", args[0], seccompOutput)
	} else {
		fmt.Printf("Generated default seccomp profile: %s\n", seccompOutput)
	}
	fmt.Printf("Try: docker run --rm --security-opt seccomp=%s alpine:3.20 true\n", seccompOutput)
	return nil
}
