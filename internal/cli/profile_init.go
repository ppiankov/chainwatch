package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/profile"
)

var initOutput string

func init() {
	profileCmd.AddCommand(profileInitCmd)
	profileInitCmd.Flags().StringVarP(&initOutput, "output", "o", "", "Output path (default: ~/.chainwatch/profiles/<name>.yaml)")
}

var profileInitCmd = &cobra.Command{
	Use:   "init <name>",
	Short: "Generate a starter profile template",
	Long:  "Creates a commented YAML profile template that you can customize for your agent.",
	Args:  cobra.ExactArgs(1),
	RunE:  runProfileInit,
}

func runProfileInit(cmd *cobra.Command, args []string) error {
	name := args[0]

	outPath := initOutput
	if outPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}
		outPath = filepath.Join(home, ".chainwatch", "profiles", name+".yaml")
	}

	// Refuse to overwrite existing files
	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("file already exists: %s (remove it first or use --output)", outPath)
	}

	// Ensure parent directory exists
	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	content := profile.InitProfile(name)
	if err := os.WriteFile(outPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write profile: %w", err)
	}

	fmt.Printf("Created profile template: %s\n", outPath)
	fmt.Printf("Edit it, then validate with: chainwatch profile check %s\n", name)
	return nil
}
