package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/policy"
)

func init() {
	rootCmd.AddCommand(initPolicyCmd)
}

var initPolicyCmd = &cobra.Command{
	Use:   "init-policy",
	Short: "Generate default policy.yaml with comments",
	Long:  "Creates ~/.chainwatch/policy.yaml with default thresholds, weights, and rules.\nEdit this file to customize chainwatch policy behavior.",
	RunE:  runInitPolicy,
}

func runInitPolicy(cmd *cobra.Command, args []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	dir := filepath.Join(home, ".chainwatch")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cannot create config directory: %w", err)
	}

	path := filepath.Join(dir, "policy.yaml")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("policy.yaml already exists at %s", path)
	}

	content := policy.DefaultConfigYAML()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write policy.yaml: %w", err)
	}

	fmt.Printf("Created %s\n", path)
	return nil
}
