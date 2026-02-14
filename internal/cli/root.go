package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "chainwatch",
	Short: "Runtime control plane for AI agent safety",
	Long:  "Intercepts tool calls at irreversible boundaries — payments, credentials, data destruction, external communication. Enforcement, not observability.",
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
