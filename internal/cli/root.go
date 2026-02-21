package cli

import (
	"fmt"
	"os"

	"github.com/ppiankov/chainwatch/internal/integrity"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "chainwatch",
	Short: "Runtime control plane for AI agent safety",
	Long:  "Intercepts tool calls at irreversible boundaries — payments, credentials, data destruction, external communication. Enforcement, not observability.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := integrity.Verify(); err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
			os.Exit(78) // EX_CONFIG
		}
		return nil
	},
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
