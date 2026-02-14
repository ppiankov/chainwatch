package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/approval"
)

func init() {
	rootCmd.AddCommand(denyCmd)
}

var denyCmd = &cobra.Command{
	Use:   "deny <key>",
	Short: "Explicitly deny an approval request",
	Long:  "Denies a pending approval request. The agent will continue to be blocked for this key.",
	Args:  cobra.ExactArgs(1),
	RunE:  runDeny,
}

func runDeny(cmd *cobra.Command, args []string) error {
	key := args[0]

	store, err := approval.NewStore(approval.DefaultDir())
	if err != nil {
		return fmt.Errorf("failed to open approval store: %w", err)
	}

	if err := store.Deny(key); err != nil {
		return err
	}

	fmt.Printf("Denied %q\n", key)
	return nil
}
