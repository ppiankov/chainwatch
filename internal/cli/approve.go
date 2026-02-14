package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/approval"
)

var approveDuration time.Duration

func init() {
	rootCmd.AddCommand(approveCmd)
	approveCmd.Flags().DurationVar(&approveDuration, "duration", 0, "Validity period (e.g., 5m, 1h). Default: one-time use")
}

var approveCmd = &cobra.Command{
	Use:   "approve <key>",
	Short: "Grant approval for a require_approval action",
	Long:  "Approves a pending approval request. Without --duration, approval is one-time (consumed on first use).\nWith --duration, approval is valid for the specified period and can be reused.",
	Args:  cobra.ExactArgs(1),
	RunE:  runApprove,
}

func runApprove(cmd *cobra.Command, args []string) error {
	key := args[0]

	store, err := approval.NewStore(approval.DefaultDir())
	if err != nil {
		return fmt.Errorf("failed to open approval store: %w", err)
	}

	if err := store.Approve(key, approveDuration); err != nil {
		return err
	}

	if approveDuration > 0 {
		fmt.Printf("Approved %q for %s\n", key, approveDuration)
	} else {
		fmt.Printf("Approved %q (one-time use)\n", key)
	}
	return nil
}
