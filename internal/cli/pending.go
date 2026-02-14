package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/approval"
)

func init() {
	rootCmd.AddCommand(pendingCmd)
}

var pendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List pending approval requests",
	Long:  "Shows all approval requests in the store with their status, resource, and timestamps.",
	RunE:  runPending,
}

func runPending(cmd *cobra.Command, args []string) error {
	store, err := approval.NewStore(approval.DefaultDir())
	if err != nil {
		return fmt.Errorf("failed to open approval store: %w", err)
	}

	list, err := store.List()
	if err != nil {
		return fmt.Errorf("failed to list approvals: %w", err)
	}

	if len(list) == 0 {
		fmt.Println("No pending approvals.")
		return nil
	}

	fmt.Printf("%-25s %-12s %-40s %s\n", "KEY", "STATUS", "RESOURCE", "CREATED")
	for _, a := range list {
		fmt.Printf("%-25s %-12s %-40s %s\n",
			a.Key,
			a.Status,
			truncate(a.Resource, 40),
			a.CreatedAt.Format("15:04:05"),
		)
	}
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
