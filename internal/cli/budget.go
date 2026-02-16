package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/policy"
)

var budgetPolicyPath string

func init() {
	rootCmd.AddCommand(budgetCmd)
	budgetCmd.AddCommand(budgetStatusCmd)

	budgetStatusCmd.Flags().StringVar(&budgetPolicyPath, "policy", "", "path to policy.yaml (default: ~/.chainwatch/policy.yaml)")
}

var budgetCmd = &cobra.Command{
	Use:   "budget",
	Short: "Manage budget enforcement",
	Long:  "Inspect per-agent session budget limits configured in policy.yaml.",
}

var budgetStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show configured budget limits",
	RunE:  runBudgetStatus,
}

func runBudgetStatus(cmd *cobra.Command, args []string) error {
	cfg, err := policy.LoadConfig(budgetPolicyPath)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	if len(cfg.Budgets) == 0 {
		fmt.Println("No budgets configured.")
		fmt.Println()
		fmt.Println("Add a budgets section to your policy.yaml:")
		fmt.Println("  budgets:")
		fmt.Println("    \"*\":")
		fmt.Println("      max_bytes: 536870912    # 512MB")
		fmt.Println("      max_duration: 30m")
		return nil
	}

	fmt.Printf("Budget limits (%d configured):\n\n", len(cfg.Budgets))
	for agent, bc := range cfg.Budgets {
		label := agent
		if agent == "*" {
			label = "* (global fallback)"
		}
		fmt.Printf("  %s:\n", label)
		if bc.MaxBytes > 0 {
			fmt.Printf("    max_bytes:    %d\n", bc.MaxBytes)
		}
		if bc.MaxRows > 0 {
			fmt.Printf("    max_rows:     %d\n", bc.MaxRows)
		}
		if bc.MaxDuration > 0 {
			fmt.Printf("    max_duration: %s\n", bc.MaxDuration)
		}
		fmt.Println()
	}

	return nil
}
