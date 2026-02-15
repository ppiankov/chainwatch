package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/breakglass"
)

var (
	bgReason   string
	bgDuration time.Duration
)

func init() {
	rootCmd.AddCommand(breakGlassCmd)
	breakGlassCmd.AddCommand(breakGlassListCmd)
	breakGlassCmd.AddCommand(breakGlassRevokeCmd)
	breakGlassCmd.Flags().StringVar(&bgReason, "reason", "", "Mandatory reason for break-glass (required)")
	breakGlassCmd.Flags().DurationVar(&bgDuration, "duration", 10*time.Minute, "Token validity period (max 1h)")
}

var breakGlassCmd = &cobra.Command{
	Use:   "break-glass",
	Short: "Issue a break-glass emergency override token",
	Long:  "Creates a time-limited, single-use token that allows one tier 2+ action\nto bypass normal enforcement. Self-targeting actions (chainwatch binary,\nconfig, logs) are immune to break-glass.",
	RunE:  runBreakGlassCreate,
}

var breakGlassListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all break-glass tokens",
	RunE:  runBreakGlassList,
}

var breakGlassRevokeCmd = &cobra.Command{
	Use:   "revoke [token-id]",
	Short: "Revoke a break-glass token",
	Args:  cobra.ExactArgs(1),
	RunE:  runBreakGlassRevoke,
}

func runBreakGlassCreate(cmd *cobra.Command, args []string) error {
	if bgReason == "" {
		return fmt.Errorf("--reason is required")
	}

	store, err := breakglass.NewStore(breakglass.DefaultDir())
	if err != nil {
		return fmt.Errorf("failed to create breakglass store: %w", err)
	}

	token, err := store.Create(bgReason, bgDuration)
	if err != nil {
		return err
	}

	fmt.Printf("Break-glass token issued: %s\n", token.ID)
	fmt.Printf("Reason:  %s\n", token.Reason)
	fmt.Printf("Expires: %s\n", token.ExpiresAt.Format(time.RFC3339))
	fmt.Println()
	fmt.Println("This token covers ONE tier 2+ action, then expires.")
	fmt.Println("Self-targeting actions (chainwatch binary, config, logs) are immune.")

	return nil
}

func runBreakGlassList(cmd *cobra.Command, args []string) error {
	store, err := breakglass.NewStore(breakglass.DefaultDir())
	if err != nil {
		return fmt.Errorf("failed to create breakglass store: %w", err)
	}

	tokens, err := store.List()
	if err != nil {
		return err
	}

	if len(tokens) == 0 {
		fmt.Println("No break-glass tokens.")
		return nil
	}

	fmt.Printf("%-20s %-10s %-30s %-25s\n", "ID", "STATUS", "REASON", "EXPIRES")
	for _, t := range tokens {
		status := "active"
		if t.UsedAt != nil {
			status = "used"
		} else if t.RevokedAt != nil {
			status = "revoked"
		} else if !t.IsActive() {
			status = "expired"
		}

		reason := t.Reason
		if len(reason) > 28 {
			reason = reason[:28] + ".."
		}

		fmt.Printf("%-20s %-10s %-30s %-25s\n",
			t.ID, status, reason, t.ExpiresAt.Format(time.RFC3339))
	}

	return nil
}

func runBreakGlassRevoke(cmd *cobra.Command, args []string) error {
	store, err := breakglass.NewStore(breakglass.DefaultDir())
	if err != nil {
		return fmt.Errorf("failed to create breakglass store: %w", err)
	}

	if err := store.Revoke(args[0]); err != nil {
		return err
	}

	fmt.Printf("Revoked token %s\n", args[0])
	return nil
}
