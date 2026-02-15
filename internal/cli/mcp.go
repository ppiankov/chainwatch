package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	chainmcp "github.com/ppiankov/chainwatch/internal/mcp"
)

var (
	mcpDenylist string
	mcpPolicy   string
	mcpProfile  string
	mcpPurpose  string
)

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.Flags().StringVar(&mcpDenylist, "denylist", "", "Path to denylist YAML")
	mcpCmd.Flags().StringVar(&mcpPolicy, "policy", "", "Path to policy YAML")
	mcpCmd.Flags().StringVar(&mcpProfile, "profile", "", "Safety profile to apply (e.g., clawbot)")
	mcpCmd.Flags().StringVar(&mcpPurpose, "purpose", "general", "Purpose identifier for policy evaluation")
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start MCP tool server for agent integration",
	Long:  "Runs chainwatch as an MCP (Model Context Protocol) server over stdio.\nExposes policy-enforced tools: exec, http, check, approve, pending.",
	RunE:  runMCP,
}

func runMCP(cmd *cobra.Command, args []string) error {
	cfg := chainmcp.Config{
		DenylistPath: mcpDenylist,
		PolicyPath:   mcpPolicy,
		ProfileName:  mcpProfile,
		Purpose:      mcpPurpose,
	}

	srv, err := chainmcp.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create MCP server: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nShutting down MCP server...")
		cancel()
	}()

	fmt.Fprintln(os.Stderr, "chainwatch MCP server running on stdio")
	if mcpProfile != "" {
		fmt.Fprintf(os.Stderr, "Profile: %s\n", mcpProfile)
	}
	fmt.Fprintln(os.Stderr)

	err = srv.Run(ctx)

	// Print trace summary on exit
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Trace summary:")
	summary := srv.TraceSummary()
	out, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Fprintln(os.Stderr, string(out))

	return err
}
