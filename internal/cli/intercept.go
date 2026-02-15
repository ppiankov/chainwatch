package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/intercept"
)

var (
	interceptPort     int
	interceptUpstream string
	interceptDenylist string
	interceptPolicy   string
	interceptProfile  string
	interceptPurpose  string
	interceptAuditLog string
)

func init() {
	rootCmd.AddCommand(interceptCmd)
	interceptCmd.Flags().IntVar(&interceptPort, "port", 9999, "Port to listen on")
	interceptCmd.Flags().StringVar(&interceptUpstream, "upstream", "https://api.anthropic.com", "Upstream LLM API URL")
	interceptCmd.Flags().StringVar(&interceptDenylist, "denylist", "", "Path to denylist YAML (default: ~/.chainwatch/denylist.yaml)")
	interceptCmd.Flags().StringVar(&interceptPolicy, "policy", "", "Path to policy YAML (default: ~/.chainwatch/policy.yaml)")
	interceptCmd.Flags().StringVar(&interceptProfile, "profile", "", "Safety profile to apply (e.g., clawbot)")
	interceptCmd.Flags().StringVar(&interceptPurpose, "purpose", "general", "Purpose identifier for policy evaluation")
	interceptCmd.Flags().StringVar(&interceptAuditLog, "audit-log", "", "Path to audit log JSONL file")
}

var interceptCmd = &cobra.Command{
	Use:   "intercept",
	Short: "Start reverse proxy intercepting LLM tool-call responses",
	Long:  "Reverse proxy between agent and LLM API that inspects tool_use/function_call blocks\nin LLM responses before the agent acts on them.\nUsage: ANTHROPIC_BASE_URL=http://localhost:9999 python agent.py",
	RunE:  runIntercept,
}

func runIntercept(cmd *cobra.Command, args []string) error {
	cfg := intercept.Config{
		Port:         interceptPort,
		Upstream:     interceptUpstream,
		DenylistPath: interceptDenylist,
		PolicyPath:   interceptPolicy,
		ProfileName:  interceptProfile,
		Purpose:      interceptPurpose,
		Actor:        map[string]any{"intercept": "chainwatch", "port": interceptPort},
		AuditLogPath: interceptAuditLog,
	}

	srv, err := intercept.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to create intercept server: %w", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\nShutting down interceptor...")
		cancel()
	}()

	fmt.Printf("chainwatch interceptor listening on :%d\n", interceptPort)
	fmt.Printf("Upstream: %s\n", interceptUpstream)
	fmt.Printf("Set ANTHROPIC_BASE_URL=http://localhost:%d to route agent traffic\n", interceptPort)
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	err = srv.Start(ctx)

	fmt.Println()
	fmt.Println("Trace summary:")
	summary := srv.TraceSummary()
	out, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Println(string(out))

	return err
}
