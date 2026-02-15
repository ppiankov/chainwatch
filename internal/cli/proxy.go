package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/proxy"
)

var (
	proxyPort     int
	proxyDenylist string
	proxyPolicy   string
	proxyProfile  string
	proxyPurpose  string
	proxyAuditLog string
)

func init() {
	rootCmd.AddCommand(proxyCmd)
	proxyCmd.Flags().IntVar(&proxyPort, "port", 8888, "Port to listen on")
	proxyCmd.Flags().StringVar(&proxyDenylist, "denylist", "", "Path to denylist YAML (default: ~/.chainwatch/denylist.yaml)")
	proxyCmd.Flags().StringVar(&proxyPolicy, "policy", "", "Path to policy YAML (default: ~/.chainwatch/policy.yaml)")
	proxyCmd.Flags().StringVar(&proxyProfile, "profile", "", "Safety profile to apply (e.g., clawbot)")
	proxyCmd.Flags().StringVar(&proxyPurpose, "purpose", "general", "Purpose identifier for policy evaluation")
	proxyCmd.Flags().StringVar(&proxyAuditLog, "audit-log", "", "Path to audit log JSONL file")
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start HTTP proxy intercepting outbound requests",
	Long:  "Forward HTTP proxy that enforces chainwatch policy on agent outbound requests.\nUsage: HTTP_PROXY=http://localhost:8888 agent run --task \"research\"",
	RunE:  runProxy,
}

func runProxy(cmd *cobra.Command, args []string) error {
	cfg := proxy.Config{
		Port:         proxyPort,
		DenylistPath: proxyDenylist,
		PolicyPath:   proxyPolicy,
		ProfileName:  proxyProfile,
		Purpose:      proxyPurpose,
		Actor:        map[string]any{"proxy": "chainwatch", "port": proxyPort},
		AuditLogPath: proxyAuditLog,
	}

	srv, err := proxy.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to create proxy server: %w", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\nShutting down proxy...")
		cancel()
	}()

	fmt.Printf("chainwatch proxy listening on :%d\n", proxyPort)
	fmt.Printf("Set HTTP_PROXY=http://localhost:%d to route agent traffic\n", proxyPort)
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	err = srv.Start(ctx)

	// Print trace summary on exit
	fmt.Println()
	fmt.Println("Trace summary:")
	summary := srv.TraceSummary()
	out, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Println(string(out))

	return err
}
