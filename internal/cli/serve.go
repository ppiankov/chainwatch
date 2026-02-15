package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/server"
)

var (
	servePort     int
	serveDenylist string
	servePolicy   string
	serveProfile  string
	serveAuditLog string
)

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntVar(&servePort, "port", 50051, "gRPC listen port")
	serveCmd.Flags().StringVar(&serveDenylist, "denylist", "", "Path to denylist YAML")
	serveCmd.Flags().StringVar(&servePolicy, "policy", "", "Path to policy YAML")
	serveCmd.Flags().StringVar(&serveProfile, "profile", "", "Safety profile to apply (e.g., clawbot)")
	serveCmd.Flags().StringVar(&serveAuditLog, "audit-log", "", "Path to audit log JSONL file")
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start gRPC policy server",
	Long:  "Runs chainwatch as a central policy server over gRPC.\nMultiple agents connect as clients for remote policy evaluation.\nSupports hot-reload of policy and denylist files.",
	RunE:  runServe,
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg := server.Config{
		Port:         servePort,
		PolicyPath:   servePolicy,
		DenylistPath: serveDenylist,
		ProfileName:  serveProfile,
		AuditLogPath: serveAuditLog,
	}

	srv, err := server.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}
	defer srv.Close()

	// Start hot-reload watcher for policy and denylist files
	watchPaths := []string{servePolicy, serveDenylist}
	reloader, err := server.NewReloader(srv, watchPaths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: hot-reload disabled: %v\n", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if reloader != nil {
		go reloader.Run(ctx)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nShutting down policy server...")
		cancel()
		srv.GracefulStop()
	}()

	fmt.Fprintf(os.Stderr, "chainwatch policy server listening on :%d\n", servePort)
	if serveProfile != "" {
		fmt.Fprintf(os.Stderr, "Profile: %s\n", serveProfile)
	}
	if servePolicy != "" {
		fmt.Fprintf(os.Stderr, "Policy: %s (hot-reload enabled)\n", servePolicy)
	}
	fmt.Fprintln(os.Stderr)

	return srv.Serve()
}
