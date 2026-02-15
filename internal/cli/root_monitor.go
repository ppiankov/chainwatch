package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/monitor"
	"github.com/ppiankov/chainwatch/internal/policy"
)

var (
	monitorPID        int
	monitorProfile    string
	monitorInterval   time.Duration
	monitorAuditLog   string
	monitorPolicyPath string
)

func init() {
	rootCmd.AddCommand(rootMonitorCmd)
	rootMonitorCmd.Flags().IntVar(&monitorPID, "pid", 0, "Target process PID to monitor (required)")
	rootMonitorCmd.Flags().StringVar(&monitorProfile, "profile", "", "Safety profile to apply (e.g., clawbot)")
	rootMonitorCmd.Flags().DurationVar(&monitorInterval, "poll-interval", 100*time.Millisecond, "Poll interval for process scanning")
	rootMonitorCmd.Flags().StringVar(&monitorAuditLog, "audit-log", "", "Path to audit log JSONL file")
	rootMonitorCmd.Flags().StringVar(&monitorPolicyPath, "policy", "", "Path to policy YAML (for alert webhooks)")
	rootMonitorCmd.MarkFlagRequired("pid")
}

var rootMonitorCmd = &cobra.Command{
	Use:   "root-monitor",
	Short: "Monitor and block root-level operations for an agent process",
	Long:  "Watches the process tree of the target PID and blocks dangerous operations\n(sudo, chmod 777, iptables, etc.) by killing offending processes immediately.\nRequires Linux with /proc filesystem.",
	RunE:  runRootMonitor,
}

func runRootMonitor(cmd *cobra.Command, args []string) error {
	cfg := monitor.Config{
		TargetPID:    monitorPID,
		ProfileName:  monitorProfile,
		PollInterval: monitorInterval,
		Actor:        map[string]any{"monitor": "chainwatch root-monitor", "target_pid": monitorPID},
		AuditLogPath: monitorAuditLog,
	}

	// Load alert config from policy if available
	if policyCfg, err := policy.LoadConfig(monitorPolicyPath); err == nil {
		cfg.Alerts = policyCfg.Alerts
	}

	watcher := &monitor.ProcfsWatcher{}
	mon, err := monitor.New(cfg, watcher)
	if err != nil {
		return fmt.Errorf("failed to create monitor: %w", err)
	}
	defer mon.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nShutting down root monitor...")
		cancel()
	}()

	fmt.Fprintf(os.Stderr, "chainwatch root-monitor watching PID %d\n", monitorPID)
	if monitorProfile != "" {
		fmt.Fprintf(os.Stderr, "Profile: %s\n", monitorProfile)
	}
	fmt.Fprintf(os.Stderr, "Poll interval: %s\n", monitorInterval)
	fmt.Fprintln(os.Stderr, "Press Ctrl+C to stop")
	fmt.Fprintln(os.Stderr)

	err = mon.Run(ctx)

	// Print trace summary on exit
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Trace summary:")
	summary := mon.TraceSummary()
	out, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Fprintln(os.Stderr, string(out))

	blocked := mon.BlockedCount()
	if blocked > 0 {
		fmt.Fprintf(os.Stderr, "\nBlocked %d operation(s).\n", blocked)
	}

	return err
}
