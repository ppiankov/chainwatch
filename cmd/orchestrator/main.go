package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ppiankov/chainwatch/internal/inventory"
	"github.com/ppiankov/chainwatch/internal/jira"
	"github.com/ppiankov/chainwatch/internal/metrics"
	"github.com/ppiankov/chainwatch/internal/observe"
	"github.com/ppiankov/chainwatch/internal/orchestrator"
	"github.com/ppiankov/chainwatch/internal/schedule"
	"github.com/spf13/cobra"
)

func main() {
	cmd := newRootCmd(os.Stdin, os.Stdout, os.Stderr, time.Now)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "orchestrator: %v\n", err)
		os.Exit(1)
	}
}

type senderFactory func(string) orchestrator.Sender

const statusTimeLayout = "2006-01-02 15:04:05 UTC"
const defaultVerifyScopeFromInventory = "/var/lib/clickhouse"

func newRootCmd(
	in io.Reader,
	out io.Writer,
	errOut io.Writer,
	nowFn func() time.Time,
) *cobra.Command {
	return newRootCmdWithFactory(
		in,
		out,
		errOut,
		nowFn,
		func(webhookURL string) orchestrator.Sender {
			return orchestrator.NewSlackWebhookSender(webhookURL, nil)
		},
	)
}

func newRootCmdWithFactory(
	in io.Reader,
	out io.Writer,
	errOut io.Writer,
	nowFn func() time.Time,
	makeSender senderFactory,
) *cobra.Command {
	if makeSender == nil {
		makeSender = func(webhookURL string) orchestrator.Sender {
			return orchestrator.NewSlackWebhookSender(webhookURL, nil)
		}
	}

	rootCmd := &cobra.Command{
		Use:   "orchestrator",
		Short: "Dispatch and lifecycle command surface for work orders",
	}

	var (
		inventoryPath string
		eventsPath    string
		dryRun        bool

		statusWOID    string
		statusAll     bool
		statusState   string
		lifecyclePath string

		transitionWOID string
		transitionTo   string
		transitionDB   string
	)

	notifyCmd := &cobra.Command{
		Use:   "notify",
		Short: "Route finding and WO lifecycle notifications to Slack",
		RunE: func(cmd *cobra.Command, _ []string) error {
			inv, err := inventory.Load(inventoryPath)
			if err != nil {
				return fmt.Errorf("load inventory: %w", err)
			}

			reader, err := resolveEventsReader(eventsPath, in)
			if err != nil {
				return err
			}

			input, err := orchestrator.ParseInput(reader)
			if err != nil {
				return err
			}

			cfg := orchestrator.Config{
				Channel:         inv.Notifications.Slack.Channel,
				CriticalChannel: inv.Notifications.Slack.CriticalChannel,
				DigestSchedule:  inv.Notifications.Slack.DigestSchedule,
				StalePRHours:    inv.Notifications.Slack.StalePRHours,
			}

			var sender orchestrator.Sender
			if !dryRun {
				webhookEnv := inv.Notifications.Slack.WebhookEnv
				webhookURL := strings.TrimSpace(os.Getenv(webhookEnv))
				if webhookURL == "" {
					return fmt.Errorf(
						"slack webhook URL is not set in environment variable %q",
						webhookEnv,
					)
				}
				sender = makeSender(webhookURL)
			}

			service := orchestrator.NewService(sender, nowFn)
			result, err := service.Notify(context.Background(), input, cfg, dryRun)
			if err != nil {
				return err
			}

			if len(result.Messages) == 0 {
				_, _ = fmt.Fprintln(out, "no notification messages generated")
				return nil
			}

			if dryRun {
				for i, msg := range result.Messages {
					_, _ = fmt.Fprintf(out, "[%d] channel=%s\n%s\n\n", i+1, msg.Channel, msg.Text)
				}
				_, _ = fmt.Fprintf(
					out,
					"dry-run complete: %d message(s) generated, 0 sent\n",
					len(result.Messages),
				)
				return nil
			}

			_, _ = fmt.Fprintf(out, "sent %d Slack message(s)\n", result.Sent)
			return nil
		},
	}

	notifyCmd.Flags().StringVar(
		&inventoryPath,
		"inventory",
		"inventory.yaml",
		"path to inventory.yaml",
	)
	notifyCmd.Flags().StringVar(
		&eventsPath,
		"events",
		"",
		"path to notifications payload JSON (defaults to stdin)",
	)
	notifyCmd.Flags().BoolVar(&dryRun, "dry-run", false, "show messages without sending")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show WO lifecycle status from SQLite",
		RunE: func(cmd *cobra.Command, _ []string) error {
			store := orchestrator.NewLifecycleStore(lifecyclePath, nowFn)
			if store == nil {
				return fmt.Errorf("lifecycle store is nil")
			}

			woID := strings.TrimSpace(statusWOID)
			stateFilter := strings.TrimSpace(statusState)

			if statusAll {
				if woID != "" {
					return fmt.Errorf("--wo and --all cannot be used together")
				}

				filter := orchestrator.LifecycleState("")
				if stateFilter != "" {
					parsed, err := orchestrator.ParseLifecycleState(stateFilter)
					if err != nil {
						return err
					}
					filter = parsed
				}

				rows, err := store.ListCurrentStatuses(filter)
				if err != nil {
					return err
				}
				if len(rows) == 0 {
					_, _ = fmt.Fprintln(out, "no work orders found")
					return nil
				}

				for _, row := range rows {
					line := fmt.Sprintf("%s [%s]", row.WOID, row.CurrentState)
					if row.Finding != "" {
						line += fmt.Sprintf(" | finding: %s", row.Finding)
					}
					if row.PRURL != "" {
						line += fmt.Sprintf(" | PR: %s", row.PRURL)
					}
					_, _ = fmt.Fprintln(out, line)
				}
				return nil
			}

			if stateFilter != "" {
				return fmt.Errorf("--state requires --all")
			}
			if woID == "" {
				return fmt.Errorf("either --wo or --all is required")
			}

			status, err := store.GetWOStatus(woID)
			if err != nil {
				if errors.Is(err, orchestrator.ErrWorkOrderNotFound) {
					return fmt.Errorf("work order %q not found", woID)
				}
				return err
			}

			_, _ = fmt.Fprintf(out, "WO: %s\n", status.WOID)
			_, _ = fmt.Fprintf(out, "Current state: %s\n", status.CurrentState)
			if status.Finding != "" {
				_, _ = fmt.Fprintf(out, "Finding: %s\n", status.Finding)
			}
			if status.PRURL != "" {
				_, _ = fmt.Fprintf(out, "PR: %s\n", status.PRURL)
			}

			transitionByState := make(map[orchestrator.LifecycleState]time.Time, len(status.Transitions))
			for _, transition := range status.Transitions {
				transitionByState[transition.ToState] = transition.TransitionedAt
			}

			_, _ = fmt.Fprintln(out, "Timeline:")
			for _, state := range orchestrator.OrderedLifecycleStates() {
				timestamp, ok := transitionByState[state]
				if !ok || timestamp.IsZero() {
					_, _ = fmt.Fprintf(out, "  %s: -\n", state)
					continue
				}
				_, _ = fmt.Fprintf(out, "  %s: %s\n", state, formatStatusTimestamp(timestamp))
			}

			return nil
		},
	}
	statusCmd.Flags().StringVar(&statusWOID, "wo", "", "work order ID to inspect")
	statusCmd.Flags().BoolVar(&statusAll, "all", false, "list all work orders with current state")
	statusCmd.Flags().StringVar(&statusState, "state", "", "filter current state (used with --all)")
	statusCmd.Flags().StringVar(
		&lifecyclePath,
		"db",
		defaultLifecycleDBPath(),
		"path to orchestrator lifecycle SQLite database",
	)

	transitionCmd := &cobra.Command{
		Use:   "transition",
		Short: "Record a manual WO lifecycle transition",
		RunE: func(cmd *cobra.Command, _ []string) error {
			woID := strings.TrimSpace(transitionWOID)
			if woID == "" {
				return fmt.Errorf("--wo is required")
			}
			if strings.TrimSpace(transitionTo) == "" {
				return fmt.Errorf("--to is required")
			}

			toState, err := orchestrator.ParseLifecycleState(transitionTo)
			if err != nil {
				return err
			}

			store := orchestrator.NewLifecycleStore(transitionDB, nowFn)
			status, err := store.GetWOStatus(woID)
			if err != nil {
				if errors.Is(err, orchestrator.ErrWorkOrderNotFound) {
					return fmt.Errorf("work order %q not found", woID)
				}
				return err
			}

			if err := store.RecordTransition(orchestrator.LifecycleTransition{
				WOID:    woID,
				ToState: toState,
			}); err != nil {
				return err
			}

			_, _ = fmt.Fprintf(
				out,
				"recorded transition %s: %s -> %s\n",
				woID,
				status.CurrentState,
				toState,
			)
			return nil
		},
	}
	transitionCmd.Flags().StringVar(&transitionWOID, "wo", "", "work order ID to transition")
	transitionCmd.Flags().StringVar(&transitionTo, "to", "", "target lifecycle state")
	transitionCmd.Flags().StringVar(
		&transitionDB,
		"db",
		defaultLifecycleDBPath(),
		"path to orchestrator lifecycle SQLite database",
	)

	var (
		dispatchInventoryPath string
		dispatchInputPath     string
		dispatchDryRun        bool
		dispatchDBPath        string
	)

	dispatchCmd := &cobra.Command{
		Use:   "dispatch",
		Short: "Route WO tasks to execution agents and create JIRA tickets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			inv, err := inventory.Load(dispatchInventoryPath)
			if err != nil {
				return fmt.Errorf("load inventory: %w", err)
			}

			reader, err := resolveEventsReader(dispatchInputPath, in)
			if err != nil {
				return err
			}

			input, err := orchestrator.ParseDispatchInput(reader)
			if err != nil {
				return err
			}

			if len(input.Tasks) == 0 {
				_, _ = fmt.Fprintln(out, "no tasks to dispatch")
				return nil
			}

			store := orchestrator.NewLifecycleStore(dispatchDBPath, nowFn)

			cfg := orchestrator.DispatcherConfig{
				LifecycleStore: store,
				JIRABaseURL:    inv.Orchestrator.JIRA.BaseURL,
				DryRun:         dispatchDryRun,
				NowFn:          nowFn,
			}

			// Wire up JIRA client if configured.
			jiraCfg := inv.Orchestrator.JIRA
			if jiraCfg.BaseURL != "" && jiraCfg.Token != "" {
				jiraClient := jira.NewClient(jira.ClientConfig{
					BaseURL:  jiraCfg.BaseURL,
					Token:    jiraCfg.Token,
					Project:  jiraCfg.Project,
					Assignee: jiraCfg.Assignee,
				})
				cfg.JIRACreator = jiraClient
			}

			// Wire up Slack notification if configured.
			if !dispatchDryRun {
				webhookEnv := inv.Notifications.Slack.WebhookEnv
				webhookURL := strings.TrimSpace(os.Getenv(webhookEnv))
				if webhookURL != "" {
					sender := makeSender(webhookURL)
					svc := orchestrator.NewService(sender, nowFn)
					cfg.NotifyService = svc
					cfg.NotifyConfig = orchestrator.Config{
						Channel:         inv.Notifications.Slack.Channel,
						CriticalChannel: inv.Notifications.Slack.CriticalChannel,
						DigestSchedule:  inv.Notifications.Slack.DigestSchedule,
						StalePRHours:    inv.Notifications.Slack.StalePRHours,
					}
				}
			}

			dispatcher := orchestrator.NewDispatcher(cfg)
			results, err := dispatcher.Dispatch(context.Background(), input)
			if err != nil {
				return err
			}

			for _, r := range results {
				line := fmt.Sprintf("%s → %s", r.WOID, r.Routed)
				if r.JIRAKey != "" {
					line += fmt.Sprintf(" | JIRA: %s", r.JIRAKey)
				}
				if r.PRURL != "" {
					line += fmt.Sprintf(" | PR: %s", r.PRURL)
				}
				if r.DryRun {
					line += " [dry-run]"
				}
				if r.Error != "" {
					line += fmt.Sprintf(" | error: %s", r.Error)
				}
				_, _ = fmt.Fprintln(out, line)
			}

			if dispatchDryRun {
				_, _ = fmt.Fprintf(out, "\ndry-run complete: %d task(s) routed, 0 dispatched\n", len(results))
			} else {
				_, _ = fmt.Fprintf(out, "\ndispatched %d task(s)\n", len(results))
			}

			return nil
		},
	}
	dispatchCmd.Flags().StringVar(
		&dispatchInventoryPath,
		"inventory",
		"inventory.yaml",
		"path to inventory.yaml",
	)
	dispatchCmd.Flags().StringVar(
		&dispatchInputPath,
		"input",
		"",
		"path to tokencontrol task JSON (defaults to stdin)",
	)
	dispatchCmd.Flags().BoolVar(&dispatchDryRun, "dry-run", false, "show routing without dispatching")
	dispatchCmd.Flags().StringVar(
		&dispatchDBPath,
		"db",
		defaultLifecycleDBPath(),
		"path to orchestrator lifecycle SQLite database",
	)

	var (
		verifyWOID          string
		verifyInventoryPath string
		verifyScope         string
		verifyType          string
		verifyDBPath        string
		verifyMaxRetries    int
		verifyRetryDelay    time.Duration
		verifyCluster       bool
	)

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Re-run observation after remediation and confirm drift is resolved",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			woID := strings.TrimSpace(verifyWOID)
			if woID == "" {
				return fmt.Errorf("--wo is required")
			}

			runbookType := strings.TrimSpace(verifyType)
			if runbookType == "" {
				return fmt.Errorf("--type is required")
			}

			var inv *inventory.Inventory
			if strings.TrimSpace(verifyInventoryPath) != "" {
				loaded, err := inventory.Load(verifyInventoryPath)
				if err != nil {
					return fmt.Errorf("load inventory: %w", err)
				}
				inv = loaded
			}

			scope := strings.TrimSpace(verifyScope)
			if scope == "" {
				if inv == nil {
					return fmt.Errorf("--scope is required unless --inventory is set")
				}
				scope = defaultVerifyScopeFromInventory
			}

			originalHash, err := observe.LookupFindingHashByWOID(verifyDBPath, woID)
			if err != nil {
				return err
			}

			chainwatch := strings.TrimSpace(os.Getenv("CHAINWATCH_BIN"))
			if chainwatch == "" {
				chainwatch = "chainwatch"
			}
			auditLog := strings.TrimSpace(os.Getenv("AUDIT_LOG"))
			if auditLog == "" {
				auditLog = "/tmp/nullbot-observe.jsonl"
			}

			runnerCfg := observe.RunnerConfig{
				Scope:      scope,
				Type:       runbookType,
				Cluster:    verifyCluster,
				Chainwatch: chainwatch,
				AuditLog:   auditLog,
			}

			var runner observe.VerifyRunner
			if inv != nil {
				runner = func(ctx context.Context, cfg observe.RunnerConfig) (*observe.RunResult, error) {
					return runVerifyWithInventory(ctx, cfg, inv)
				}
			}

			verifyResult, err := observe.VerifyWithRunner(ctx, observe.VerifyConfig{
				WOID:                woID,
				RunnerConfig:        runnerCfg,
				OriginalFindingHash: originalHash,
				MaxRetries:          verifyMaxRetries,
				RetryDelay:          verifyRetryDelay,
			}, runner)
			if err != nil {
				return err
			}

			_, _ = fmt.Fprintf(out, "WO: %s\n", verifyResult.WOID)
			_, _ = fmt.Fprintf(out, "Passed: %t\n", verifyResult.Passed)
			_, _ = fmt.Fprintf(out, "Attempt: %d\n", verifyResult.Attempt)
			_, _ = fmt.Fprintf(out, "Original hash: %s\n", verifyResult.OriginalHash)
			_, _ = fmt.Fprintf(out, "Current hash: %s\n", verifyResult.CurrentHash)
			_, _ = fmt.Fprintf(out, "Detail: %s\n", verifyResult.Detail)

			if !verifyResult.Passed {
				_, _ = fmt.Fprintf(out, "Lifecycle: %s\n", orchestrator.LifecycleStateApplied)
				return fmt.Errorf("drift persists for %s", woID)
			}

			store := orchestrator.NewLifecycleStore(verifyDBPath, nowFn)
			if err := orchestrator.VerifyAndTransition(ctx, store, woID, verifyResult); err != nil {
				return err
			}
			if err := observe.UpdateFindingHashStatus(
				verifyDBPath,
				originalHash,
				observe.FindingStatusClosed,
				nowFn(),
			); err != nil {
				return err
			}

			_, _ = fmt.Fprintf(out, "Lifecycle: %s\n", orchestrator.LifecycleStateVerified)
			return nil
		},
	}
	verifyCmd.Flags().StringVar(&verifyWOID, "wo", "", "work order ID to verify")
	verifyCmd.Flags().StringVar(&verifyInventoryPath, "inventory", "", "path to inventory.yaml")
	verifyCmd.Flags().StringVar(&verifyScope, "scope", "", "target scope to re-run observation against")
	verifyCmd.Flags().StringVar(&verifyType, "type", "", "runbook type to verify")
	verifyCmd.Flags().StringVar(
		&verifyDBPath,
		"db",
		defaultLifecycleDBPath(),
		"path to shared observation/lifecycle SQLite database",
	)
	verifyCmd.Flags().IntVar(&verifyMaxRetries, "retries", 1, "number of verification retries")
	verifyCmd.Flags().DurationVar(
		&verifyRetryDelay,
		"retry-delay",
		30*time.Second,
		"delay between verification retries",
	)
	verifyCmd.Flags().BoolVar(
		&verifyCluster,
		"cluster",
		false,
		"include cluster-only runbook steps during verification",
	)

	var (
		scheduleInventoryPath string
		scheduleFormat        string
	)

	scheduleCmd := &cobra.Command{
		Use:   "schedule",
		Short: "Generate schedule templates for automated nullbot observe runs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			inv, err := inventory.Load(scheduleInventoryPath)
			if err != nil {
				return fmt.Errorf("load inventory: %w", err)
			}

			switch scheduleFormat {
			case "crontab":
				result := schedule.GenerateCrontab(inv)
				if result == "" {
					_, _ = fmt.Fprintln(out, "no enabled schedules found")
					return nil
				}
				_, _ = fmt.Fprint(out, result)

			case "systemd":
				units := schedule.GenerateSystemdTimers(inv)
				if len(units) == 0 {
					_, _ = fmt.Fprintln(out, "no enabled schedules found")
					return nil
				}
				for i, unit := range units {
					_, _ = fmt.Fprintf(out, "# %s.timer\n%s", unit.Name, unit.Timer)
					_, _ = fmt.Fprintf(out, "# %s.service\n%s", unit.Name, unit.Service)
					if i < len(units)-1 {
						_, _ = fmt.Fprintln(out, "---")
					}
				}

			case "eventbridge":
				rules := schedule.GenerateEventBridgeRules(inv)
				if len(rules) == 0 {
					_, _ = fmt.Fprintln(out, "no enabled schedules found")
					return nil
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rules); err != nil {
					return fmt.Errorf("encode EventBridge rules: %w", err)
				}

			default:
				return fmt.Errorf("unsupported format %q (use crontab, systemd, or eventbridge)", scheduleFormat)
			}

			return nil
		},
	}
	scheduleCmd.Flags().StringVar(
		&scheduleInventoryPath,
		"inventory",
		"inventory.yaml",
		"path to inventory.yaml",
	)
	scheduleCmd.Flags().StringVar(
		&scheduleFormat,
		"format",
		"crontab",
		"output format: crontab, systemd, or eventbridge",
	)

	var (
		metricsObsDB       string
		metricsLifecycleDB string
		metricsFormat      string
	)

	metricsCmd := &cobra.Command{
		Use:   "metrics",
		Short: "Show pipeline metrics from observation and lifecycle databases",
		RunE: func(cmd *cobra.Command, _ []string) error {
			collector := metrics.NewCollector(metricsObsDB, metricsLifecycleDB, nowFn)

			findings, err := collector.FindingMetrics()
			if err != nil {
				return fmt.Errorf("finding metrics: %w", err)
			}
			pipeline, err := collector.PipelineMetrics()
			if err != nil {
				return fmt.Errorf("pipeline metrics: %w", err)
			}
			redaction, err := collector.RedactionMetrics()
			if err != nil {
				return fmt.Errorf("redaction metrics: %w", err)
			}

			switch metricsFormat {
			case "json":
				combined := struct {
					Findings  *metrics.FindingStats   `json:"findings"`
					Pipeline  *metrics.PipelineStats  `json:"pipeline"`
					Redaction *metrics.RedactionStats `json:"redaction"`
				}{
					Findings:  findings,
					Pipeline:  pipeline,
					Redaction: redaction,
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(combined); err != nil {
					return fmt.Errorf("encode metrics: %w", err)
				}

			case "text":
				_, _ = fmt.Fprintln(out, "Findings")
				_, _ = fmt.Fprintf(out, "  total:    %d\n", findings.TotalFindings)
				_, _ = fmt.Fprintf(out, "  open:     %d\n", findings.OpenFindings)
				_, _ = fmt.Fprintf(out, "  resolved: %d\n", findings.ResolvedFindings)
				if findings.MeanTimeToResolve > 0 {
					_, _ = fmt.Fprintf(out, "  MTTR:     %s\n", findings.MeanTimeToResolve.Truncate(time.Second))
				}
				if len(findings.FindingsByType) > 0 {
					_, _ = fmt.Fprintln(out, "  by type:")
					for t, c := range findings.FindingsByType {
						_, _ = fmt.Fprintf(out, "    %s: %d\n", t, c)
					}
				}

				_, _ = fmt.Fprintln(out, "Pipeline")
				_, _ = fmt.Fprintf(out, "  total WOs:  %d\n", pipeline.TotalWOs)
				_, _ = fmt.Fprintf(out, "  stale PRs:  %d\n", pipeline.StalePRs)
				if pipeline.MeanTimeToMerge > 0 {
					_, _ = fmt.Fprintf(out, "  avg merge:  %s\n", pipeline.MeanTimeToMerge.Truncate(time.Second))
				}
				if pipeline.MeanTimeToVerify > 0 {
					_, _ = fmt.Fprintf(out, "  avg verify: %s\n", pipeline.MeanTimeToVerify.Truncate(time.Second))
				}
				if len(pipeline.WOsByState) > 0 {
					_, _ = fmt.Fprintln(out, "  by state:")
					for s, c := range pipeline.WOsByState {
						_, _ = fmt.Fprintf(out, "    %s: %d\n", s, c)
					}
				}

				if redaction.TotalRedactions > 0 {
					_, _ = fmt.Fprintln(out, "Redaction")
					_, _ = fmt.Fprintf(out, "  total: %d\n", redaction.TotalRedactions)
				}

			default:
				return fmt.Errorf("unsupported format %q (use text or json)", metricsFormat)
			}

			return nil
		},
	}
	metricsCmd.Flags().StringVar(
		&metricsObsDB,
		"db",
		"",
		"path to observation cache SQLite database",
	)
	metricsCmd.Flags().StringVar(
		&metricsLifecycleDB,
		"lifecycle",
		defaultLifecycleDBPath(),
		"path to orchestrator lifecycle SQLite database",
	)
	metricsCmd.Flags().StringVar(
		&metricsFormat,
		"format",
		"text",
		"output format: text or json",
	)

	rootCmd.SetOut(out)
	rootCmd.SetErr(errOut)
	rootCmd.AddCommand(notifyCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(transitionCmd)
	rootCmd.AddCommand(dispatchCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(scheduleCmd)
	rootCmd.AddCommand(metricsCmd)
	return rootCmd
}

func defaultLifecycleDBPath() string {
	if explicit := strings.TrimSpace(os.Getenv("ORCHESTRATOR_DB_PATH")); explicit != "" {
		return explicit
	}
	if stateDir := strings.TrimSpace(os.Getenv("ORCHESTRATOR_STATE_DIR")); stateDir != "" {
		return filepath.Join(stateDir, "cache.db")
	}
	home, err := os.UserHomeDir()
	if err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".orchestrator", "state", "cache.db")
	}
	return filepath.Join(os.TempDir(), "orchestrator", "state", "cache.db")
}

func formatStatusTimestamp(t time.Time) string {
	return t.UTC().Format(statusTimeLayout)
}

func resolveEventsReader(eventsPath string, stdin io.Reader) (io.Reader, error) {
	if strings.TrimSpace(eventsPath) != "" {
		data, err := os.ReadFile(eventsPath)
		if err != nil {
			return nil, fmt.Errorf("read events file: %w", err)
		}
		return bytes.NewReader(data), nil
	}

	if file, ok := stdin.(*os.File); ok {
		info, err := file.Stat()
		if err != nil {
			return nil, fmt.Errorf("inspect stdin: %w", err)
		}
		if info.Mode()&os.ModeCharDevice != 0 {
			return nil, fmt.Errorf(
				"no event input provided (use --events <file> or pipe JSON on stdin)",
			)
		}
	}

	return stdin, nil
}

func cloneVerifyParams(params map[string]string) map[string]string {
	if len(params) == 0 {
		return nil
	}

	cloned := make(map[string]string, len(params))
	for key, value := range params {
		cloned[key] = value
	}
	return cloned
}

func verifyRunnerConfigForHost(
	baseCfg observe.RunnerConfig,
	cluster inventory.Cluster,
	host inventory.Host,
) observe.RunnerConfig {
	cfg := baseCfg
	cfg.ClusterName = cluster.Name
	cfg.Host = host.Name
	cfg.SSHUser = host.SSHUser
	cfg.Port = host.ClickHousePort
	cfg.ConfigRepo = cluster.ConfigRepoPath()
	cfg.ConfigPath = cluster.ConfigPathResolved()

	params := cloneVerifyParams(baseCfg.Params)
	if params == nil {
		params = make(map[string]string, 6)
	}
	params["CLUSTER"] = cluster.Name
	params["HOST"] = host.Name
	params["SSH_USER"] = host.SSHUser
	params["CLICKHOUSE_PORT"] = strconv.Itoa(host.ClickHousePort)
	params["CONFIG_REPO"] = cfg.ConfigRepo
	params["CONFIG_PATH"] = cfg.ConfigPath
	cfg.Params = params

	return cfg
}

func runVerifyWithInventory(
	ctx context.Context,
	baseCfg observe.RunnerConfig,
	inv *inventory.Inventory,
) (*observe.RunResult, error) {
	if inv == nil {
		return nil, fmt.Errorf("inventory is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	result := &observe.RunResult{
		Scope:   baseCfg.Scope,
		Type:    baseCfg.Type,
		StartAt: time.Now().UTC(),
	}

	for _, cluster := range inv.Clusters() {
		for _, host := range cluster.Hosts() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			hostCfg := verifyRunnerConfigForHost(baseCfg, cluster, host)
			hostResult, err := observe.Run(hostCfg, observe.GetRunbook(hostCfg.Type))
			if err != nil {
				result.Steps = append(result.Steps, observe.StepResult{
					Command:  hostCfg.Type,
					Purpose:  fmt.Sprintf("run verification for %s/%s", cluster.Name, host.Name),
					Output:   err.Error(),
					ExitCode: 1,
					Cluster:  cluster.Name,
					Host:     host.Name,
				})
				continue
			}

			result.Steps = append(result.Steps, hostResult.Steps...)
		}
	}

	result.EndAt = time.Now().UTC()
	return result, nil
}
