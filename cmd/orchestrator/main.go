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
	"strings"
	"time"

	"github.com/ppiankov/chainwatch/internal/inventory"
	"github.com/ppiankov/chainwatch/internal/jira"
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

	rootCmd.SetOut(out)
	rootCmd.SetErr(errOut)
	rootCmd.AddCommand(notifyCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(transitionCmd)
	rootCmd.AddCommand(dispatchCmd)
	rootCmd.AddCommand(scheduleCmd)
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
