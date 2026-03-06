package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ppiankov/chainwatch/internal/inventory"
	"github.com/ppiankov/chainwatch/internal/orchestrator"
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

	rootCmd.SetOut(out)
	rootCmd.SetErr(errOut)
	rootCmd.AddCommand(notifyCmd)
	rootCmd.AddCommand(statusCmd)
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
