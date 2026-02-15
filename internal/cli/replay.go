package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/audit"
)

var (
	replayLog    string
	replayFrom   string
	replayTo     string
	replayFormat string
)

func init() {
	rootCmd.AddCommand(replayCmd)
	replayCmd.Flags().StringVarP(&replayLog, "log", "l", "", "Path to audit log (required)")
	replayCmd.Flags().StringVar(&replayFrom, "from", "", "Start time filter (RFC3339)")
	replayCmd.Flags().StringVar(&replayTo, "to", "", "End time filter (RFC3339)")
	replayCmd.Flags().StringVarP(&replayFormat, "format", "f", "text", "Output format (text|json)")
	replayCmd.MarkFlagRequired("log")
}

var replayCmd = &cobra.Command{
	Use:   "replay <trace-id>",
	Short: "Replay a session from the audit log",
	Long:  "Reads the audit log, filters by trace ID and optional time range,\nand renders a human-readable decision timeline with summary.",
	Args:  cobra.ExactArgs(1),
	RunE:  runReplay,
}

func runReplay(cmd *cobra.Command, args []string) error {
	traceID := args[0]

	filter := audit.ReplayFilter{TraceID: traceID}

	if replayFrom != "" {
		from, err := time.Parse(time.RFC3339, replayFrom)
		if err != nil {
			return fmt.Errorf("invalid --from time %q: %w", replayFrom, err)
		}
		filter.From = from
	}

	if replayTo != "" {
		to, err := time.Parse(time.RFC3339, replayTo)
		if err != nil {
			return fmt.Errorf("invalid --to time %q: %w", replayTo, err)
		}
		filter.To = to
	}

	result, err := audit.Replay(replayLog, filter)
	if err != nil {
		return err
	}

	switch replayFormat {
	case "json":
		out, err := audit.FormatJSON(result)
		if err != nil {
			return err
		}
		fmt.Println(out)
	default:
		fmt.Print(audit.FormatTimeline(result))
	}

	return nil
}
