package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/sim"
)

var (
	simTrace    string
	simPolicy   string
	simDenylist string
	simPurpose  string
	simAgent    string
	simFormat   string
)

func init() {
	rootCmd.AddCommand(simulateCmd)
	simulateCmd.Flags().StringVar(&simTrace, "trace", "", "Path to audit log (required)")
	simulateCmd.Flags().StringVar(&simPolicy, "policy", "", "Path to new policy YAML (required)")
	simulateCmd.Flags().StringVar(&simDenylist, "denylist", "", "Path to denylist YAML (optional)")
	simulateCmd.Flags().StringVar(&simPurpose, "purpose", "", "Purpose string for all entries (optional)")
	simulateCmd.Flags().StringVar(&simAgent, "agent", "", "Agent ID override for all entries (optional)")
	simulateCmd.Flags().StringVarP(&simFormat, "format", "f", "text", "Output format (text|json)")
	simulateCmd.MarkFlagRequired("trace")
	simulateCmd.MarkFlagRequired("policy")
}

var simulateCmd = &cobra.Command{
	Use:   "simulate",
	Short: "Replay audit log against a new policy and show decision diffs",
	Long: "Reads a recorded audit log, replays each action through the evaluation\n" +
		"pipeline with an alternate policy file, and shows which decisions changed.\n\n" +
		"Use this to preview policy changes before deploying them.",
	RunE: runSimulate,
}

func runSimulate(cmd *cobra.Command, args []string) error {
	result, err := sim.Simulate(simTrace, simPolicy, simDenylist, simPurpose, simAgent)
	if err != nil {
		return err
	}

	switch simFormat {
	case "json":
		out, err := sim.FormatJSON(result)
		if err != nil {
			return err
		}
		fmt.Println(out)
	default:
		fmt.Print(sim.FormatText(result))
	}

	return nil
}
