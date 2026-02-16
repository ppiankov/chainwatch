package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/scenario"
)

var (
	checkScenario string
	checkPolicy   string
	checkDenylist string
	checkFormat   string
)

func init() {
	rootCmd.AddCommand(checkCmd)
	checkCmd.Flags().StringVar(&checkScenario, "scenario", "", "Glob pattern for scenario YAML files (required)")
	checkCmd.Flags().StringVar(&checkPolicy, "policy", "", "Path to policy YAML (optional)")
	checkCmd.Flags().StringVar(&checkDenylist, "denylist", "", "Path to denylist YAML (optional)")
	checkCmd.Flags().StringVarP(&checkFormat, "format", "f", "text", "Output format (text|json)")
	checkCmd.MarkFlagRequired("scenario")
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Run policy assertions from scenario files",
	Long: "Loads scenario YAML files matching a glob pattern, evaluates each\n" +
		"test case through the policy pipeline, and reports pass/fail.\n\n" +
		"Exit code 0 if all cases pass, 1 if any fail.\n" +
		"Use in CI to gate deployments on policy correctness.",
	RunE: runCheck,
}

func runCheck(cmd *cobra.Command, args []string) error {
	matches, err := filepath.Glob(checkScenario)
	if err != nil {
		return fmt.Errorf("invalid glob pattern: %w", err)
	}
	if len(matches) == 0 {
		return fmt.Errorf("no scenario files match pattern: %s", checkScenario)
	}

	var results []*scenario.RunResult
	for _, path := range matches {
		r, err := scenario.LoadAndRun(path, checkPolicy, checkDenylist)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		results = append(results, r)
	}

	switch checkFormat {
	case "json":
		out, err := scenario.FormatJSON(results)
		if err != nil {
			return err
		}
		fmt.Println(out)
	default:
		fmt.Print(scenario.FormatText(results))
	}

	// Exit 1 if any scenario has failures
	for _, r := range results {
		if r.Failed > 0 {
			os.Exit(1)
		}
	}

	return nil
}
