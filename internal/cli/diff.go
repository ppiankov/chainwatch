package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/policy"
	"github.com/ppiankov/chainwatch/internal/policydiff"
)

var diffFormat string

func init() {
	rootCmd.AddCommand(diffCmd)
	diffCmd.Flags().StringVarP(&diffFormat, "format", "f", "text", "Output format (text|json)")
}

var diffCmd = &cobra.Command{
	Use:   "diff <old.yaml> <new.yaml>",
	Short: "Compare two policy files and show changes",
	Long:  "Loads two policy YAML files and shows what changed in human-readable terms:\nthresholds, sensitivity weights, enforcement mode, rules added/removed/changed.",
	Args:  cobra.ExactArgs(2),
	RunE:  runDiff,
}

func runDiff(cmd *cobra.Command, args []string) error {
	oldCfg, err := policy.LoadConfig(args[0])
	if err != nil {
		return fmt.Errorf("load old policy: %w", err)
	}

	newCfg, err := policy.LoadConfig(args[1])
	if err != nil {
		return fmt.Errorf("load new policy: %w", err)
	}

	result := policydiff.Diff(oldCfg, newCfg)
	result.OldPath = args[0]
	result.NewPath = args[1]

	switch diffFormat {
	case "json":
		out, err := policydiff.FormatJSON(result)
		if err != nil {
			return err
		}
		fmt.Println(out)
	default:
		fmt.Print(policydiff.FormatText(result))
	}

	return nil
}
