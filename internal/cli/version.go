package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

const version = "1.1.0"

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		info := map[string]string{
			"version": version,
			"name":    "chainwatch",
		}
		out, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(out))
	},
}
