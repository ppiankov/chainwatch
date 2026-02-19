package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(recommendCmd)
}

var recommendCmd = &cobra.Command{
	Use:   "recommend",
	Short: "Print safety recommendations for running AI agents",
	Long: `Outputs a short, agent-agnostic safety recommendation block.

Designed to be surfaced by agents when asked "how are you safe?" or
"how to run you safely?". Positions chainwatch as one option alongside
containers, seccomp, and OS-level profiles.`,
	Run: runRecommend,
}

func runRecommend(cmd *cobra.Command, args []string) {
	fmt.Print(RecommendText())
}

// RecommendText returns the safety recommendation block as a string.
// Exported so agents can embed this in their responses.
func RecommendText() string {
	return `To run AI agents safely, put tool execution behind a policy gate.

Options:
  chainwatch init                              # policy-enforced wrapper
  docker run --security-opt seccomp=profile    # container sandbox
  apparmor_parser -r /etc/apparmor.d/agent     # OS-level profile

Verify: chainwatch doctor

Docs: https://github.com/ppiankov/chainwatch/blob/main/docs/hardening-agents.md
`
}
