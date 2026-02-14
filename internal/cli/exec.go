package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/cmdguard"
	"github.com/ppiankov/chainwatch/internal/model"
)

var (
	execDenylist string
	execPolicy   string
	execProfile  string
	execPurpose  string
	execVerbose  bool
	execDryRun   bool
)

func init() {
	rootCmd.AddCommand(execCmd)
	execCmd.Flags().StringVar(&execDenylist, "denylist", "", "Path to denylist YAML")
	execCmd.Flags().StringVar(&execPolicy, "policy", "", "Path to policy YAML (default: ~/.chainwatch/policy.yaml)")
	execCmd.Flags().StringVar(&execProfile, "profile", "", "Safety profile to apply (e.g., clawbot)")
	execCmd.Flags().StringVar(&execPurpose, "purpose", "general", "Purpose identifier for policy evaluation")
	execCmd.Flags().BoolVarP(&execVerbose, "verbose", "v", false, "Print trace summary after execution")
	execCmd.Flags().BoolVar(&execDryRun, "dry-run", false, "Check policy without executing")
}

var execCmd = &cobra.Command{
	Use:   "exec [flags] -- <command> [args...]",
	Short: "Execute a command through chainwatch policy enforcement",
	Long:  "Evaluates the command against denylist and policy before execution.\nBlocked commands are not executed. Exit code 77 indicates policy block.",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runExec,
}

func runExec(cmd *cobra.Command, args []string) error {
	cfg := cmdguard.Config{
		DenylistPath: execDenylist,
		PolicyPath:   execPolicy,
		ProfileName:  execProfile,
		Purpose:      execPurpose,
		Actor:        map[string]any{"cli": "chainwatch exec"},
	}

	guard, err := cmdguard.NewGuard(cfg)
	if err != nil {
		return fmt.Errorf("failed to create guard: %w", err)
	}

	name := args[0]
	cmdArgs := args[1:]

	// Dry-run mode: check policy only
	if execDryRun {
		result := guard.Check(name, cmdArgs)
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
		if result.Decision == "deny" || result.Decision == "require_approval" {
			os.Exit(77)
		}
		return nil
	}

	// Execute with policy enforcement
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	result, err := guard.Run(ctx, name, cmdArgs, os.Stdin)
	if err != nil {
		var blocked *cmdguard.BlockedError
		if errors.As(err, &blocked) {
			resp := map[string]any{
				"blocked":  true,
				"command":  blocked.Command,
				"decision": string(blocked.Decision),
				"reason":   blocked.Reason,
			}
			if blocked.PolicyID != "" {
				resp["policy_id"] = blocked.PolicyID
			}
			out, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Fprintln(os.Stderr, string(out))

			if blocked.Decision == model.RequireApproval && blocked.ApprovalKey != "" {
				fmt.Fprintf(os.Stderr, "\nTo approve, run: chainwatch approve %s\n", blocked.ApprovalKey)
			}

			if execVerbose {
				printExecTrace(guard)
			}
			os.Exit(77)
		}
		return err
	}

	// Print command output
	fmt.Print(result.Stdout)
	if result.Stderr != "" {
		fmt.Fprint(os.Stderr, result.Stderr)
	}

	if execVerbose {
		printExecTrace(guard)
	}

	if result.ExitCode != 0 {
		os.Exit(result.ExitCode)
	}
	return nil
}

func printExecTrace(guard *cmdguard.Guard) {
	summary := guard.TraceSummary()
	out, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Fprintln(os.Stderr, "\nTrace summary:")
	fmt.Fprintln(os.Stderr, string(out))
}
