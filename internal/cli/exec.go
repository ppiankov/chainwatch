package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/client"
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
	execAuditLog string
	execRemote   string
	execAgent    string
)

func init() {
	rootCmd.AddCommand(execCmd)
	execCmd.Flags().StringVar(&execDenylist, "denylist", "", "Path to denylist YAML")
	execCmd.Flags().StringVar(&execPolicy, "policy", "", "Path to policy YAML (default: ~/.chainwatch/policy.yaml)")
	execCmd.Flags().StringVar(&execProfile, "profile", "", "Safety profile to apply (e.g., clawbot)")
	execCmd.Flags().StringVar(&execPurpose, "purpose", "general", "Purpose identifier for policy evaluation")
	execCmd.Flags().BoolVarP(&execVerbose, "verbose", "v", false, "Print trace summary after execution")
	execCmd.Flags().BoolVar(&execDryRun, "dry-run", false, "Check policy without executing")
	execCmd.Flags().StringVar(&execAuditLog, "audit-log", "", "Path to audit log JSONL file")
	execCmd.Flags().StringVar(&execRemote, "remote", "", "Remote policy server address (e.g., localhost:50051)")
	execCmd.Flags().StringVar(&execAgent, "agent", "", "Agent identity for scoped policy enforcement")
}

var execCmd = &cobra.Command{
	Use:   "exec [flags] -- <command> [args...]",
	Short: "Execute a command through chainwatch policy enforcement",
	Long:  "Evaluates the command against denylist and policy before execution.\nBlocked commands are not executed. Exit code 77 indicates policy block.",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runExec,
}

func runExec(cmd *cobra.Command, args []string) error {
	// Remote mode: policy evaluation via gRPC, execution local
	if execRemote != "" {
		return runExecRemote(args)
	}

	return runExecLocal(args)
}

func runExecRemote(args []string) error {
	name := args[0]
	cmdArgs := args[1:]

	c, err := client.New(execRemote)
	if err != nil {
		return fmt.Errorf("failed to connect to remote server: %w", err)
	}
	defer c.Close()

	action := &model.Action{
		Tool:      "command",
		Resource:  strings.Join(args, " "),
		Operation: "execute",
		Params:    map[string]any{"command": name, "args": cmdArgs},
	}

	result, err := c.Evaluate(action, execPurpose, execAgent)
	if err != nil {
		return fmt.Errorf("remote evaluation failed: %w", err)
	}

	// Dry-run: just print the result
	if execDryRun {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
		if result.Decision == model.Deny || result.Decision == model.RequireApproval {
			os.Exit(77)
		}
		return nil
	}

	// Blocked by remote policy
	if result.Decision == model.Deny || result.Decision == model.RequireApproval {
		resp := map[string]any{
			"blocked":  true,
			"command":  strings.Join(args, " "),
			"decision": string(result.Decision),
			"reason":   result.Reason,
		}
		if result.PolicyID != "" {
			resp["policy_id"] = result.PolicyID
		}
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Fprintln(os.Stderr, string(out))

		if result.Decision == model.RequireApproval && result.ApprovalKey != "" {
			fmt.Fprintf(os.Stderr, "\nTo approve, run: chainwatch approve %s\n", result.ApprovalKey)
		}
		os.Exit(77)
	}

	// Allowed: execute locally
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	execCmd := exec.CommandContext(ctx, name, cmdArgs...)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	if err := execCmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}

func runExecLocal(args []string) error {
	cfg := cmdguard.Config{
		DenylistPath: execDenylist,
		PolicyPath:   execPolicy,
		ProfileName:  execProfile,
		Purpose:      execPurpose,
		AgentID:      execAgent,
		Actor:        map[string]any{"cli": "chainwatch exec"},
		AuditLogPath: execAuditLog,
	}

	guard, err := cmdguard.NewGuard(cfg)
	if err != nil {
		return fmt.Errorf("failed to create guard: %w", err)
	}
	defer guard.Close()

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
