package cmdguard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"

	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/policy"
	"github.com/ppiankov/chainwatch/internal/tracer"
)

// Config holds command guard configuration.
type Config struct {
	DenylistPath string
	PolicyPath   string
	Purpose      string
	Actor        map[string]any
}

// Result captures subprocess execution outcome.
type Result struct {
	Stdout   string         `json:"stdout"`
	Stderr   string         `json:"stderr"`
	ExitCode int            `json:"exit_code"`
	Decision model.Decision `json:"decision"`
}

// BlockedError is returned when policy denies command execution.
type BlockedError struct {
	Command  string
	Decision model.Decision
	Reason   string
	PolicyID string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("command blocked (%s): %s", e.Decision, e.Reason)
}

// Guard evaluates policy and optionally executes subprocess commands.
type Guard struct {
	cfg       Config
	dl        *denylist.Denylist
	policyCfg *policy.PolicyConfig
	tracer    *tracer.TraceAccumulator
	mu        sync.Mutex
}

// NewGuard creates a Guard with loaded denylist and fresh tracer.
func NewGuard(cfg Config) (*Guard, error) {
	dl, err := denylist.Load(cfg.DenylistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load denylist: %w", err)
	}

	policyCfg, err := policy.LoadConfig(cfg.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy config: %w", err)
	}

	if cfg.Actor == nil {
		cfg.Actor = map[string]any{"guard": "chainwatch"}
	}
	if cfg.Purpose == "" {
		cfg.Purpose = "general"
	}

	return &Guard{
		cfg:       cfg,
		dl:        dl,
		policyCfg: policyCfg,
		tracer:    tracer.NewAccumulator(tracer.NewTraceID()),
	}, nil
}

// Run evaluates policy for the command, executes if allowed, and records trace.
func (g *Guard) Run(ctx context.Context, name string, args []string, stdin io.Reader) (*Result, error) {
	action := buildActionFromCommand(name, args)

	g.mu.Lock()
	result := policy.Evaluate(action, g.tracer.State, g.cfg.Purpose, g.dl, g.policyCfg)
	g.tracer.RecordAction(g.cfg.Actor, g.cfg.Purpose, action, map[string]any{
		"result":       string(result.Decision),
		"reason":       result.Reason,
		"policy_id":    result.PolicyID,
		"approval_key": result.ApprovalKey,
	}, "")
	g.mu.Unlock()

	if result.Decision == model.Deny || result.Decision == model.RequireApproval {
		return nil, &BlockedError{
			Command:  action.Resource,
			Decision: result.Decision,
			Reason:   result.Reason,
			PolicyID: result.PolicyID,
		}
	}

	// Execute the command
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if stdin != nil {
		cmd.Stdin = stdin
	}

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				exitCode = status.ExitStatus()
			}
		} else {
			return nil, err
		}
	}

	return &Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Decision: result.Decision,
	}, nil
}

// Check evaluates policy without executing. Dry-run mode.
func (g *Guard) Check(name string, args []string) model.PolicyResult {
	action := buildActionFromCommand(name, args)

	g.mu.Lock()
	defer g.mu.Unlock()
	return policy.Evaluate(action, g.tracer.State, g.cfg.Purpose, g.dl, g.policyCfg)
}

// TraceSummary exports the trace for debugging/audit.
func (g *Guard) TraceSummary() map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tracer.ToJSON()
}
