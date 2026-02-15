package cmdguard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/ppiankov/chainwatch/internal/approval"
	"github.com/ppiankov/chainwatch/internal/audit"
	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/policy"
	"github.com/ppiankov/chainwatch/internal/profile"
	"github.com/ppiankov/chainwatch/internal/tracer"
)

// Config holds command guard configuration.
type Config struct {
	DenylistPath string
	PolicyPath   string
	ProfileName  string
	Purpose      string
	Actor        map[string]any
	AuditLogPath string
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
	Command     string
	Decision    model.Decision
	Reason      string
	PolicyID    string
	ApprovalKey string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("command blocked (%s): %s", e.Decision, e.Reason)
}

// Guard evaluates policy and optionally executes subprocess commands.
type Guard struct {
	cfg        Config
	dl         *denylist.Denylist
	policyCfg  *policy.PolicyConfig
	approvals  *approval.Store
	tracer     *tracer.TraceAccumulator
	auditLog   *audit.Log
	policyHash string
	mu         sync.Mutex
}

// NewGuard creates a Guard with loaded denylist and fresh tracer.
func NewGuard(cfg Config) (*Guard, error) {
	dl, err := denylist.Load(cfg.DenylistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load denylist: %w", err)
	}

	policyCfg, policyHash, err := policy.LoadConfigWithHash(cfg.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy config: %w", err)
	}

	if cfg.ProfileName != "" {
		prof, err := profile.Load(cfg.ProfileName)
		if err != nil {
			return nil, fmt.Errorf("failed to load profile %q: %w", cfg.ProfileName, err)
		}
		profile.ApplyToDenylist(prof, dl)
		policyCfg = profile.ApplyToPolicy(prof, policyCfg)
	}

	approvalStore, err := approval.NewStore(approval.DefaultDir())
	if err != nil {
		return nil, fmt.Errorf("failed to create approval store: %w", err)
	}
	approvalStore.Cleanup()

	if cfg.Actor == nil {
		cfg.Actor = map[string]any{"guard": "chainwatch"}
	}
	if cfg.Purpose == "" {
		cfg.Purpose = "general"
	}

	var auditLog *audit.Log
	if cfg.AuditLogPath != "" {
		auditLog, err = audit.Open(cfg.AuditLogPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log: %w", err)
		}
	}

	return &Guard{
		cfg:        cfg,
		dl:         dl,
		policyCfg:  policyCfg,
		approvals:  approvalStore,
		tracer:     tracer.NewAccumulator(tracer.NewTraceID()),
		auditLog:   auditLog,
		policyHash: policyHash,
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

	if g.auditLog != nil {
		g.auditLog.Record(audit.AuditEntry{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:    g.tracer.State.TraceID,
			Action:     audit.AuditAction{Tool: action.Tool, Resource: action.Resource},
			Decision:   string(result.Decision),
			Reason:     result.Reason,
			PolicyHash: g.policyHash,
		})
	}

	if result.Decision == model.Deny {
		return nil, &BlockedError{
			Command:     action.Resource,
			Decision:    result.Decision,
			Reason:      result.Reason,
			PolicyID:    result.PolicyID,
			ApprovalKey: result.ApprovalKey,
		}
	}

	if result.Decision == model.RequireApproval && result.ApprovalKey != "" {
		status, _ := g.approvals.Check(result.ApprovalKey)
		if status == approval.StatusApproved {
			g.approvals.Consume(result.ApprovalKey)
			// fall through to execute
		} else {
			if status != approval.StatusPending && status != approval.StatusDenied {
				g.approvals.Request(result.ApprovalKey, result.Reason, result.PolicyID, action.Resource)
			}
			return nil, &BlockedError{
				Command:  action.Resource,
				Decision: result.Decision,
				Reason:   result.Reason,
				PolicyID: result.PolicyID,
			}
		}
	} else if result.Decision == model.RequireApproval {
		return nil, &BlockedError{
			Command:     action.Resource,
			Decision:    result.Decision,
			Reason:      result.Reason,
			PolicyID:    result.PolicyID,
			ApprovalKey: result.ApprovalKey,
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

// Close closes the audit log if configured.
func (g *Guard) Close() error {
	if g.auditLog != nil {
		return g.auditLog.Close()
	}
	return nil
}

// TraceSummary exports the trace for debugging/audit.
func (g *Guard) TraceSummary() map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tracer.ToJSON()
}
