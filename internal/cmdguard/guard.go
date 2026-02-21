package cmdguard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ppiankov/chainwatch/internal/alert"
	"github.com/ppiankov/chainwatch/internal/approval"
	"github.com/ppiankov/chainwatch/internal/audit"
	"github.com/ppiankov/chainwatch/internal/breakglass"
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
	AgentID      string
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
	bgStore    *breakglass.Store
	dispatcher *alert.Dispatcher
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

	bgStore, _ := breakglass.NewStore(breakglass.DefaultDir())

	return &Guard{
		cfg:        cfg,
		dl:         dl,
		policyCfg:  policyCfg,
		approvals:  approvalStore,
		bgStore:    bgStore,
		dispatcher: alert.NewDispatcher(policyCfg.Alerts),
		tracer:     tracer.NewAccumulator(tracer.NewTraceID()),
		auditLog:   auditLog,
		policyHash: policyHash,
	}, nil
}

// Run evaluates policy for the command, executes if allowed, and records trace.
func (g *Guard) Run(ctx context.Context, name string, args []string, stdin io.Reader) (*Result, error) {
	action := buildActionFromCommand(name, args)

	g.mu.Lock()
	result := policy.Evaluate(action, g.tracer.State, g.cfg.Purpose, g.cfg.AgentID, g.dl, g.policyCfg)
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
			Tier:       result.Tier,
			PolicyHash: g.policyHash,
		})
	}
	g.dispatchAlert(action, result)

	// Break-glass override (CW-23.2)
	if result.Tier >= 2 && g.bgStore != nil {
		if token := breakglass.CheckAndConsume(g.bgStore, result.Tier, action); token != nil {
			originalDecision := result.Decision
			result.Decision = model.Allow
			result.Reason = fmt.Sprintf("break-glass override (token=%s, original=%s): %s",
				token.ID, originalDecision, token.Reason)
			result.PolicyID = "breakglass.override"
			if g.auditLog != nil {
				g.auditLog.Record(audit.AuditEntry{
					Timestamp:        time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
					TraceID:          g.tracer.State.TraceID,
					Action:           audit.AuditAction{Tool: action.Tool, Resource: action.Resource},
					Decision:         "allow",
					Reason:           result.Reason,
					Tier:             result.Tier,
					PolicyHash:       g.policyHash,
					Type:             "break_glass_used",
					TokenID:          token.ID,
					OriginalDecision: string(originalDecision),
					OverriddenTo:     "allow",
					ExpiresAt:        token.ExpiresAt.Format(time.RFC3339),
				})
			}
			g.dispatchBreakGlass(action, result)
		}
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

	// Execute the command with sanitized environment.
	// Sensitive env vars (API keys, tokens) are stripped so spawned
	// processes cannot exfiltrate credentials via shell builtins.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = sanitizeEnv(os.Environ())
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

	// Scan output for leaked secrets and redact before returning.
	cleanOut, nOut := ScanOutputFull(stdout.String())
	cleanErr, nErr := ScanOutputFull(stderr.String())
	if nOut+nErr > 0 && g.auditLog != nil {
		g.auditLog.Record(audit.AuditEntry{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:    g.tracer.State.TraceID,
			Action:     audit.AuditAction{Tool: "output_scan", Resource: action.Resource},
			Decision:   "redacted",
			Reason:     fmt.Sprintf("output contained %d secret(s)", nOut+nErr),
			Tier:       3,
			PolicyHash: g.policyHash,
		})
	}

	return &Result{
		Stdout:   cleanOut,
		Stderr:   cleanErr,
		ExitCode: exitCode,
		Decision: result.Decision,
	}, nil
}

func (g *Guard) dispatchAlert(action *model.Action, result model.PolicyResult) {
	if g.dispatcher != nil {
		g.dispatcher.Dispatch(alert.AlertEvent{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:    g.tracer.State.TraceID,
			Tool:       action.Tool,
			Resource:   action.Resource,
			Decision:   string(result.Decision),
			Reason:     result.Reason,
			Tier:       result.Tier,
			PolicyHash: g.policyHash,
		})
	}
}

func (g *Guard) dispatchBreakGlass(action *model.Action, result model.PolicyResult) {
	if g.dispatcher != nil {
		g.dispatcher.Dispatch(alert.AlertEvent{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:    g.tracer.State.TraceID,
			Tool:       action.Tool,
			Resource:   action.Resource,
			Decision:   string(result.Decision),
			Reason:     result.Reason,
			Tier:       result.Tier,
			PolicyHash: g.policyHash,
			Type:       "break_glass_used",
		})
	}
}

// sensitiveEnvPrefixes are env var name prefixes that are stripped from
// subprocess environments. This prevents credential exfiltration via
// shell builtins like `set`, `declare -p`, or `env`.
var sensitiveEnvPrefixes = []string{
	"NULLBOT_",
	"GROQ_API",
	"OPENAI_API",
	"ANTHROPIC_API",
	"AWS_",
	"CHAINWATCH_",
}

// sensitiveEnvExact are env var names stripped by exact match.
var sensitiveEnvExact = []string{
	"API_KEY",
	"API_SECRET",
}

// sanitizeEnv filters sensitive environment variables from the list.
// Returns a new slice with matching entries removed.
func sanitizeEnv(environ []string) []string {
	clean := make([]string, 0, len(environ))
	for _, entry := range environ {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			clean = append(clean, entry)
			continue
		}
		upper := strings.ToUpper(name)
		skip := false
		for _, prefix := range sensitiveEnvPrefixes {
			if strings.HasPrefix(upper, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			for _, exact := range sensitiveEnvExact {
				if upper == exact {
					skip = true
					break
				}
			}
		}
		if !skip {
			clean = append(clean, entry)
		}
	}
	return clean
}

// Check evaluates policy without executing. Dry-run mode.
func (g *Guard) Check(name string, args []string) model.PolicyResult {
	action := buildActionFromCommand(name, args)

	g.mu.Lock()
	defer g.mu.Unlock()
	return policy.Evaluate(action, g.tracer.State, g.cfg.Purpose, g.cfg.AgentID, g.dl, g.policyCfg)
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
