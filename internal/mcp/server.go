package mcp

import (
	"context"
	"fmt"
	"sync"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"time"

	"github.com/ppiankov/chainwatch/internal/alert"
	"github.com/ppiankov/chainwatch/internal/approval"
	"github.com/ppiankov/chainwatch/internal/audit"
	"github.com/ppiankov/chainwatch/internal/breakglass"
	"github.com/ppiankov/chainwatch/internal/cmdguard"
	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/policy"
	"github.com/ppiankov/chainwatch/internal/profile"
	"github.com/ppiankov/chainwatch/internal/tracer"
)

// Config holds MCP server configuration.
type Config struct {
	DenylistPath string
	PolicyPath   string
	ProfileName  string
	Purpose      string
	AgentID      string
	AuditLogPath string
}

// Server wraps the MCP SDK server with chainwatch policy enforcement.
type Server struct {
	mcpServer  *mcpsdk.Server
	guard      *cmdguard.Guard
	dl         *denylist.Denylist
	policyCfg  *policy.PolicyConfig
	approvals  *approval.Store
	bgStore    *breakglass.Store
	dispatcher *alert.Dispatcher
	tracer     *tracer.TraceAccumulator
	auditLog   *audit.Log
	policyHash string
	purpose    string
	agentID    string
	mu         sync.Mutex
}

// New creates an MCP server with loaded policy, denylist, and tools.
func New(cfg Config) (*Server, error) {
	// Load denylist and policy for HTTP/check tools
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

	// Create cmdguard for exec tool
	guardCfg := cmdguard.Config{
		DenylistPath: cfg.DenylistPath,
		PolicyPath:   cfg.PolicyPath,
		ProfileName:  cfg.ProfileName,
		Purpose:      cfg.Purpose,
		AgentID:      cfg.AgentID,
		Actor:        map[string]any{"mcp": "chainwatch"},
		AuditLogPath: cfg.AuditLogPath,
	}
	guard, err := cmdguard.NewGuard(guardCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create guard: %w", err)
	}

	purpose := cfg.Purpose
	if purpose == "" {
		purpose = "general"
	}

	var auditLog *audit.Log
	if cfg.AuditLogPath != "" {
		auditLog, err = audit.Open(cfg.AuditLogPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log: %w", err)
		}
	}

	bgStore, _ := breakglass.NewStore(breakglass.DefaultDir())

	s := &Server{
		guard:      guard,
		dl:         dl,
		policyCfg:  policyCfg,
		approvals:  approvalStore,
		bgStore:    bgStore,
		dispatcher: alert.NewDispatcher(policyCfg.Alerts),
		tracer:     tracer.NewAccumulator(tracer.NewTraceID()),
		auditLog:   auditLog,
		policyHash: policyHash,
		purpose:    purpose,
		agentID:    cfg.AgentID,
	}

	s.mcpServer = mcpsdk.NewServer(
		&mcpsdk.Implementation{
			Name:    "chainwatch",
			Version: "0.1.0",
		},
		nil,
	)

	s.registerTools()
	return s, nil
}

// Run starts the MCP server on stdio transport. Blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	return s.mcpServer.Run(ctx, &mcpsdk.StdioTransport{})
}

// Close closes the audit log if configured.
func (s *Server) Close() error {
	if s.auditLog != nil {
		return s.auditLog.Close()
	}
	return nil
}

// TraceSummary exports the trace for debugging/audit.
func (s *Server) TraceSummary() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tracer.ToJSON()
}

func (s *Server) dispatchAlert(action *model.Action, decision, reason string, tier int) {
	if s.dispatcher != nil {
		s.dispatcher.Dispatch(alert.AlertEvent{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:    s.tracer.State.TraceID,
			Tool:       action.Tool,
			Resource:   action.Resource,
			Decision:   decision,
			Reason:     reason,
			Tier:       tier,
			PolicyHash: s.policyHash,
		})
	}
}

func (s *Server) dispatchBreakGlass(action *model.Action, decision, reason string, tier int) {
	if s.dispatcher != nil {
		s.dispatcher.Dispatch(alert.AlertEvent{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:    s.tracer.State.TraceID,
			Tool:       action.Tool,
			Resource:   action.Resource,
			Decision:   decision,
			Reason:     reason,
			Tier:       tier,
			PolicyHash: s.policyHash,
			Type:       "break_glass_used",
		})
	}
}

func (s *Server) recordAudit(action *model.Action, decision, reason string, tier int) {
	if s.auditLog != nil {
		s.auditLog.Record(audit.AuditEntry{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:    s.tracer.State.TraceID,
			Action:     audit.AuditAction{Tool: action.Tool, Resource: action.Resource},
			Decision:   decision,
			Reason:     reason,
			Tier:       tier,
			PolicyHash: s.policyHash,
		})
	}
}

// registerTools adds all chainwatch tools to the MCP server.
func (s *Server) registerTools() {
	mcpsdk.AddTool(s.mcpServer, &mcpsdk.Tool{
		Name:        "chainwatch_exec",
		Description: "Execute a command through chainwatch policy enforcement. Blocked commands return an error with the reason.",
	}, s.handleExec)

	mcpsdk.AddTool(s.mcpServer, &mcpsdk.Tool{
		Name:        "chainwatch_http",
		Description: "Make an HTTP request through chainwatch policy enforcement. Blocked requests return an error with the reason.",
	}, s.handleHTTP)

	mcpsdk.AddTool(s.mcpServer, &mcpsdk.Tool{
		Name:        "chainwatch_check",
		Description: "Check if an action would be allowed by chainwatch policy without executing it (dry-run).",
	}, s.handleCheck)

	mcpsdk.AddTool(s.mcpServer, &mcpsdk.Tool{
		Name:        "chainwatch_approve",
		Description: "Grant approval for a require_approval action. Use after a blocked action returns an approval_key.",
	}, s.handleApprove)

	mcpsdk.AddTool(s.mcpServer, &mcpsdk.Tool{
		Name:        "chainwatch_pending",
		Description: "List all pending approval requests.",
	}, s.handlePending)
}
