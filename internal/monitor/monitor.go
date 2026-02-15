package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ppiankov/chainwatch/internal/approval"
	"github.com/ppiankov/chainwatch/internal/audit"
	"github.com/ppiankov/chainwatch/internal/breakglass"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/profile"
	"github.com/ppiankov/chainwatch/internal/tracer"
)

// Config holds root monitor configuration.
type Config struct {
	TargetPID    int
	ProfileName  string
	DenylistPath string
	PolicyPath   string
	PollInterval time.Duration
	Actor        map[string]any
	AuditLogPath string
}

// Monitor watches an agent process tree and blocks root-level operations.
type Monitor struct {
	cfg       Config
	watcher   Watcher
	rules     []Rule
	approvals *approval.Store
	bgStore   *breakglass.Store
	tracer    *tracer.TraceAccumulator
	auditLog  *audit.Log
	seen      map[int]bool // PIDs already evaluated
	mu        sync.Mutex
}

// New creates a Monitor with loaded rules and fresh tracer.
func New(cfg Config, watcher Watcher) (*Monitor, error) {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 100 * time.Millisecond
	}
	if cfg.Actor == nil {
		cfg.Actor = map[string]any{"monitor": "chainwatch root-monitor"}
	}

	rules := DefaultRules()

	if cfg.ProfileName != "" {
		prof, err := profile.Load(cfg.ProfileName)
		if err != nil {
			return nil, fmt.Errorf("failed to load profile %q: %w", cfg.ProfileName, err)
		}
		rules = append(rules, RulesFromProfile(prof)...)
	}

	approvalStore, err := approval.NewStore(approval.DefaultDir())
	if err != nil {
		return nil, fmt.Errorf("failed to create approval store: %w", err)
	}

	var auditLog *audit.Log
	if cfg.AuditLogPath != "" {
		auditLog, err = audit.Open(cfg.AuditLogPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log: %w", err)
		}
	}

	bgStore, _ := breakglass.NewStore(breakglass.DefaultDir())

	return &Monitor{
		cfg:       cfg,
		watcher:   watcher,
		rules:     rules,
		approvals: approvalStore,
		bgStore:   bgStore,
		tracer:    tracer.NewAccumulator(tracer.NewTraceID()),
		auditLog:  auditLog,
		seen:      make(map[int]bool),
	}, nil
}

// NewWithApprovals creates a Monitor with a specific approval store (for testing).
func NewWithApprovals(cfg Config, watcher Watcher, store *approval.Store) (*Monitor, error) {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 100 * time.Millisecond
	}
	if cfg.Actor == nil {
		cfg.Actor = map[string]any{"monitor": "chainwatch root-monitor"}
	}

	rules := DefaultRules()

	if cfg.ProfileName != "" {
		prof, err := profile.Load(cfg.ProfileName)
		if err != nil {
			return nil, fmt.Errorf("failed to load profile %q: %w", cfg.ProfileName, err)
		}
		rules = append(rules, RulesFromProfile(prof)...)
	}

	bgStore, _ := breakglass.NewStore(breakglass.DefaultDir())

	return &Monitor{
		cfg:       cfg,
		watcher:   watcher,
		rules:     rules,
		approvals: store,
		bgStore:   bgStore,
		tracer:    tracer.NewAccumulator(tracer.NewTraceID()),
		seen:      make(map[int]bool),
	}, nil
}

// Run starts the monitor loop. Blocks until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(m.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			m.scan()
		}
	}
}

// scan checks all descendant processes and enforces rules.
func (m *Monitor) scan() {
	procs, err := m.watcher.Children(m.cfg.TargetPID)
	if err != nil {
		// Target process may have exited; continue polling
		return
	}

	for _, proc := range procs {
		m.mu.Lock()
		alreadySeen := m.seen[proc.PID]
		m.mu.Unlock()

		if alreadySeen {
			continue
		}

		rule, matched := Match(proc.Command, m.rules)
		if !matched {
			m.mu.Lock()
			m.seen[proc.PID] = true
			m.mu.Unlock()
			continue
		}

		// Check approval store for grace-period rules
		if rule.ApprovalKey != "" {
			status, _ := m.approvals.Check(rule.ApprovalKey)
			if status == approval.StatusApproved {
				m.approvals.Consume(rule.ApprovalKey)
				m.recordAction(proc, rule, "allow", "pre-approved via approval store", 0)
				m.mu.Lock()
				m.seen[proc.PID] = true
				m.mu.Unlock()
				continue
			}
		}

		// Break-glass override (CW-23.2)
		if m.bgStore != nil {
			action := &model.Action{
				Tool:      "syscall",
				Resource:  proc.Command,
				Operation: "execute",
			}
			if token := breakglass.CheckAndConsume(m.bgStore, 3, action); token != nil {
				reason := fmt.Sprintf("break-glass override (token=%s): %s", token.ID, token.Reason)
				m.recordAction(proc, rule, "allow", reason, 0)
				if m.auditLog != nil {
					m.auditLog.Record(audit.AuditEntry{
						Timestamp:        time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
						TraceID:          m.tracer.State.TraceID,
						Action:           audit.AuditAction{Tool: "syscall", Resource: proc.Command},
						Decision:         "allow",
						Reason:           reason,
						Tier:             3,
						Type:             "break_glass_used",
						TokenID:          token.ID,
						OriginalDecision: "deny",
						OverriddenTo:     "allow",
						ExpiresAt:        token.ExpiresAt.Format(time.RFC3339),
					})
				}
				m.mu.Lock()
				m.seen[proc.PID] = true
				m.mu.Unlock()
				continue
			}
		}

		// Block: kill the process and record
		m.watcher.Kill(proc.PID)
		m.recordAction(proc, rule, "deny", fmt.Sprintf("blocked %s: %s", rule.Category, rule.Pattern), 3)

		// Request approval for future attempts if applicable
		if rule.ApprovalKey != "" {
			m.approvals.Request(
				rule.ApprovalKey,
				fmt.Sprintf("%s operation requires approval", rule.Category),
				"root_monitor."+rule.Category,
				proc.Command,
			)
		}

		m.mu.Lock()
		m.seen[proc.PID] = true
		m.mu.Unlock()
	}
}

// recordAction writes a trace event for a monitored process.
func (m *Monitor) recordAction(proc ProcessInfo, rule Rule, decision, reason string, tier int) {
	action := &model.Action{
		Tool:      "syscall",
		Resource:  proc.Command,
		Operation: "execute",
		Params: map[string]any{
			"pid":      proc.PID,
			"ppid":     proc.PPID,
			"category": rule.Category,
		},
		RawMeta: map[string]any{
			"sensitivity": "high",
			"tags":        []any{rule.Category},
			"bytes":       0,
			"rows":        0,
			"egress":      "internal",
			"destination": "",
		},
	}

	m.mu.Lock()
	m.tracer.RecordAction(m.cfg.Actor, "root_monitor", action, map[string]any{
		"result": decision,
		"reason": reason,
	}, "")
	m.mu.Unlock()

	if m.auditLog != nil {
		m.auditLog.Record(audit.AuditEntry{
			Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:   m.tracer.State.TraceID,
			Action:    audit.AuditAction{Tool: action.Tool, Resource: action.Resource},
			Decision:  decision,
			Reason:    reason,
			Tier:      tier,
		})
	}
}

// Close closes the audit log if configured.
func (m *Monitor) Close() error {
	if m.auditLog != nil {
		return m.auditLog.Close()
	}
	return nil
}

// TraceSummary exports the trace for debugging/audit.
func (m *Monitor) TraceSummary() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tracer.ToJSON()
}

// BlockedCount returns the number of blocked operations recorded.
func (m *Monitor) BlockedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, ev := range m.tracer.Events {
		if d, ok := ev.Decision["result"]; ok && d == "deny" {
			count++
		}
	}
	return count
}

// Events returns a copy of all trace events (for testing).
func (m *Monitor) Events() []tracer.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	events := make([]tracer.Event, len(m.tracer.Events))
	copy(events, m.tracer.Events)
	return events
}
