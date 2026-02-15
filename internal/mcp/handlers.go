package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ppiankov/chainwatch/internal/approval"
	"github.com/ppiankov/chainwatch/internal/audit"
	"github.com/ppiankov/chainwatch/internal/breakglass"
	"github.com/ppiankov/chainwatch/internal/cmdguard"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/policy"
)

// --- Input/Output types ---

// ExecInput defines parameters for the chainwatch_exec tool.
type ExecInput struct {
	Command string   `json:"command" jsonschema:"command to execute"`
	Args    []string `json:"args,omitempty" jsonschema:"command arguments"`
}

// ExecOutput contains the result of command execution or block details.
type ExecOutput struct {
	Stdout      string `json:"stdout,omitempty"`
	Stderr      string `json:"stderr,omitempty"`
	ExitCode    int    `json:"exit_code"`
	Blocked     bool   `json:"blocked,omitempty"`
	Decision    string `json:"decision,omitempty"`
	Reason      string `json:"reason,omitempty"`
	ApprovalKey string `json:"approval_key,omitempty"`
}

// HTTPInput defines parameters for the chainwatch_http tool.
type HTTPInput struct {
	Method  string            `json:"method" jsonschema:"HTTP method (GET/POST/PUT/DELETE)"`
	URL     string            `json:"url" jsonschema:"request URL"`
	Headers map[string]string `json:"headers,omitempty" jsonschema:"request headers"`
	Body    string            `json:"body,omitempty" jsonschema:"request body"`
}

// HTTPOutput contains the HTTP response or block details.
type HTTPOutput struct {
	Status      int               `json:"status,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	Blocked     bool              `json:"blocked,omitempty"`
	Decision    string            `json:"decision,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	ApprovalKey string            `json:"approval_key,omitempty"`
}

// CheckInput defines parameters for the chainwatch_check tool.
type CheckInput struct {
	Tool      string `json:"tool" jsonschema:"tool type (command/http_proxy/file_read)"`
	Resource  string `json:"resource" jsonschema:"resource being accessed"`
	Operation string `json:"operation,omitempty" jsonschema:"operation type (execute/read/write/GET/POST)"`
}

// CheckOutput contains the policy decision.
type CheckOutput struct {
	Decision    string `json:"decision"`
	Reason      string `json:"reason"`
	PolicyID    string `json:"policy_id,omitempty"`
	ApprovalKey string `json:"approval_key,omitempty"`
}

// ApproveInput defines parameters for the chainwatch_approve tool.
type ApproveInput struct {
	Key      string `json:"key" jsonschema:"approval key from a blocked action"`
	Duration string `json:"duration,omitempty" jsonschema:"approval duration (e.g. 5m), omit for one-time approval"`
}

// ApproveOutput confirms the approval.
type ApproveOutput struct {
	Key      string `json:"key"`
	Status   string `json:"status"`
	Duration string `json:"duration,omitempty"`
}

// PendingInput is empty — no parameters needed.
type PendingInput struct{}

// PendingOutput lists all pending approvals.
type PendingOutput struct {
	Approvals []PendingItem `json:"approvals"`
}

// PendingItem describes a single approval request.
type PendingItem struct {
	Key       string `json:"key"`
	Status    string `json:"status"`
	Resource  string `json:"resource"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
}

// --- Handlers ---

func (s *Server) handleExec(ctx context.Context, req *mcpsdk.CallToolRequest, input ExecInput) (*mcpsdk.CallToolResult, ExecOutput, error) {
	result, err := s.guard.Run(ctx, input.Command, input.Args, nil)
	if err != nil {
		var blocked *cmdguard.BlockedError
		if errors.As(err, &blocked) {
			out := ExecOutput{
				Blocked:     true,
				Decision:    string(blocked.Decision),
				Reason:      blocked.Reason,
				ApprovalKey: blocked.ApprovalKey,
			}
			return &mcpsdk.CallToolResult{IsError: true}, out, nil
		}
		return nil, ExecOutput{}, err
	}

	return nil, ExecOutput{
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
		ExitCode: result.ExitCode,
	}, nil
}

func (s *Server) handleHTTP(ctx context.Context, req *mcpsdk.CallToolRequest, input HTTPInput) (*mcpsdk.CallToolResult, HTTPOutput, error) {
	if input.Method == "" {
		input.Method = "GET"
	}

	// Build action for policy evaluation
	action := buildHTTPAction(input)

	s.mu.Lock()
	result := policy.Evaluate(action, s.tracer.State, s.purpose, s.dl, s.policyCfg)
	s.tracer.RecordAction(
		map[string]any{"mcp": "chainwatch_http"},
		s.purpose, action,
		map[string]any{
			"result":       string(result.Decision),
			"reason":       result.Reason,
			"policy_id":    result.PolicyID,
			"approval_key": result.ApprovalKey,
		}, "",
	)
	s.mu.Unlock()

	s.recordAudit(action, string(result.Decision), result.Reason, result.Tier)

	// Break-glass override (CW-23.2)
	if result.Tier >= 2 && s.bgStore != nil {
		if token := breakglass.CheckAndConsume(s.bgStore, result.Tier, action); token != nil {
			originalDecision := result.Decision
			result.Decision = model.Allow
			result.Reason = fmt.Sprintf("break-glass override (token=%s, original=%s): %s",
				token.ID, originalDecision, token.Reason)
			result.PolicyID = "breakglass.override"
			if s.auditLog != nil {
				s.auditLog.Record(audit.AuditEntry{
					Timestamp:        time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
					TraceID:          s.tracer.State.TraceID,
					Action:           audit.AuditAction{Tool: action.Tool, Resource: action.Resource},
					Decision:         "allow",
					Reason:           result.Reason,
					Tier:             result.Tier,
					PolicyHash:       s.policyHash,
					Type:             "break_glass_used",
					TokenID:          token.ID,
					OriginalDecision: string(originalDecision),
					OverriddenTo:     "allow",
					ExpiresAt:        token.ExpiresAt.Format(time.RFC3339),
				})
			}
		}
	}

	// Check decision
	if result.Decision == model.Deny {
		out := HTTPOutput{
			Blocked:     true,
			Decision:    string(result.Decision),
			Reason:      result.Reason,
			ApprovalKey: result.ApprovalKey,
		}
		return &mcpsdk.CallToolResult{IsError: true}, out, nil
	}

	if result.Decision == model.RequireApproval && result.ApprovalKey != "" {
		status, _ := s.approvals.Check(result.ApprovalKey)
		if status == approval.StatusApproved {
			s.approvals.Consume(result.ApprovalKey)
			// fall through to execute
		} else {
			if status != approval.StatusPending && status != approval.StatusDenied {
				s.approvals.Request(result.ApprovalKey, result.Reason, result.PolicyID, action.Resource)
			}
			out := HTTPOutput{
				Blocked:     true,
				Decision:    string(result.Decision),
				Reason:      result.Reason,
				ApprovalKey: result.ApprovalKey,
			}
			return &mcpsdk.CallToolResult{IsError: true}, out, nil
		}
	} else if result.Decision == model.RequireApproval {
		out := HTTPOutput{
			Blocked:  true,
			Decision: string(result.Decision),
			Reason:   result.Reason,
		}
		return &mcpsdk.CallToolResult{IsError: true}, out, nil
	}

	// Execute HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, strings.ToUpper(input.Method), input.URL, strings.NewReader(input.Body))
	if err != nil {
		return nil, HTTPOutput{}, fmt.Errorf("invalid request: %w", err)
	}
	for k, v := range input.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, HTTPOutput{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, HTTPOutput{}, fmt.Errorf("failed to read response: %w", err)
	}

	headers := make(map[string]string)
	for k, vv := range resp.Header {
		headers[k] = strings.Join(vv, ", ")
	}

	return nil, HTTPOutput{
		Status:  resp.StatusCode,
		Headers: headers,
		Body:    string(body),
	}, nil
}

func (s *Server) handleCheck(ctx context.Context, req *mcpsdk.CallToolRequest, input CheckInput) (*mcpsdk.CallToolResult, CheckOutput, error) {
	action := buildCheckAction(input)

	s.mu.Lock()
	result := policy.Evaluate(action, s.tracer.State, s.purpose, s.dl, s.policyCfg)
	s.tracer.RecordAction(
		map[string]any{"mcp": "chainwatch_check"},
		s.purpose, action,
		map[string]any{
			"result":       string(result.Decision),
			"reason":       result.Reason,
			"policy_id":    result.PolicyID,
			"approval_key": result.ApprovalKey,
		}, "",
	)
	s.mu.Unlock()

	s.recordAudit(action, string(result.Decision), result.Reason, result.Tier)

	return nil, CheckOutput{
		Decision:    string(result.Decision),
		Reason:      result.Reason,
		PolicyID:    result.PolicyID,
		ApprovalKey: result.ApprovalKey,
	}, nil
}

func (s *Server) handleApprove(ctx context.Context, req *mcpsdk.CallToolRequest, input ApproveInput) (*mcpsdk.CallToolResult, ApproveOutput, error) {
	var duration time.Duration
	if input.Duration != "" {
		var err error
		duration, err = time.ParseDuration(input.Duration)
		if err != nil {
			return nil, ApproveOutput{}, fmt.Errorf("invalid duration %q: %w", input.Duration, err)
		}
	}

	if err := s.approvals.Approve(input.Key, duration); err != nil {
		return nil, ApproveOutput{}, err
	}

	out := ApproveOutput{
		Key:    input.Key,
		Status: "approved",
	}
	if duration > 0 {
		out.Duration = duration.String()
	}
	return nil, out, nil
}

func (s *Server) handlePending(ctx context.Context, req *mcpsdk.CallToolRequest, input PendingInput) (*mcpsdk.CallToolResult, PendingOutput, error) {
	list, err := s.approvals.List()
	if err != nil {
		return nil, PendingOutput{}, err
	}

	items := make([]PendingItem, len(list))
	for i, a := range list {
		items[i] = PendingItem{
			Key:       a.Key,
			Status:    string(a.Status),
			Resource:  a.Resource,
			Reason:    a.Reason,
			CreatedAt: a.CreatedAt.Format(time.RFC3339),
		}
	}

	return nil, PendingOutput{Approvals: items}, nil
}

// --- Action builders ---

func buildHTTPAction(input HTTPInput) *model.Action {
	method := strings.ToLower(input.Method)
	sensitivity, tags := classifyURLSensitivity(input.URL)

	egress := model.EgressExternal
	lower := strings.ToLower(input.URL)
	if strings.Contains(lower, "localhost") || strings.Contains(lower, "127.0.0.1") {
		egress = model.EgressInternal
	}

	return &model.Action{
		Tool:      "http_proxy",
		Resource:  input.URL,
		Operation: method,
		Params: map[string]any{
			"method": input.Method,
			"url":    input.URL,
		},
		RawMeta: map[string]any{
			"sensitivity": string(sensitivity),
			"tags":        toAnySlice(tags),
			"bytes":       len(input.Body),
			"rows":        0,
			"egress":      string(egress),
			"destination": extractHost(input.URL),
		},
	}
}

func buildCheckAction(input CheckInput) *model.Action {
	tool := input.Tool
	if tool == "" {
		tool = "command"
	}
	op := input.Operation
	if op == "" {
		op = "execute"
	}

	sensitivity := model.SensLow
	var tags []string

	switch tool {
	case "command":
		sensitivity, tags = classifyCommandSensitivity(input.Resource)
	case "http_proxy":
		sensitivity, tags = classifyURLSensitivity(input.Resource)
	}

	egress := model.EgressInternal
	if tool == "http_proxy" {
		egress = model.EgressExternal
	}

	return &model.Action{
		Tool:      tool,
		Resource:  input.Resource,
		Operation: op,
		Params:    map[string]any{"resource": input.Resource},
		RawMeta: map[string]any{
			"sensitivity": string(sensitivity),
			"tags":        toAnySlice(tags),
			"bytes":       0,
			"rows":        0,
			"egress":      string(egress),
			"destination": "",
		},
	}
}

// --- Helpers ---

func classifyURLSensitivity(url string) (model.Sensitivity, []string) {
	lower := strings.ToLower(url)
	payment := []string{"/checkout", "/payment", "/billing", "stripe.com", "paypal.com"}
	for _, p := range payment {
		if strings.Contains(lower, p) {
			return model.SensHigh, []string{"payment"}
		}
	}
	cred := []string{"/oauth/token", "/api/keys", "/api/credentials"}
	for _, p := range cred {
		if strings.Contains(lower, p) {
			return model.SensHigh, []string{"credential"}
		}
	}
	sensitive := []string{"/hr/", "/salary", "/payroll", "/pii/"}
	for _, p := range sensitive {
		if strings.Contains(lower, p) {
			return model.SensHigh, []string{"sensitive"}
		}
	}
	return model.SensLow, nil
}

func classifyCommandSensitivity(cmd string) (model.Sensitivity, []string) {
	lower := strings.ToLower(cmd)
	destructive := []string{"rm -rf", "dd if=", "mkfs", "chmod -r 777"}
	for _, p := range destructive {
		if strings.Contains(lower, p) {
			return model.SensHigh, []string{"destructive"}
		}
	}
	credential := []string{"sudo", "passwd", "ssh-keygen"}
	for _, p := range credential {
		if strings.Contains(lower, p) {
			return model.SensHigh, []string{"credential"}
		}
	}
	return model.SensLow, nil
}

func extractHost(rawURL string) string {
	// Simple host extraction without importing net/url
	s := rawURL
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	if idx := strings.IndexAny(s, "/?#"); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, ":"); idx >= 0 {
		s = s[:idx]
	}
	return s
}

func toAnySlice(ss []string) []any {
	if ss == nil {
		return []any{}
	}
	result := make([]any, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}

// marshalJSON is a helper for JSON encoding in responses.
func marshalJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(data)
}
