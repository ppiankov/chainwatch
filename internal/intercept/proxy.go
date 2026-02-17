package intercept

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
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

// Config holds interceptor proxy configuration.
type Config struct {
	Port         int
	Upstream     string // e.g. "https://api.anthropic.com"
	DenylistPath string
	PolicyPath   string
	ProfileName  string
	Purpose      string
	AgentID      string
	Actor        map[string]any
	AuditLogPath string
}

// Server is a reverse HTTP proxy that intercepts LLM responses
// and evaluates chainwatch policy on tool_use/function_call blocks.
type Server struct {
	cfg        Config
	upstream   *url.URL
	dl         *denylist.Denylist
	policyCfg  *policy.PolicyConfig
	approvals  *approval.Store
	bgStore    *breakglass.Store
	dispatcher *alert.Dispatcher
	tracer     *tracer.TraceAccumulator
	auditLog   *audit.Log
	policyHash string
	mu         sync.Mutex
	srv        *http.Server
}

// NewServer creates an interceptor proxy with loaded policy.
func NewServer(cfg Config) (*Server, error) {
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

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
		cfg.Actor = map[string]any{"interceptor": "chainwatch"}
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

	s := &Server{
		cfg:        cfg,
		upstream:   upstream,
		dl:         dl,
		policyCfg:  policyCfg,
		approvals:  approvalStore,
		bgStore:    bgStore,
		dispatcher: alert.NewDispatcher(policyCfg.Alerts),
		tracer:     tracer.NewAccumulator(tracer.NewTraceID()),
		auditLog:   auditLog,
		policyHash: policyHash,
	}

	s.srv = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: s,
	}

	return s, nil
}

// Start begins listening. Blocks until context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.srv.Shutdown(shutdownCtx)
	}()

	err = s.srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Close closes the audit log if configured.
func (s *Server) Close() error {
	if s.auditLog != nil {
		return s.auditLog.Close()
	}
	return nil
}

// TraceSummary exports the accumulated trace for debugging/audit.
func (s *Server) TraceSummary() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tracer.ToJSON()
}

// ServeHTTP forwards requests to upstream and intercepts responses.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Build outbound request to upstream
	outURL := *s.upstream
	outURL.Path = r.URL.Path
	outURL.RawQuery = r.URL.RawQuery

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create request: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy all headers (preserves Authorization, anthropic-version, etc.)
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}
	outReq.Header.Set("Host", s.upstream.Host)
	outReq.ContentLength = r.ContentLength

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Route to streaming or non-streaming handler
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/event-stream") {
		s.handleStreaming(w, r, resp)
		return
	}

	s.handleNonStreaming(w, resp)
}

// handleNonStreaming reads the full response, extracts tool calls, evaluates, rewrites.
func (s *Server) handleNonStreaming(w http.ResponseWriter, resp *http.Response) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read upstream response: %v", err), http.StatusBadGateway)
		return
	}

	var bodyMap map[string]any
	if err := json.Unmarshal(body, &bodyMap); err != nil {
		// Not JSON — passthrough unchanged
		copyHeaders(w, resp)
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	calls, format := ExtractToolCalls(bodyMap)
	if len(calls) == 0 {
		// No tool calls — passthrough unchanged
		copyHeaders(w, resp)
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	// Evaluate each tool call
	var results []EvalResult
	for _, call := range calls {
		result := s.evaluateToolCall(call)
		results = append(results, EvalResult{Call: call, Result: result})
	}

	// Rewrite blocked calls
	modified, changed := RewriteResponse(bodyMap, results, format)
	if !changed {
		copyHeaders(w, resp)
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	// Write modified response with corrected Content-Length
	copyHeaders(w, resp)
	w.Header().Set("Content-Length", strconv.Itoa(len(modified)))
	w.WriteHeader(resp.StatusCode)
	w.Write(modified)
}

// handleStreaming processes SSE streaming responses, buffering tool_use blocks.
func (s *Server) handleStreaming(w http.ResponseWriter, r *http.Request, resp *http.Response) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Fallback: read entire stream and handle as non-streaming
		s.handleNonStreaming(w, resp)
		return
	}

	// Copy response headers
	copyHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)

	format := DetectStreamingFormat(r.URL.Path, r.Header)
	if format != FormatAnthropic {
		// For non-Anthropic streaming, pass through (OpenAI streaming is more complex)
		io.Copy(w, resp.Body)
		flusher.Flush()
		return
	}

	buf := NewStreamBuffer(format)
	scanner := bufio.NewScanner(resp.Body)
	var currentIndex int = -1
	var buffering bool

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line signals end of SSE event
		if line == "" {
			if !buffering {
				fmt.Fprint(w, "\n")
				flusher.Flush()
			}
			continue
		}

		// Parse SSE data lines
		if strings.HasPrefix(line, "data: ") {
			dataStr := strings.TrimPrefix(line, "data: ")

			// Check for [DONE] sentinel
			if dataStr == "[DONE]" {
				fmt.Fprintf(w, "%s\n", line)
				flusher.Flush()
				continue
			}

			var event map[string]any
			if err := json.Unmarshal([]byte(dataStr), &event); err != nil {
				// Not JSON — pass through
				if !buffering {
					fmt.Fprintf(w, "%s\n", line)
					flusher.Flush()
				}
				continue
			}

			eventType, _ := event["type"].(string)

			switch eventType {
			case "content_block_start":
				idx := intFromAny(event["index"])
				if cb, ok := event["content_block"].(map[string]any); ok {
					if cbType, _ := cb["type"].(string); cbType == "tool_use" {
						name, _ := cb["name"].(string)
						id, _ := cb["id"].(string)
						buf.StartToolUse(idx, id, name, line)
						currentIndex = idx
						buffering = true
						continue
					}
				}
				// Non-tool block — pass through
				fmt.Fprintf(w, "%s\n", line)
				flusher.Flush()

			case "content_block_delta":
				idx := intFromAny(event["index"])
				if buf.IsBuffering(idx) {
					if delta, ok := event["delta"].(map[string]any); ok {
						if deltaType, _ := delta["type"].(string); deltaType == "input_json_delta" {
							fragment, _ := delta["partial_json"].(string)
							buf.AppendDelta(idx, fragment, line)
							continue
						}
					}
				}
				// Non-tool delta — pass through
				fmt.Fprintf(w, "%s\n", line)
				flusher.Flush()

			case "content_block_stop":
				idx := intFromAny(event["index"])
				if tc, bufferedEvents, ok := buf.Complete(idx, line); ok {
					// Evaluate the complete tool call
					result := s.evaluateToolCall(tc)

					if result.Decision == model.Allow || result.Decision == model.AllowWithRedaction {
						// Allowed — emit original buffered events
						for _, ev := range bufferedEvents {
							fmt.Fprintf(w, "%s\n\n", ev)
							flusher.Flush()
						}
					} else {
						// Blocked — emit replacement text block
						replacements := RewriteAnthropicSSE(idx, tc, result)
						for _, rep := range replacements {
							fmt.Fprintf(w, "%s\n", rep)
							flusher.Flush()
						}
					}

					if idx == currentIndex {
						buffering = false
						currentIndex = -1
					}
					continue
				}
				// Not buffered — pass through
				fmt.Fprintf(w, "%s\n", line)
				flusher.Flush()

			default:
				// message_start, message_delta, message_stop, ping — pass through
				if !buffering {
					fmt.Fprintf(w, "%s\n", line)
					flusher.Flush()
				} else {
					// If buffering, still pass through non-content events
					fmt.Fprintf(w, "%s\n", line)
					flusher.Flush()
				}
			}
		} else if strings.HasPrefix(line, "event: ") {
			if !buffering {
				fmt.Fprintf(w, "%s\n", line)
			} else if buf.IsBuffering(currentIndex) {
				// Buffer event lines for tool_use blocks
			} else {
				fmt.Fprintf(w, "%s\n", line)
			}
		} else {
			// Other lines — pass through
			if !buffering {
				fmt.Fprintf(w, "%s\n", line)
				flusher.Flush()
			}
		}
	}
}

// evaluateToolCall builds a model.Action from a ToolCall and evaluates policy.
func (s *Server) evaluateToolCall(tc ToolCall) model.PolicyResult {
	action := buildActionFromToolCall(tc)

	s.mu.Lock()
	result := policy.Evaluate(action, s.tracer.State, s.cfg.Purpose, s.cfg.AgentID, s.dl, s.policyCfg)
	s.tracer.RecordAction(s.cfg.Actor, s.cfg.Purpose, action, map[string]any{
		"result":       string(result.Decision),
		"reason":       result.Reason,
		"policy_id":    result.PolicyID,
		"approval_key": result.ApprovalKey,
		"tool_call_id": tc.ID,
		"tool_name":    tc.Name,
		"source":       "intercept",
	}, "")
	s.mu.Unlock()

	if s.auditLog != nil {
		s.auditLog.Record(audit.AuditEntry{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:    s.tracer.State.TraceID,
			Action:     audit.AuditAction{Tool: action.Tool, Resource: action.Resource},
			Decision:   string(result.Decision),
			Reason:     result.Reason,
			Tier:       result.Tier,
			PolicyHash: s.policyHash,
		})
	}
	s.dispatchAlert(action, result)

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
			s.dispatchBreakGlass(action, result)
		}
	}

	// Handle approval flow
	if result.Decision == model.RequireApproval && result.ApprovalKey != "" {
		status, _ := s.approvals.Check(result.ApprovalKey)
		if status == approval.StatusApproved {
			s.approvals.Consume(result.ApprovalKey)
			return model.PolicyResult{
				Decision: model.Allow,
				Reason:   "approved via approval flow",
				PolicyID: result.PolicyID,
			}
		}
		if status != approval.StatusPending && status != approval.StatusDenied {
			s.approvals.Request(result.ApprovalKey, result.Reason, result.PolicyID, action.Resource)
		}
	}

	return result
}

func (s *Server) dispatchAlert(action *model.Action, result model.PolicyResult) {
	if s.dispatcher != nil {
		s.dispatcher.Dispatch(alert.AlertEvent{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:    s.tracer.State.TraceID,
			Tool:       action.Tool,
			Resource:   action.Resource,
			Decision:   string(result.Decision),
			Reason:     result.Reason,
			Tier:       result.Tier,
			PolicyHash: s.policyHash,
		})
	}
}

func (s *Server) dispatchBreakGlass(action *model.Action, result model.PolicyResult) {
	if s.dispatcher != nil {
		s.dispatcher.Dispatch(alert.AlertEvent{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:    s.tracer.State.TraceID,
			Tool:       action.Tool,
			Resource:   action.Resource,
			Decision:   string(result.Decision),
			Reason:     result.Reason,
			Tier:       result.Tier,
			PolicyHash: s.policyHash,
			Type:       "break_glass_used",
		})
	}
}

// buildActionFromToolCall maps a parsed ToolCall to a model.Action.
func buildActionFromToolCall(tc ToolCall) *model.Action {
	tool, operation := classifyTool(tc.Name)
	resource := extractResource(tc.Arguments, tool)
	if resource == "" {
		resource = tc.Name
	}

	sensitivity, tags := classifyToolSensitivity(tool, resource)
	egress := inferEgress(tool, resource)

	// If tool is HTTP and args have a method, use it as operation
	if tool == "http" {
		if method, ok := tc.Arguments["method"].(string); ok {
			operation = strings.ToLower(method)
		}
	}

	return &model.Action{
		Tool:      tool,
		Resource:  resource,
		Operation: operation,
		Params:    tc.Arguments,
		RawMeta: map[string]any{
			"sensitivity": string(sensitivity),
			"tags":        toAnySlice(tags),
			"bytes":       0,
			"rows":        0,
			"egress":      string(egress),
			"destination": extractDestination(resource),
		},
	}
}

// classifyTool maps a tool name to chainwatch tool category and operation.
func classifyTool(name string) (string, string) {
	lower := strings.ToLower(name)

	commandPatterns := []string{"command", "exec", "shell", "bash", "run_"}
	for _, p := range commandPatterns {
		if strings.Contains(lower, p) {
			return "command", "execute"
		}
	}

	httpPatterns := []string{"http", "fetch", "request", "curl", "api_"}
	for _, p := range httpPatterns {
		if strings.Contains(lower, p) {
			return "http", "get"
		}
	}

	if strings.Contains(lower, "read") || strings.Contains(lower, "cat") {
		return "file_read", "read"
	}
	if strings.Contains(lower, "write") || strings.Contains(lower, "save") || strings.Contains(lower, "create_file") {
		return "file_write", "write"
	}
	if strings.Contains(lower, "delete") || strings.Contains(lower, "remove") {
		return "file_delete", "delete"
	}
	if strings.Contains(lower, "browser") || strings.Contains(lower, "web") {
		return "browser", "navigate"
	}

	return name, "execute"
}

// extractResource tries to extract the resource string from tool arguments.
func extractResource(args map[string]any, tool string) string {
	keys := []string{"command", "url", "path", "file_path", "filename", "resource"}
	for _, k := range keys {
		if v, ok := args[k].(string); ok && v != "" {
			return v
		}
	}

	// Fallback: first string value in args
	for _, v := range args {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}

	return ""
}

// classifyToolSensitivity returns sensitivity level and tags.
func classifyToolSensitivity(tool, resource string) (model.Sensitivity, []string) {
	lower := strings.ToLower(resource)

	// Destructive command patterns
	if tool == "command" {
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
	}

	// File sensitivity
	if tool == "file_read" || tool == "file_write" || tool == "file_delete" {
		sensitive := []string{".ssh/", ".aws/", ".env", "credentials", "secret", "password", "salary"}
		for _, p := range sensitive {
			if strings.Contains(lower, p) {
				return model.SensHigh, []string{"sensitive_file"}
			}
		}
	}

	// HTTP sensitivity
	if tool == "http" || tool == "browser" {
		payment := []string{"stripe.com", "paypal.com", "/checkout", "/payment"}
		for _, p := range payment {
			if strings.Contains(lower, p) {
				return model.SensHigh, []string{"payment"}
			}
		}
	}

	return model.SensLow, nil
}

// inferEgress determines if the action involves external communication.
func inferEgress(tool, resource string) model.EgressDirection {
	if tool == "http" || tool == "browser" {
		return model.EgressExternal
	}
	lower := strings.ToLower(resource)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return model.EgressExternal
	}
	if tool == "command" {
		network := []string{"curl ", "wget ", "nc ", "telnet ", "ssh ", "scp "}
		for _, p := range network {
			if strings.Contains(lower, p) {
				return model.EgressExternal
			}
		}
	}
	return model.EgressInternal
}

// extractDestination extracts a hostname from a resource string.
func extractDestination(resource string) string {
	if strings.HasPrefix(resource, "http://") || strings.HasPrefix(resource, "https://") {
		if u, err := url.Parse(resource); err == nil {
			return u.Host
		}
	}
	return ""
}

// copyHeaders copies response headers to the writer.
func copyHeaders(w http.ResponseWriter, resp *http.Response) {
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
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

func intFromAny(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}
