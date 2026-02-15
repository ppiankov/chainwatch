package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ppiankov/chainwatch/internal/approval"
	"github.com/ppiankov/chainwatch/internal/audit"
	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/policy"
	"github.com/ppiankov/chainwatch/internal/profile"
	"github.com/ppiankov/chainwatch/internal/tracer"
)

// Config holds proxy server configuration.
type Config struct {
	Port         int
	DenylistPath string
	PolicyPath   string
	ProfileName  string
	Purpose      string
	Actor        map[string]any
	AuditLogPath string
}

// Server is a forward HTTP proxy that enforces chainwatch policy on outbound requests.
// MITM-free: no TLS interception. HTTPS CONNECT sees hostname only.
type Server struct {
	cfg        Config
	dl         *denylist.Denylist
	policyCfg  *policy.PolicyConfig
	approvals  *approval.Store
	tracer     *tracer.TraceAccumulator
	auditLog   *audit.Log
	policyHash string
	mu         sync.Mutex // protects tracer state
	srv        *http.Server
}

// NewServer creates a proxy server with the given configuration.
func NewServer(cfg Config) (*Server, error) {
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
		cfg.Actor = map[string]any{"proxy": "chainwatch"}
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

	s := &Server{
		cfg:        cfg,
		dl:         dl,
		policyCfg:  policyCfg,
		approvals:  approvalStore,
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

// Start begins listening for proxy connections. Blocks until context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.srv.Addr, err)
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

// Stop gracefully shuts down the proxy server.
func (s *Server) Stop(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// Addr returns the server's listen address. Only valid after Start is called.
func (s *Server) Addr() string {
	return s.srv.Addr
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

func (s *Server) recordAudit(action *model.Action, result model.PolicyResult) {
	if s.auditLog != nil {
		s.auditLog.Record(audit.AuditEntry{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:    s.tracer.State.TraceID,
			Action:     audit.AuditAction{Tool: action.Tool, Resource: action.Resource},
			Decision:   string(result.Decision),
			Reason:     result.Reason,
			PolicyHash: s.policyHash,
		})
	}
}

// ServeHTTP dispatches incoming requests to the appropriate handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
	} else {
		s.handleHTTP(w, r)
	}
}

// handleHTTP handles plain HTTP proxy requests with full inspection.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	action := buildActionFromRequest(r)

	s.mu.Lock()
	result := policy.Evaluate(action, s.tracer.State, s.cfg.Purpose, s.dl, s.policyCfg)
	s.tracer.RecordAction(s.cfg.Actor, s.cfg.Purpose, action, map[string]any{
		"result":       string(result.Decision),
		"reason":       result.Reason,
		"policy_id":    result.PolicyID,
		"approval_key": result.ApprovalKey,
	}, "")
	s.mu.Unlock()

	s.recordAudit(action, result)

	if result.Decision == model.Deny {
		writeBlocked(w, http.StatusForbidden, result)
		return
	}

	if result.Decision == model.RequireApproval && result.ApprovalKey != "" {
		status, _ := s.approvals.Check(result.ApprovalKey)
		if status == approval.StatusApproved {
			s.approvals.Consume(result.ApprovalKey)
			// fall through to forward
		} else {
			if status != approval.StatusPending && status != approval.StatusDenied {
				s.approvals.Request(result.ApprovalKey, result.Reason, result.PolicyID, action.Resource)
			}
			writeBlocked(w, http.StatusForbidden, result)
			return
		}
	} else if result.Decision == model.RequireApproval {
		writeBlocked(w, http.StatusForbidden, result)
		return
	}

	// Forward the request
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("proxy error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleConnect handles HTTPS CONNECT tunneling with hostname-only inspection.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Build a minimal action for the CONNECT request
	action := &model.Action{
		Tool:      "http_proxy",
		Resource:  host,
		Operation: "connect",
		Params:    map[string]any{"method": "CONNECT", "host": r.Host},
		RawMeta: map[string]any{
			"sensitivity": "low",
			"egress":      "external",
			"destination": host,
		},
	}

	// Check denylist on hostname
	s.mu.Lock()
	blocked, reason := s.dl.IsBlocked(host, "http_proxy")
	if !blocked {
		// Also check with full host:port
		blocked, reason = s.dl.IsBlocked(r.Host, "http_proxy")
	}

	var result model.PolicyResult
	if blocked {
		result = model.PolicyResult{
			Decision: model.Deny,
			Reason:   fmt.Sprintf("denylisted: %s", reason),
			PolicyID: "denylist.block",
		}
	} else {
		result = policy.Evaluate(action, s.tracer.State, s.cfg.Purpose, s.dl, s.policyCfg)
	}

	s.tracer.RecordAction(s.cfg.Actor, s.cfg.Purpose, action, map[string]any{
		"result":       string(result.Decision),
		"reason":       result.Reason,
		"policy_id":    result.PolicyID,
		"approval_key": result.ApprovalKey,
	}, "")
	s.mu.Unlock()

	s.recordAudit(action, result)

	if result.Decision == model.Deny {
		http.Error(w, fmt.Sprintf("CONNECT blocked: %s", result.Reason), http.StatusForbidden)
		return
	}

	if result.Decision == model.RequireApproval && result.ApprovalKey != "" {
		status, _ := s.approvals.Check(result.ApprovalKey)
		if status == approval.StatusApproved {
			s.approvals.Consume(result.ApprovalKey)
			// fall through to tunnel
		} else {
			if status != approval.StatusPending && status != approval.StatusDenied {
				s.approvals.Request(result.ApprovalKey, result.Reason, result.PolicyID, action.Resource)
			}
			http.Error(w, fmt.Sprintf("CONNECT blocked: %s (approval_key=%s)", result.Reason, result.ApprovalKey), http.StatusForbidden)
			return
		}
	} else if result.Decision == model.RequireApproval {
		http.Error(w, fmt.Sprintf("CONNECT blocked: %s", result.Reason), http.StatusForbidden)
		return
	}

	// Establish tunnel to target
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("tunnel error: %v", err), http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		http.Error(w, fmt.Sprintf("hijack error: %v", err), http.StatusInternalServerError)
		return
	}

	// Bidirectional tunnel
	go func() {
		defer targetConn.Close()
		defer clientConn.Close()
		io.Copy(targetConn, clientConn)
	}()
	go func() {
		defer targetConn.Close()
		defer clientConn.Close()
		io.Copy(clientConn, targetConn)
	}()
}

// buildActionFromRequest maps an HTTP request to a chainwatch Action.
func buildActionFromRequest(r *http.Request) *model.Action {
	url := r.URL.String()
	if r.URL.Host == "" && r.Host != "" {
		url = r.Host + r.URL.RequestURI()
	}

	method := strings.ToLower(r.Method)
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	contentLength := 0
	if r.ContentLength > 0 {
		contentLength = int(r.ContentLength)
	}

	sensitivity, tags := classifySensitivity(url)
	egress := model.EgressExternal
	if isLocalhost(host) {
		egress = model.EgressInternal
	}

	return &model.Action{
		Tool:      "http_proxy",
		Resource:  url,
		Operation: method,
		Params: map[string]any{
			"method": r.Method,
			"host":   r.Host,
		},
		RawMeta: map[string]any{
			"sensitivity": string(sensitivity),
			"tags":        toAnySlice(tags),
			"bytes":       contentLength,
			"rows":        0,
			"egress":      string(egress),
			"destination": host,
		},
	}
}

// classifySensitivity determines sensitivity and tags from URL patterns.
func classifySensitivity(url string) (model.Sensitivity, []string) {
	lower := strings.ToLower(url)
	var tags []string

	// Payment/checkout patterns
	paymentPatterns := []string{"/checkout", "/payment", "/billing", "stripe.com", "paypal.com", "paddle.com"}
	for _, p := range paymentPatterns {
		if strings.Contains(lower, p) {
			tags = append(tags, "payment")
			return model.SensHigh, tags
		}
	}

	// Credential patterns
	credPatterns := []string{"/oauth/token", "/api/keys", "/api/credentials", "/account/delete", "/settings/security"}
	for _, p := range credPatterns {
		if strings.Contains(lower, p) {
			tags = append(tags, "credential")
			return model.SensHigh, tags
		}
	}

	// Sensitive data patterns
	sensitivePatterns := []string{"/hr/", "/employee", "/salary", "/payroll", "/pii/"}
	for _, p := range sensitivePatterns {
		if strings.Contains(lower, p) {
			tags = append(tags, "sensitive")
			return model.SensHigh, tags
		}
	}

	return model.SensLow, tags
}

func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func toAnySlice(ss []string) []any {
	result := make([]any, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}

func writeBlocked(w http.ResponseWriter, status int, result model.PolicyResult) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := map[string]any{
		"blocked":  true,
		"reason":   result.Reason,
		"decision": string(result.Decision),
	}
	if result.ApprovalKey != "" {
		resp["approval_key"] = result.ApprovalKey
	}
	json.NewEncoder(w).Encode(resp)
}

// parsePort extracts a port number string for display.
func parsePort(port int) string {
	return strconv.Itoa(port)
}
