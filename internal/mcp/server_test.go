package mcp

import (
	"context"
	"strings"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := Config{Purpose: "test"}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create MCP server: %v", err)
	}
	return s
}

func newTestServerWithProfile(t *testing.T, profile string) *Server {
	t.Helper()
	cfg := Config{
		Purpose:     "test",
		ProfileName: profile,
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create MCP server with profile: %v", err)
	}
	return s
}

func TestExecAllowed(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	result, out, err := s.handleExec(ctx, &mcpsdk.CallToolRequest{}, ExecInput{
		Command: "echo",
		Args:    []string{"hello"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil && result.IsError {
		t.Fatal("expected success, got error result")
	}
	if !strings.Contains(out.Stdout, "hello") {
		t.Fatalf("expected stdout to contain 'hello', got %q", out.Stdout)
	}
	if out.Blocked {
		t.Fatal("expected not blocked")
	}
}

func TestExecBlocked(t *testing.T) {
	s := newTestServerWithProfile(t, "clawbot")
	ctx := context.Background()

	result, out, err := s.handleExec(ctx, &mcpsdk.CallToolRequest{}, ExecInput{
		Command: "rm",
		Args:    []string{"-rf", "/"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected IsError result for blocked command")
	}
	if !out.Blocked {
		t.Fatal("expected blocked=true")
	}
	if out.Decision != "deny" {
		t.Fatalf("expected deny, got %q", out.Decision)
	}
}

func TestCheckDryRun(t *testing.T) {
	s := newTestServerWithProfile(t, "clawbot")
	ctx := context.Background()

	// Check a command that should be blocked
	_, out, err := s.handleCheck(ctx, &mcpsdk.CallToolRequest{}, CheckInput{
		Tool:     "command",
		Resource: "rm -rf /",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Decision != "deny" {
		t.Fatalf("expected deny for rm -rf, got %q", out.Decision)
	}

	// Check a safe command
	_, safeOut, err := s.handleCheck(ctx, &mcpsdk.CallToolRequest{}, CheckInput{
		Tool:     "command",
		Resource: "ls /tmp",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if safeOut.Decision != "allow" {
		t.Fatalf("expected allow for ls, got %q", safeOut.Decision)
	}
}

func TestCheckHTTPBlocked(t *testing.T) {
	s := newTestServerWithProfile(t, "clawbot")
	ctx := context.Background()

	_, out, err := s.handleCheck(ctx, &mcpsdk.CallToolRequest{}, CheckInput{
		Tool:      "http_proxy",
		Resource:  "https://stripe.com/v1/charges",
		Operation: "post",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Decision != "deny" {
		t.Fatalf("expected deny for stripe, got %q", out.Decision)
	}
}

func TestApproveAndCheck(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	// First create a pending approval
	s.approvals.Request("test_key", "test reason", "test.policy", "test resource")

	// Approve it
	_, approveOut, err := s.handleApprove(ctx, &mcpsdk.CallToolRequest{}, ApproveInput{
		Key: "test_key",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if approveOut.Status != "approved" {
		t.Fatalf("expected approved, got %q", approveOut.Status)
	}
}

func TestApproveWithDuration(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	s.approvals.Request("timed_key", "test", "test", "resource")

	_, out, err := s.handleApprove(ctx, &mcpsdk.CallToolRequest{}, ApproveInput{
		Key:      "timed_key",
		Duration: "5m",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Duration != "5m0s" {
		t.Fatalf("expected 5m0s duration, got %q", out.Duration)
	}
}

func TestPendingList(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	// Create some pending approvals
	s.approvals.Request("key_a", "reason a", "policy.a", "resource_a")
	s.approvals.Request("key_b", "reason b", "policy.b", "resource_b")

	_, out, err := s.handlePending(ctx, &mcpsdk.CallToolRequest{}, PendingInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Approvals) != 2 {
		t.Fatalf("expected 2 approvals, got %d", len(out.Approvals))
	}
}

func TestProfileApplied(t *testing.T) {
	s := newTestServerWithProfile(t, "clawbot")
	ctx := context.Background()

	// Clawbot profile blocks sudo
	result, out, err := s.handleExec(ctx, &mcpsdk.CallToolRequest{}, ExecInput{
		Command: "sudo",
		Args:    []string{"ls"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected IsError for sudo with clawbot profile")
	}
	if !out.Blocked {
		t.Fatal("expected blocked=true for sudo")
	}
}

func TestTraceRecorded(t *testing.T) {
	s := newTestServerWithProfile(t, "clawbot")
	ctx := context.Background()

	// Make a check call that records a trace
	s.handleCheck(ctx, &mcpsdk.CallToolRequest{}, CheckInput{
		Tool:     "command",
		Resource: "echo hello",
	})

	summary := s.TraceSummary()
	events, ok := summary["events"]
	if !ok {
		t.Fatal("expected events in trace summary")
	}
	evList, ok := events.([]interface{})
	if ok && len(evList) == 0 {
		t.Fatal("expected at least one trace event")
	}
}

func TestToolRegistration(t *testing.T) {
	s := newTestServer(t)
	if s.mcpServer == nil {
		t.Fatal("expected MCP server to be initialized")
	}
	// The server should have been created with tools registered.
	// We can't easily list tools without a client, but we verify
	// the server was created without error.
}

func TestHTTPActionBuilder(t *testing.T) {
	action := buildHTTPAction(HTTPInput{
		Method: "POST",
		URL:    "https://stripe.com/v1/charges",
		Body:   `{"amount": 100}`,
	})

	if action.Tool != "http_proxy" {
		t.Fatalf("expected tool http_proxy, got %q", action.Tool)
	}
	if action.Operation != "post" {
		t.Fatalf("expected operation post, got %q", action.Operation)
	}
	if action.Resource != "https://stripe.com/v1/charges" {
		t.Fatalf("unexpected resource: %q", action.Resource)
	}
}

func TestCheckActionBuilder(t *testing.T) {
	action := buildCheckAction(CheckInput{
		Tool:      "file_read",
		Resource:  "/etc/passwd",
		Operation: "read",
	})

	if action.Tool != "file_read" {
		t.Fatalf("expected tool file_read, got %q", action.Tool)
	}
	if action.Operation != "read" {
		t.Fatalf("expected operation read, got %q", action.Operation)
	}
}
