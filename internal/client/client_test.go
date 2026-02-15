package client

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/ppiankov/chainwatch/api/proto/chainwatch/v1"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/server"
)

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

// startTestServer creates a server + returns its address.
func startTestServer(t *testing.T, policyPath, denylistPath string) (string, func()) {
	t.Helper()

	cfg := server.Config{
		PolicyPath:   policyPath,
		DenylistPath: denylistPath,
	}

	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go srv.ServeOn(lis)

	cleanup := func() {
		srv.GracefulStop()
		srv.Close()
	}
	return lis.Addr().String(), cleanup
}

func TestClientEvaluateAllowed(t *testing.T) {
	addr, cleanup := startTestServer(t, "", "")
	defer cleanup()

	c, err := New(addr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	result, err := c.Evaluate(&model.Action{
		Tool:      "command",
		Resource:  "echo hello",
		Operation: "execute",
	}, "general")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if result.Decision == model.Deny {
		t.Errorf("expected non-deny for echo, got %s: %s", result.Decision, result.Reason)
	}
}

func TestClientEvaluateDenied(t *testing.T) {
	denylistPath := writeTempFile(t, "denylist.yaml", `
commands:
  - "rm -rf /"
`)
	addr, cleanup := startTestServer(t, "", denylistPath)
	defer cleanup()

	c, err := New(addr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	result, err := c.Evaluate(&model.Action{
		Tool:      "command",
		Resource:  "rm -rf /",
		Operation: "execute",
	}, "general")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if result.Decision != model.Deny {
		t.Errorf("expected deny for rm -rf /, got %s", result.Decision)
	}
	if result.Tier != 3 {
		t.Errorf("expected tier 3, got %d", result.Tier)
	}
}

func TestClientFailClosed(t *testing.T) {
	// Connect to a port that doesn't have a server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	lis.Close() // close immediately — no server running

	c, err := New(addr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	result, err := c.Evaluate(&model.Action{
		Tool:      "command",
		Resource:  "echo hello",
		Operation: "execute",
	}, "general")
	if err != nil {
		t.Fatalf("Evaluate returned error (should not): %v", err)
	}

	// Fail-closed: unreachable server returns deny
	if result.Decision != model.Deny {
		t.Errorf("expected deny (fail-closed), got %s", result.Decision)
	}
	if result.PolicyID != "failclosed.unreachable" {
		t.Errorf("expected failclosed.unreachable policy_id, got %q", result.PolicyID)
	}
}

func TestClientApproveFlow(t *testing.T) {
	policyPath := writeTempFile(t, "policy.yaml", `
enforcement_mode: guarded
rules:
  - purpose: "*"
    resource_pattern: "*salary*"
    decision: require_approval
    reason: "salary needs approval"
    approval_key: salary_client_test
`)
	addr, cleanup := startTestServer(t, policyPath, "")
	defer cleanup()

	c, err := New(addr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	// Trigger require_approval
	result, err := c.Evaluate(&model.Action{
		Tool:      "http_proxy",
		Resource:  "https://internal.corp/api/salary",
		Operation: "get",
	}, "general")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Decision != model.RequireApproval {
		t.Fatalf("expected require_approval, got %s", result.Decision)
	}

	// Approve via client
	if err := c.Approve("salary_client_test", 5*time.Minute); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Verify via ListPending
	list, err := c.ListPending()
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}

	found := false
	for _, a := range list {
		if a.Key == "salary_client_test" {
			found = true
			if a.Status != "approved" {
				t.Errorf("expected approved status, got %s", a.Status)
			}
		}
	}
	if !found {
		t.Error("expected salary_client_test in list")
	}
}

// stubServer implements the gRPC interface to test client against minimal server.
type stubServer struct {
	pb.UnimplementedChainwatchServiceServer
}

func TestClientConnectsToServer(t *testing.T) {
	// Verify client can connect to a raw grpc server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	gs := grpc.NewServer()
	pb.RegisterChainwatchServiceServer(gs, &stubServer{})
	go gs.Serve(lis)
	defer gs.GracefulStop()

	c, err := New(lis.Addr().String())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	// Call Evaluate — stub returns Unimplemented, client should fail-close to deny
	result, err := c.Evaluate(&model.Action{
		Tool:      "command",
		Resource:  "ls",
		Operation: "execute",
	}, "general")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Decision != model.Deny {
		t.Errorf("expected deny (unimplemented = fail-closed), got %s", result.Decision)
	}
}
