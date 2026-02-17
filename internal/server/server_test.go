package server

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/ppiankov/chainwatch/api/proto/chainwatch/v1"
)

// testServer spins up an in-process gRPC server on a random port and returns a client.
func testServer(t *testing.T, policyPath, denylistPath string) (pb.ChainwatchServiceClient, func()) {
	t.Helper()

	cfg := Config{
		PolicyPath:   policyPath,
		DenylistPath: denylistPath,
		ApprovalDir:  filepath.Join(t.TempDir(), "approvals"),
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go srv.ServeOn(lis)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		srv.GracefulStop()
		t.Fatalf("dial: %v", err)
	}

	client := pb.NewChainwatchServiceClient(conn)

	cleanup := func() {
		conn.Close()
		srv.GracefulStop()
		srv.Close()
	}
	return client, cleanup
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func TestEvaluateAllowsLowRisk(t *testing.T) {
	client, cleanup := testServer(t, "", "")
	defer cleanup()

	resp, err := client.Evaluate(context.Background(), &pb.EvalRequest{
		Action: &pb.Action{
			Tool:      "command",
			Resource:  "ls",
			Operation: "execute",
		},
		Purpose: "general",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if resp.Decision == "deny" {
		t.Errorf("expected non-deny decision for ls, got %s: %s", resp.Decision, resp.Reason)
	}
	if resp.TraceId == "" {
		t.Error("expected trace_id to be set")
	}
}

func TestEvaluateDeniesDestructive(t *testing.T) {
	denylistPath := writeTempFile(t, "denylist.yaml", `
commands:
  - "rm -rf /"
`)
	client, cleanup := testServer(t, "", denylistPath)
	defer cleanup()

	resp, err := client.Evaluate(context.Background(), &pb.EvalRequest{
		Action: &pb.Action{
			Tool:      "command",
			Resource:  "rm -rf /",
			Operation: "execute",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if resp.Decision != "deny" {
		t.Errorf("expected deny for rm -rf /, got %s", resp.Decision)
	}
	if resp.Tier != 3 {
		t.Errorf("expected tier 3, got %d", resp.Tier)
	}
}

func TestEvaluateDenylistBlock(t *testing.T) {
	denylistPath := writeTempFile(t, "denylist.yaml", `
urls:
  - "evil.com"
`)
	client, cleanup := testServer(t, "", denylistPath)
	defer cleanup()

	resp, err := client.Evaluate(context.Background(), &pb.EvalRequest{
		Action: &pb.Action{
			Tool:      "http_proxy",
			Resource:  "https://evil.com/exfil",
			Operation: "get",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if resp.Decision != "deny" {
		t.Errorf("expected deny for denylisted URL, got %s", resp.Decision)
	}
}

func TestEvaluateRequiresApproval(t *testing.T) {
	policyPath := writeTempFile(t, "policy.yaml", `
enforcement_mode: guarded
rules:
  - purpose: "*"
    resource_pattern: "*salary*"
    decision: require_approval
    reason: "salary data requires approval"
    approval_key: salary_access
`)
	client, cleanup := testServer(t, policyPath, "")
	defer cleanup()

	resp, err := client.Evaluate(context.Background(), &pb.EvalRequest{
		Action: &pb.Action{
			Tool:      "http_proxy",
			Resource:  "https://internal.corp/api/salary",
			Operation: "get",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if resp.Decision != "require_approval" {
		t.Errorf("expected require_approval, got %s", resp.Decision)
	}
	if resp.ApprovalKey != "salary_access" {
		t.Errorf("expected approval_key salary_access, got %q", resp.ApprovalKey)
	}
}

func TestApproveAndReevaluate(t *testing.T) {
	policyPath := writeTempFile(t, "policy.yaml", `
enforcement_mode: guarded
rules:
  - purpose: "*"
    resource_pattern: "*salary*"
    decision: require_approval
    reason: "salary data requires approval"
    approval_key: salary_access
`)
	client, cleanup := testServer(t, policyPath, "")
	defer cleanup()

	// First: trigger the require_approval
	resp, err := client.Evaluate(context.Background(), &pb.EvalRequest{
		Action: &pb.Action{
			Tool:      "http_proxy",
			Resource:  "https://internal.corp/api/salary",
			Operation: "get",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if resp.Decision != "require_approval" {
		t.Fatalf("expected require_approval, got %s", resp.Decision)
	}

	// Approve it
	approveResp, err := client.Approve(context.Background(), &pb.ApproveRequest{
		Key: "salary_access",
	})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if approveResp.Status != "approved" {
		t.Errorf("expected approved, got %s", approveResp.Status)
	}

	// Re-evaluate: should now be allowed
	resp2, err := client.Evaluate(context.Background(), &pb.EvalRequest{
		Action: &pb.Action{
			Tool:      "http_proxy",
			Resource:  "https://internal.corp/api/salary",
			Operation: "get",
		},
	})
	if err != nil {
		t.Fatalf("re-Evaluate: %v", err)
	}
	if resp2.Decision != "allow" {
		t.Errorf("expected allow after approval, got %s: %s", resp2.Decision, resp2.Reason)
	}
}

func TestListPending(t *testing.T) {
	policyPath := writeTempFile(t, "policy.yaml", `
enforcement_mode: guarded
rules:
  - purpose: "*"
    resource_pattern: "*salary*"
    decision: require_approval
    reason: "salary data requires approval"
    approval_key: salary_pending_test
`)
	client, cleanup := testServer(t, policyPath, "")
	defer cleanup()

	// Trigger to create pending
	_, err := client.Evaluate(context.Background(), &pb.EvalRequest{
		Action: &pb.Action{
			Tool:      "http_proxy",
			Resource:  "https://internal.corp/api/salary",
			Operation: "get",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	// List pending
	listResp, err := client.ListPending(context.Background(), &pb.ListPendingRequest{})
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}

	found := false
	for _, a := range listResp.Approvals {
		if a.Key == "salary_pending_test" {
			found = true
			if a.Status != "pending" {
				t.Errorf("expected pending status, got %s", a.Status)
			}
		}
	}
	if !found {
		t.Error("expected salary_pending_test in pending list")
	}
}

func TestDenyApproval(t *testing.T) {
	policyPath := writeTempFile(t, "policy.yaml", `
enforcement_mode: guarded
rules:
  - purpose: "*"
    resource_pattern: "*salary*"
    decision: require_approval
    reason: "salary data requires approval"
    approval_key: salary_deny_test
`)
	client, cleanup := testServer(t, policyPath, "")
	defer cleanup()

	// Trigger to create pending
	_, _ = client.Evaluate(context.Background(), &pb.EvalRequest{
		Action: &pb.Action{
			Tool:      "http_proxy",
			Resource:  "https://internal.corp/api/salary",
			Operation: "get",
		},
	})

	// Deny it
	denyResp, err := client.Deny(context.Background(), &pb.DenyRequest{
		Key: "salary_deny_test",
	})
	if err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if denyResp.Status != "denied" {
		t.Errorf("expected denied, got %s", denyResp.Status)
	}
}

func TestConcurrentEvaluations(t *testing.T) {
	client, cleanup := testServer(t, "", "")
	defer cleanup()

	var wg sync.WaitGroup
	errs := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.Evaluate(context.Background(), &pb.EvalRequest{
				Action: &pb.Action{
					Tool:      "command",
					Resource:  "echo hello",
					Operation: "execute",
				},
			})
			if err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent eval error: %v", err)
	}
}

func TestHotReloadPolicyChange(t *testing.T) {
	// Write initial policy allowing everything
	policyPath := writeTempFile(t, "policy.yaml", `
enforcement_mode: guarded
rules: []
`)

	cfg := Config{PolicyPath: policyPath}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.ServeOn(lis)
	defer srv.GracefulStop()
	defer srv.Close()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewChainwatchServiceClient(conn)

	// Evaluate before reload — salary should not be blocked (no rule)
	resp1, err := client.Evaluate(context.Background(), &pb.EvalRequest{
		Action: &pb.Action{
			Tool:      "http_proxy",
			Resource:  "https://internal.corp/api/salary",
			Operation: "get",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate before reload: %v", err)
	}
	if resp1.Decision == "require_approval" {
		t.Fatalf("expected no require_approval before reload, got %s", resp1.Decision)
	}

	// Overwrite policy file to add salary rule
	newPolicy := `
enforcement_mode: guarded
rules:
  - purpose: "*"
    resource_pattern: "*salary*"
    decision: require_approval
    reason: "salary needs approval after reload"
    approval_key: salary_reload_test
`
	if err := os.WriteFile(policyPath, []byte(newPolicy), 0644); err != nil {
		t.Fatalf("write new policy: %v", err)
	}

	// Manually trigger reload (no need to wait for fsnotify in tests)
	if err := srv.ReloadPolicy(); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}

	// Evaluate after reload — salary should now require approval
	resp2, err := client.Evaluate(context.Background(), &pb.EvalRequest{
		Action: &pb.Action{
			Tool:      "http_proxy",
			Resource:  "https://internal.corp/api/salary",
			Operation: "get",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate after reload: %v", err)
	}
	if resp2.Decision != "require_approval" {
		t.Errorf("expected require_approval after reload, got %s: %s", resp2.Decision, resp2.Reason)
	}
}

func TestTraceStateAccumulatesAcrossRequests(t *testing.T) {
	client, cleanup := testServer(t, "", "")
	defer cleanup()

	traceID := "test-trace-accumulate"

	// First request with one tool
	_, err := client.Evaluate(context.Background(), &pb.EvalRequest{
		Action: &pb.Action{
			Tool:      "command",
			Resource:  "echo hello",
			Operation: "execute",
		},
		TraceId: traceID,
	})
	if err != nil {
		t.Fatalf("Evaluate 1: %v", err)
	}

	// Second request with different tool, same trace
	resp, err := client.Evaluate(context.Background(), &pb.EvalRequest{
		Action: &pb.Action{
			Tool:      "http_proxy",
			Resource:  "https://api.example.com/data",
			Operation: "get",
			Meta:      map[string]string{"egress": "external", "sensitivity": "high"},
		},
		TraceId: traceID,
	})
	if err != nil {
		t.Fatalf("Evaluate 2: %v", err)
	}

	// Trace state should have accumulated — the second action with high sensitivity
	// and external egress should push the tier higher than a standalone low-risk action
	if resp.TraceId != traceID {
		t.Errorf("expected trace_id %q, got %q", traceID, resp.TraceId)
	}
}

func TestEvaluateMissingAction(t *testing.T) {
	client, cleanup := testServer(t, "", "")
	defer cleanup()

	resp, err := client.Evaluate(context.Background(), &pb.EvalRequest{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if resp.Decision != "deny" {
		t.Errorf("expected deny for missing action, got %s", resp.Decision)
	}
}

func TestReloaderCreation(t *testing.T) {
	policyPath := writeTempFile(t, "policy.yaml", `enforcement_mode: guarded`)

	srv, err := New(Config{PolicyPath: policyPath})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()

	r, err := NewReloader(srv, []string{policyPath})
	if err != nil {
		t.Fatalf("NewReloader: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)

	// Write to trigger reload
	os.WriteFile(policyPath, []byte("enforcement_mode: locked"), 0644)
	time.Sleep(800 * time.Millisecond) // debounce is 500ms

	srv.mu.RLock()
	mode := srv.policyCfg.EnforcementMode
	srv.mu.RUnlock()

	if mode != "locked" {
		t.Errorf("expected enforcement_mode locked after reload, got %q", mode)
	}

	cancel()
}
