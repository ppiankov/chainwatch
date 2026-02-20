package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ppiankov/chainwatch/internal/ingest"
	"github.com/ppiankov/chainwatch/internal/wo"
)

func setupGateway(t *testing.T) (*Gateway, DirConfig) {
	t.Helper()
	root := t.TempDir()
	cfg := DirConfig{
		Inbox:  filepath.Join(root, "inbox"),
		Outbox: filepath.Join(root, "outbox"),
		State:  filepath.Join(root, "state"),
	}
	if err := EnsureDirs(cfg); err != nil {
		t.Fatal(err)
	}
	g := NewGateway(cfg.Outbox, cfg.State, 1*time.Hour)
	return g, cfg
}

func writePendingResult(t *testing.T, outbox string, id string) {
	t.Helper()
	r := &Result{
		ID:          id,
		Status:      ResultPendingApproval,
		CompletedAt: time.Now().UTC(),
	}
	data, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(outbox, id+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayPendingWOs(t *testing.T) {
	g, cfg := setupGateway(t)

	// Write some results.
	writePendingResult(t, cfg.Outbox, "wo-001")
	writePendingResult(t, cfg.Outbox, "wo-002")

	// Write a non-pending result.
	r := &Result{ID: "wo-003", Status: ResultDone, CompletedAt: time.Now().UTC()}
	data, _ := json.MarshalIndent(r, "", "  ")
	_ = os.WriteFile(filepath.Join(cfg.Outbox, "wo-003.json"), data, 0600)

	pending, err := g.PendingWOs()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending WOs, got %d", len(pending))
	}
}

func TestGatewayApprove(t *testing.T) {
	g, cfg := setupGateway(t)
	writePendingResult(t, cfg.Outbox, "wo-approve")

	if err := g.Approve("wo-approve"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Should be in approved dir.
	approvedPath := filepath.Join(cfg.ApprovedDir(), "wo-approve.json")
	if _, err := os.Stat(approvedPath); err != nil {
		t.Error("expected file in approved dir")
	}

	// Should be removed from outbox.
	outboxPath := filepath.Join(cfg.Outbox, "wo-approve.json")
	if _, err := os.Stat(outboxPath); !os.IsNotExist(err) {
		t.Error("expected file removed from outbox")
	}
}

func TestGatewayApproveNonPending(t *testing.T) {
	g, cfg := setupGateway(t)

	// Write a done result.
	r := &Result{ID: "wo-done", Status: ResultDone, CompletedAt: time.Now().UTC()}
	data, _ := json.MarshalIndent(r, "", "  ")
	_ = os.WriteFile(filepath.Join(cfg.Outbox, "wo-done.json"), data, 0600)

	if err := g.Approve("wo-done"); err == nil {
		t.Error("expected error approving non-pending WO")
	}
}

func TestGatewayApproveNonexistent(t *testing.T) {
	g, _ := setupGateway(t)
	if err := g.Approve("nonexistent"); err == nil {
		t.Error("expected error for nonexistent WO")
	}
}

func TestGatewayReject(t *testing.T) {
	g, cfg := setupGateway(t)
	writePendingResult(t, cfg.Outbox, "wo-reject")

	if err := g.Reject("wo-reject", "not appropriate"); err != nil {
		t.Fatalf("Reject: %v", err)
	}

	// Should be in rejected dir.
	rejectedPath := filepath.Join(cfg.RejectedDir(), "wo-reject.json")
	data, err := os.ReadFile(rejectedPath)
	if err != nil {
		t.Fatal("expected file in rejected dir")
	}

	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "rejected" {
		t.Errorf("status = %q, want rejected", result.Status)
	}
	if result.Error != "not appropriate" {
		t.Errorf("error = %q, want 'not appropriate'", result.Error)
	}

	// Should be removed from outbox.
	if _, err := os.Stat(filepath.Join(cfg.Outbox, "wo-reject.json")); !os.IsNotExist(err) {
		t.Error("expected file removed from outbox")
	}
}

func TestGatewayCheckExpired(t *testing.T) {
	root := t.TempDir()
	cfg := DirConfig{
		Inbox:  filepath.Join(root, "inbox"),
		Outbox: filepath.Join(root, "outbox"),
		State:  filepath.Join(root, "state"),
	}
	if err := EnsureDirs(cfg); err != nil {
		t.Fatal(err)
	}

	// Use a very short TTL.
	g := NewGateway(cfg.Outbox, cfg.State, 1*time.Millisecond)

	writePendingResult(t, cfg.Outbox, "wo-expire")

	// Wait for expiration.
	time.Sleep(10 * time.Millisecond)

	n, err := g.CheckExpired()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 expired, got %d", n)
	}

	// Should be in rejected dir.
	rejectedPath := filepath.Join(cfg.RejectedDir(), "wo-expire.json")
	data, err := os.ReadFile(rejectedPath)
	if err != nil {
		t.Fatal("expected expired WO in rejected dir")
	}
	var result Result
	_ = json.Unmarshal(data, &result)
	if result.Error != "expired" {
		t.Errorf("error = %q, want expired", result.Error)
	}
}

func TestGatewayPathTraversal(t *testing.T) {
	g, _ := setupGateway(t)

	for _, id := range []string{"../etc/passwd", "wo-..bad", "wo;bad"} {
		if err := g.Approve(id); err == nil {
			t.Errorf("expected error for path traversal ID %q", id)
		}
		if err := g.Reject(id, "test"); err == nil {
			t.Errorf("expected error for path traversal ID %q", id)
		}
	}
}

func TestGatewayDoubleApprove(t *testing.T) {
	g, cfg := setupGateway(t)
	writePendingResult(t, cfg.Outbox, "wo-double")

	if err := g.Approve("wo-double"); err != nil {
		t.Fatal(err)
	}

	// Second approve should fail (file no longer in outbox).
	if err := g.Approve("wo-double"); err == nil {
		t.Error("expected error for double approve")
	}
}

func writePendingResultWithWO(t *testing.T, outbox string, id string) {
	t.Helper()
	r := &Result{
		ID:     id,
		Status: ResultPendingApproval,
		Observations: []wo.Observation{
			{
				Type:     wo.SuspiciousCode,
				Severity: wo.SeverityHigh,
				Detail:   "eval/base64_decode found",
				Data:     map[string]interface{}{"file": "/var/www/site/loader.php"},
			},
		},
		ProposedWO: &wo.WorkOrder{
			WOVersion:  wo.Version,
			ID:         id,
			CreatedAt:  time.Now().UTC(),
			IncidentID: "job-001",
			Target:     wo.Target{Host: "web-01", Scope: "/var/www/site"},
			Observations: []wo.Observation{
				{
					Type:     wo.SuspiciousCode,
					Severity: wo.SeverityHigh,
					Detail:   "eval/base64_decode found",
					Data:     map[string]interface{}{"file": "/var/www/site/loader.php"},
				},
			},
			Constraints: wo.Constraints{
				AllowPaths: []string{"/var/www/site"},
				DenyPaths:  []string{"/etc"},
				Network:    false,
				Sudo:       false,
				MaxSteps:   10,
			},
			ProposedGoals: []string{"Investigate and remediate: eval/base64_decode found"},
		},
		CompletedAt: time.Now().UTC(),
	}
	data, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(outbox, id+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayApproveWritesIngestPayload(t *testing.T) {
	g, cfg := setupGateway(t)
	writePendingResultWithWO(t, cfg.Outbox, "wo-ingest")

	if err := g.Approve("wo-ingest"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Verify ingest payload exists.
	payloadPath := filepath.Join(cfg.IngestedDir(), "wo-ingest.json")
	data, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatalf("expected ingest payload at %s: %v", payloadPath, err)
	}

	var payload ingest.IngestPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	if payload.WOID != "wo-ingest" {
		t.Errorf("WOID = %q, want %q", payload.WOID, "wo-ingest")
	}
	if payload.Target.Host != "web-01" {
		t.Errorf("Target.Host = %q, want %q", payload.Target.Host, "web-01")
	}
	if len(payload.Observations) != 1 {
		t.Fatalf("Observations count = %d, want 1", len(payload.Observations))
	}

	// Verify raw Data is stripped: re-marshal observation and check no "data" key.
	obsData, _ := json.Marshal(payload.Observations[0])
	var m map[string]interface{}
	_ = json.Unmarshal(obsData, &m)
	if _, hasData := m["data"]; hasData {
		t.Error("ingest observation should not have 'data' field")
	}
}

func TestGatewayApproveNoPayloadWithoutWO(t *testing.T) {
	g, cfg := setupGateway(t)
	writePendingResult(t, cfg.Outbox, "wo-nowopayload")

	if err := g.Approve("wo-nowopayload"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// No ingest payload should be written when ProposedWO is nil.
	payloadPath := filepath.Join(cfg.IngestedDir(), "wo-nowopayload.json")
	if _, err := os.Stat(payloadPath); !os.IsNotExist(err) {
		t.Error("should not write ingest payload when ProposedWO is nil")
	}
}

func TestGatewayEmptyOutbox(t *testing.T) {
	g, _ := setupGateway(t)
	pending, err := g.PendingWOs()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("expected 0 pending, got %d", len(pending))
	}
}
