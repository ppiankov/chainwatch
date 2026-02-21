package policy

import (
	"testing"

	"github.com/ppiankov/chainwatch/internal/model"
)

func TestClassifyTierFromBoundaryZone(t *testing.T) {
	tests := []struct {
		zone model.BoundaryZone
		tier int
	}{
		{model.Safe, TierSafe},
		{model.Sensitive, TierElevated},
		{model.Commitment, TierGuarded},
		{model.Irreversible, TierCritical},
	}

	for _, tt := range tests {
		got := ClassifyTier(tt.zone)
		if got != tt.tier {
			t.Errorf("ClassifyTier(%v) = %d, want %d", tt.zone, got, tt.tier)
		}
	}
}

func TestSelfTargetingAlwaysTier3(t *testing.T) {
	tests := []struct {
		resource string
		want     bool
	}{
		{"rm /usr/local/bin/chainwatch", true},
		{"cat ~/.chainwatch/policy.yaml", true},
		{"cat chainwatch.yaml", true},
		{"cat ~/config/nullbot.env", true},
		{"cat /tmp/.groq-key", true},
		{"systemctl status nullbot", true},
		{"rm /usr/local/bin/nullbot", true},
		{"ls /tmp/reports", false},
		{"echo hello", false},
		{"cat /var/log/app.log", false},
	}

	for _, tt := range tests {
		action := &model.Action{Tool: "command", Resource: tt.resource}
		got := model.IsSelfTargeting(action)
		if got != tt.want {
			t.Errorf("IsSelfTargeting(%q) = %v, want %v", tt.resource, got, tt.want)
		}
	}
}

func TestKnownSafeIsTier0(t *testing.T) {
	tests := []struct {
		tool     string
		resource string
		op       string
		sens     string
		want     bool
	}{
		{"command", "ls /tmp", "execute", "low", true},
		{"command", "cat /etc/hosts", "execute", "low", true},
		{"command", "whoami", "execute", "low", true},
		{"file_read", "/data/public/readme.txt", "read", "low", true},
		{"http", "https://example.com/status", "get", "low", true},
		// Not safe: high sensitivity
		{"file_read", "/data/hr/salary.csv", "read", "high", false},
		// Not safe: write operation
		{"file_write", "/tmp/output.txt", "write", "low", false},
		// Not safe: unknown command
		{"command", "unknown_tool --flag", "execute", "low", false},
	}

	for _, tt := range tests {
		action := &model.Action{
			Tool:      tt.tool,
			Resource:  tt.resource,
			Operation: tt.op,
			RawMeta:   map[string]any{"sensitivity": tt.sens},
		}
		action.NormalizeMeta()
		got := IsKnownSafe(action)
		if got != tt.want {
			t.Errorf("IsKnownSafe(tool=%q, res=%q, op=%q, sens=%q) = %v, want %v",
				tt.tool, tt.resource, tt.op, tt.sens, got, tt.want)
		}
	}
}

func TestUnknownDefaultsToTier1(t *testing.T) {
	// An action with no zone signals and not known-safe should
	// be classified as tier 1 (elevated) in the evaluate flow.
	// This is tested in evaluate_test.go; here we verify the
	// building blocks work correctly.
	action := &model.Action{
		Tool:      "custom_tool",
		Resource:  "/some/resource",
		Operation: "process",
		RawMeta:   map[string]any{"sensitivity": "low"},
	}
	action.NormalizeMeta()

	// Not known safe
	if IsKnownSafe(action) {
		t.Error("expected unknown action to not be known-safe")
	}

	// Zone-based tier is 0 (Safe)
	tier := ClassifyTier(model.Safe)
	if tier != TierSafe {
		t.Errorf("expected tier 0, got %d", tier)
	}

	// The evaluate function handles the unknown→1 promotion
}

func TestEnforceByTierAdvisory(t *testing.T) {
	for tier := 0; tier <= 3; tier++ {
		decision, _ := EnforceByTier("advisory", tier)
		if decision != model.Allow {
			t.Errorf("advisory mode: tier %d should Allow, got %s", tier, decision)
		}
	}
}

func TestEnforceByTierGuarded(t *testing.T) {
	tests := []struct {
		tier     int
		decision model.Decision
	}{
		{TierSafe, model.Allow},
		{TierElevated, model.Allow},
		{TierGuarded, model.RequireApproval},
		{TierCritical, model.Deny},
	}

	for _, tt := range tests {
		decision, _ := EnforceByTier("guarded", tt.tier)
		if decision != tt.decision {
			t.Errorf("guarded mode: tier %d should be %s, got %s", tt.tier, tt.decision, decision)
		}
	}
}

func TestEnforceByTierLocked(t *testing.T) {
	tests := []struct {
		tier     int
		decision model.Decision
	}{
		{TierSafe, model.Allow},
		{TierElevated, model.RequireApproval},
		{TierGuarded, model.Deny},
		{TierCritical, model.Deny},
	}

	for _, tt := range tests {
		decision, _ := EnforceByTier("locked", tt.tier)
		if decision != tt.decision {
			t.Errorf("locked mode: tier %d should be %s, got %s", tt.tier, tt.decision, decision)
		}
	}
}

func TestTierLabel(t *testing.T) {
	if TierLabel(0) != "safe" {
		t.Errorf("expected 'safe', got %q", TierLabel(0))
	}
	if TierLabel(1) != "elevated" {
		t.Errorf("expected 'elevated', got %q", TierLabel(1))
	}
	if TierLabel(2) != "guarded" {
		t.Errorf("expected 'guarded', got %q", TierLabel(2))
	}
	if TierLabel(3) != "critical" {
		t.Errorf("expected 'critical', got %q", TierLabel(3))
	}
}

func TestProfileMinTierPromotesOnly(t *testing.T) {
	// MinTier is applied in Evaluate via cfg.MinTier.
	// Here we verify the enforcement decision changes.
	// Tier 0 action promoted to tier 2 by MinTier → RequireApproval in guarded mode
	decision, _ := EnforceByTier("guarded", 2)
	if decision != model.RequireApproval {
		t.Errorf("promoted tier 2 should RequireApproval in guarded, got %s", decision)
	}

	// Tier 3 action stays tier 3 (MinTier cannot demote)
	decision, _ = EnforceByTier("guarded", 3)
	if decision != model.Deny {
		t.Errorf("tier 3 should Deny in guarded, got %s", decision)
	}
}
