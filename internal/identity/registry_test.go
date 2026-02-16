package identity

import (
	"testing"

	"github.com/ppiankov/chainwatch/internal/model"
)

func testRegistry() *Registry {
	return NewRegistry(map[string]*AgentConfig{
		"clawbot-prod": {
			Purposes:       []string{"SOC_efficiency", "compliance_check"},
			AllowResources: []string{"/hr/*", "/finance/*"},
			MaxSensitivity: model.SensHigh,
			Rules: []AgentRule{
				{ResourcePattern: "*salary*", Decision: "allow", Reason: "prod authorized"},
			},
		},
		"clawbot-staging": {
			Purposes:       []string{"testing"},
			AllowResources: []string{"/test/*"},
			MaxSensitivity: model.SensMedium,
		},
		"wildcard-agent": {
			Purposes:       []string{"*"},
			AllowResources: []string{},
		},
	})
}

func TestRegistryLookupKnown(t *testing.T) {
	r := testRegistry()
	cfg := r.Lookup("clawbot-prod")
	if cfg == nil {
		t.Fatal("expected config for clawbot-prod")
	}
	if len(cfg.Purposes) != 2 {
		t.Errorf("expected 2 purposes, got %d", len(cfg.Purposes))
	}
}

func TestRegistryLookupUnknown(t *testing.T) {
	r := testRegistry()
	cfg := r.Lookup("unknown-bot")
	if cfg != nil {
		t.Error("expected nil for unknown agent")
	}
}

func TestValidatePurposeMatching(t *testing.T) {
	r := testRegistry()
	if !r.ValidatePurpose("clawbot-prod", "SOC_efficiency") {
		t.Error("expected SOC_efficiency to be valid for clawbot-prod")
	}
	if r.ValidatePurpose("clawbot-prod", "testing") {
		t.Error("expected testing to be invalid for clawbot-prod")
	}
}

func TestValidatePurposeWildcard(t *testing.T) {
	r := testRegistry()
	if !r.ValidatePurpose("wildcard-agent", "anything") {
		t.Error("expected wildcard agent to accept any purpose")
	}
}

func TestMatchResourceInScope(t *testing.T) {
	r := testRegistry()
	if !r.MatchResource("clawbot-prod", "/hr/salaries.csv") {
		t.Error("expected /hr/salaries.csv to match /hr/*")
	}
	if !r.MatchResource("clawbot-prod", "/finance/report.pdf") {
		t.Error("expected /finance/report.pdf to match /finance/*")
	}
}

func TestMatchResourceOutOfScope(t *testing.T) {
	r := testRegistry()
	if r.MatchResource("clawbot-staging", "/hr/salaries.csv") {
		t.Error("expected /hr/salaries.csv to NOT match /test/* for staging")
	}
}

func TestMatchResourceEmptyAllowAll(t *testing.T) {
	r := testRegistry()
	// wildcard-agent has empty AllowResources — should allow everything
	if !r.MatchResource("wildcard-agent", "/anything/at/all") {
		t.Error("expected empty AllowResources to allow all")
	}
}

func TestMatchPatternVariants(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{"*salary*", "/data/salary.csv", true},
		{"*salary*", "/data/report.csv", false},
		{"*.csv", "report.csv", true},
		{"*.csv", "report.txt", false},
		{"/hr/*", "/hr/salaries.csv", true},
		{"/hr/*", "/finance/report.csv", false},
		{"exact.txt", "exact.txt", true},
		{"exact.txt", "other.txt", false},
		{"*", "anything", true},
		{"", "anything", true},
	}

	for _, tt := range tests {
		got := MatchPattern(tt.pattern, tt.value)
		if got != tt.want {
			t.Errorf("MatchPattern(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}
