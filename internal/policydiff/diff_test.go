package policydiff

import (
	"testing"

	"github.com/ppiankov/chainwatch/internal/policy"
)

func TestIdenticalPoliciesNoChanges(t *testing.T) {
	a := policy.DefaultConfig()
	b := policy.DefaultConfig()

	r := Diff(a, b)
	if r.HasChanges {
		t.Errorf("expected no changes, got %d changes + %d rule changes",
			len(r.Changes), len(r.RuleChanges))
	}
}

func TestChangedThresholdDetected(t *testing.T) {
	a := policy.DefaultConfig()
	b := policy.DefaultConfig()
	b.Thresholds.AllowMax = 3

	r := Diff(a, b)
	if !r.HasChanges {
		t.Fatal("expected changes")
	}

	found := false
	for _, c := range r.Changes {
		if c.Field == "thresholds.allow_max" {
			found = true
			if c.Old != "5" || c.New != "3" {
				t.Errorf("expected 5→3, got %s→%s", c.Old, c.New)
			}
			if c.Comment != "stricter" {
				t.Errorf("expected 'stricter', got %q", c.Comment)
			}
		}
	}
	if !found {
		t.Error("allow_max change not found")
	}
}

func TestChangedEnforcementMode(t *testing.T) {
	a := policy.DefaultConfig()
	b := policy.DefaultConfig()
	b.EnforcementMode = "locked"

	r := Diff(a, b)
	if !r.HasChanges {
		t.Fatal("expected changes")
	}

	found := false
	for _, c := range r.Changes {
		if c.Field == "enforcement_mode" {
			found = true
			if c.Old != "guarded" || c.New != "locked" {
				t.Errorf("expected guarded→locked, got %s→%s", c.Old, c.New)
			}
		}
	}
	if !found {
		t.Error("enforcement_mode change not found")
	}
}

func TestAddedRuleDetected(t *testing.T) {
	a := policy.DefaultConfig()
	b := policy.DefaultConfig()
	b.Rules = append(b.Rules, policy.Rule{
		Purpose:         "*",
		ResourcePattern: "*password*",
		Decision:        "deny",
	})

	r := Diff(a, b)
	if !r.HasChanges {
		t.Fatal("expected changes")
	}

	found := false
	for _, rc := range r.RuleChanges {
		if rc.Type == "added" {
			found = true
		}
	}
	if !found {
		t.Error("added rule not found")
	}
}

func TestRemovedRuleDetected(t *testing.T) {
	a := policy.DefaultConfig()
	b := policy.DefaultConfig()
	b.Rules = nil // remove all rules

	r := Diff(a, b)
	if !r.HasChanges {
		t.Fatal("expected changes")
	}

	found := false
	for _, rc := range r.RuleChanges {
		if rc.Type == "removed" {
			found = true
		}
	}
	if !found {
		t.Error("removed rule not found")
	}
}

func TestChangedRuleDecision(t *testing.T) {
	a := policy.DefaultConfig()
	b := policy.DefaultConfig()
	// Same purpose+pattern, different decision
	b.Rules[0].Decision = "deny"

	r := Diff(a, b)
	if !r.HasChanges {
		t.Fatal("expected changes")
	}

	found := false
	for _, rc := range r.RuleChanges {
		if rc.Type == "changed" {
			found = true
		}
	}
	if !found {
		t.Error("changed rule not found")
	}
}

func TestChangedSensitivityWeight(t *testing.T) {
	a := policy.DefaultConfig()
	b := policy.DefaultConfig()
	b.SensitivityWeights.High = 10

	r := Diff(a, b)
	if !r.HasChanges {
		t.Fatal("expected changes")
	}

	found := false
	for _, c := range r.Changes {
		if c.Field == "sensitivity_weights.high" {
			found = true
			if c.Old != "6" || c.New != "10" {
				t.Errorf("expected 6→10, got %s→%s", c.Old, c.New)
			}
			if c.Comment != "stricter" {
				t.Errorf("expected 'stricter', got %q", c.Comment)
			}
		}
	}
	if !found {
		t.Error("sensitivity_weights.high change not found")
	}
}

func TestMultipleChanges(t *testing.T) {
	a := policy.DefaultConfig()
	b := policy.DefaultConfig()
	b.EnforcementMode = "locked"
	b.Thresholds.AllowMax = 2
	b.SensitivityWeights.Medium = 5
	b.Rules = append(b.Rules, policy.Rule{
		Purpose:         "*",
		ResourcePattern: "*secret*",
		Decision:        "deny",
	})

	r := Diff(a, b)
	if !r.HasChanges {
		t.Fatal("expected changes")
	}

	// Should have at least 3 scalar changes + 1 rule addition
	if len(r.Changes) < 3 {
		t.Errorf("expected at least 3 changes, got %d", len(r.Changes))
	}
	if len(r.RuleChanges) < 1 {
		t.Errorf("expected at least 1 rule change, got %d", len(r.RuleChanges))
	}
}
