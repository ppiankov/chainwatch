package scenario

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/policy"
)

func writeScenario(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAllCasesPass(t *testing.T) {
	cfg := policy.DefaultConfig()
	cfg.EnforcementMode = "guarded"
	dl := denylist.NewDefault()

	s := &Scenario{
		Name: "basic allow",
		Cases: []Case{
			{Action: ScenarioAction{Tool: "file_read", Resource: "/data/report.csv"}, Expect: "allow"},
		},
	}

	result := Run(s, cfg, dl)
	if result.Failed != 0 {
		t.Errorf("expected 0 failures, got %d", result.Failed)
	}
	if result.Passed != 1 {
		t.Errorf("expected 1 passed, got %d", result.Passed)
	}
}

func TestFailedAssertionDetected(t *testing.T) {
	cfg := policy.DefaultConfig()
	cfg.EnforcementMode = "guarded"
	dl := denylist.NewDefault()

	s := &Scenario{
		Name: "wrong expectation",
		Cases: []Case{
			// file_read with default policy → allow (tier 1 in guarded), but we expect deny
			{Action: ScenarioAction{Tool: "file_read", Resource: "/data/report.csv"}, Expect: "deny"},
		},
	}

	result := Run(s, cfg, dl)
	if result.Failed != 1 {
		t.Errorf("expected 1 failure, got %d", result.Failed)
	}
	if result.Passed != 0 {
		t.Errorf("expected 0 passed, got %d", result.Passed)
	}
}

func TestLoadAndRunFromFile(t *testing.T) {
	dir := t.TempDir()
	writeScenario(t, dir, "test.yaml", `
name: "file test"
cases:
  - action: {tool: file_read, resource: /data/report.csv}
    expect: allow
`)

	result, err := LoadAndRun(filepath.Join(dir, "test.yaml"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Failed != 0 {
		t.Errorf("expected 0 failures, got %d", result.Failed)
	}
	if result.File != filepath.Join(dir, "test.yaml") {
		t.Errorf("expected file path set, got %q", result.File)
	}
}

func TestInvalidScenarioYAML(t *testing.T) {
	dir := t.TempDir()
	writeScenario(t, dir, "bad.yaml", ":::not yaml\x00")

	_, err := LoadAndRun(filepath.Join(dir, "bad.yaml"), "", "")
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestPurposeAndAgentPerCase(t *testing.T) {
	cfg := policy.DefaultConfig()
	cfg.EnforcementMode = "guarded"
	// Default config has a rule: SOC_efficiency + *salary* → require_approval
	dl := denylist.NewDefault()

	s := &Scenario{
		Name: "purpose rule match",
		Cases: []Case{
			{
				Action:  ScenarioAction{Tool: "file_read", Resource: "/hr/salary.csv"},
				Expect:  "require_approval",
				Purpose: "SOC_efficiency",
			},
		},
	}

	result := Run(s, cfg, dl)
	if result.Failed != 0 {
		t.Errorf("expected 0 failures, got %d; cases: %+v", result.Failed, result.Cases)
	}
}

func TestEmptyCasesList(t *testing.T) {
	cfg := policy.DefaultConfig()
	dl := denylist.NewDefault()

	s := &Scenario{
		Name:  "empty",
		Cases: []Case{},
	}

	result := Run(s, cfg, dl)
	if result.Total != 0 {
		t.Errorf("expected 0 total, got %d", result.Total)
	}
	if result.Failed != 0 {
		t.Errorf("expected 0 failed, got %d", result.Failed)
	}
}

func TestCaseResultFieldsPopulated(t *testing.T) {
	cfg := policy.DefaultConfig()
	cfg.EnforcementMode = "locked" // tier 1 → require_approval
	dl := denylist.NewDefault()

	s := &Scenario{
		Name: "fields check",
		Cases: []Case{
			{
				Action: ScenarioAction{Tool: "file_read", Resource: "/data/report.csv"},
				Expect: "require_approval",
			},
		},
	}

	result := Run(s, cfg, dl)
	if len(result.Cases) != 1 {
		t.Fatalf("expected 1 case, got %d", len(result.Cases))
	}
	c := result.Cases[0]
	if c.Index != 1 {
		t.Errorf("index: got %d", c.Index)
	}
	if c.Tool != "file_read" {
		t.Errorf("tool: got %s", c.Tool)
	}
	if c.Resource != "/data/report.csv" {
		t.Errorf("resource: got %s", c.Resource)
	}
	if c.Expected != "require_approval" {
		t.Errorf("expected: got %s", c.Expected)
	}
	if c.Actual != "require_approval" {
		t.Errorf("actual: got %s", c.Actual)
	}
	if !c.Passed {
		t.Error("expected passed=true")
	}
	if c.Reason == "" {
		t.Error("reason should not be empty")
	}
}

func TestMultipleScenariosViaGlob(t *testing.T) {
	dir := t.TempDir()
	writeScenario(t, dir, "a.yaml", `
name: "scenario A"
cases:
  - action: {tool: file_read, resource: /data/a.csv}
    expect: allow
`)
	writeScenario(t, dir, "b.yaml", `
name: "scenario B"
cases:
  - action: {tool: file_read, resource: /data/b.csv}
    expect: allow
`)

	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}

	var results []*RunResult
	for _, m := range matches {
		r, err := LoadAndRun(m, "", "")
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, r)
	}

	totalPassed := 0
	for _, r := range results {
		totalPassed += r.Passed
	}
	if totalPassed != 2 {
		t.Errorf("expected 2 total passed across scenarios, got %d", totalPassed)
	}
}
