package scenario

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/policy"
	"github.com/ppiankov/chainwatch/internal/profile"
)

const minimumScenarioLibraryPassRate = 0.80

func TestScenarioLibrary(t *testing.T) {
	scenarioDir := scenarioLibraryDir(t)
	paths := scenarioLibraryPaths(t, scenarioDir)

	cfg := policy.DefaultConfig()

	totalCases := 0
	passedCases := 0
	var failures []string

	for _, path := range paths {
		scenarioDef := loadScenarioFile(t, path)

		if scenarioDef.Profile != "" {
			if _, err := profile.Load(scenarioDef.Profile); err != nil {
				t.Fatalf("%s: load profile %q: %v", path, scenarioDef.Profile, err)
			}
		}

		validateScenario(t, path, &scenarioDef)

		result := Run(&scenarioDef, cfg, denylist.NewDefault())
		totalCases += result.Total
		passedCases += result.Passed

		for _, caseResult := range result.Cases {
			if caseResult.Passed {
				continue
			}
			failures = append(failures, fmt.Sprintf(
				"%s case %d: %s %q expected %s, got %s (%s)",
				filepath.Base(path),
				caseResult.Index,
				caseResult.Tool,
				caseResult.Resource,
				caseResult.Expected,
				caseResult.Actual,
				caseResult.Reason,
			))
		}
	}

	if totalCases == 0 {
		t.Fatal("scenario library is empty")
	}

	for _, failure := range failures {
		t.Log(failure)
	}

	passRate := float64(passedCases) / float64(totalCases)
	t.Logf("scenario library pass rate: %.1f%% (%d/%d)", passRate*100, passedCases, totalCases)

	if passRate < minimumScenarioLibraryPassRate {
		t.Fatalf(
			"scenario library pass rate %.1f%% (%d/%d), want at least %.0f%%",
			passRate*100,
			passedCases,
			totalCases,
			minimumScenarioLibraryPassRate*100,
		)
	}
}

func scenarioLibraryDir(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}

	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "tests", "scenarios"))
}

func scenarioLibraryPaths(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read scenario dir %s: %v", dir, err)
	}

	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		paths = append(paths, filepath.Join(dir, name))
	}

	if len(paths) == 0 {
		t.Fatalf("no scenario files found in %s", dir)
	}

	return paths
}

func loadScenarioFile(t *testing.T, path string) Scenario {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scenario %s: %v", path, err)
	}

	var scenarioDef Scenario
	if err := yaml.Unmarshal(data, &scenarioDef); err != nil {
		t.Fatalf("parse scenario %s: %v", path, err)
	}

	return scenarioDef
}

func validateScenario(t *testing.T, path string, scenarioDef *Scenario) {
	t.Helper()

	if strings.TrimSpace(scenarioDef.Name) == "" {
		t.Fatalf("%s: scenario name is required", path)
	}
	if len(scenarioDef.Cases) == 0 {
		t.Fatalf("%s: scenario must contain at least one case", path)
	}

	validExpectations := map[string]bool{
		"allow":            true,
		"deny":             true,
		"require_approval": true,
	}

	for i, c := range scenarioDef.Cases {
		if strings.TrimSpace(c.Action.Tool) == "" {
			t.Fatalf("%s: case %d missing action.tool", path, i+1)
		}
		if strings.TrimSpace(c.Action.Resource) == "" {
			t.Fatalf("%s: case %d missing action.resource", path, i+1)
		}

		expectation := strings.ToLower(strings.TrimSpace(c.Expect))
		if !validExpectations[expectation] {
			t.Fatalf("%s: case %d has unsupported expect value %q", path, i+1, c.Expect)
		}
	}
}
