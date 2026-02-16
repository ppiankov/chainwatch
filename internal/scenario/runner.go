package scenario

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/policy"
	"github.com/ppiankov/chainwatch/internal/profile"
)

// Run evaluates all cases in a scenario against the given policy and denylist.
// Each case gets a fresh TraceState (cases are independent).
func Run(s *Scenario, cfg *policy.PolicyConfig, dl *denylist.Denylist) *RunResult {
	evalCfg := cfg
	evalDL := dl

	// Apply scenario-level profile if specified
	if s.Profile != "" {
		p, err := profile.Load(s.Profile)
		if err == nil {
			evalCfg = profile.ApplyToPolicy(p, evalCfg)
			if evalDL != nil {
				profile.ApplyToDenylist(p, evalDL)
			}
		}
	}

	result := &RunResult{
		Name:  s.Name,
		Total: len(s.Cases),
	}

	for i, c := range s.Cases {
		state := model.NewTraceState(fmt.Sprintf("scenario-%d", i))

		action := &model.Action{
			Tool:      c.Action.Tool,
			Resource:  c.Action.Resource,
			Operation: c.Action.Operation,
		}

		evalResult := policy.Evaluate(action, state, c.Purpose, c.Agent, evalDL, evalCfg)
		actual := string(evalResult.Decision)
		expected := strings.ToLower(c.Expect)

		cr := CaseResult{
			Index:    i + 1,
			Tool:     c.Action.Tool,
			Resource: c.Action.Resource,
			Expected: expected,
			Actual:   actual,
			Reason:   evalResult.Reason,
		}

		if actual == expected {
			cr.Passed = true
			result.Passed++
		} else {
			result.Failed++
		}

		result.Cases = append(result.Cases, cr)
	}

	return result
}

// LoadAndRun loads a scenario YAML file, loads policy and denylist, and runs.
func LoadAndRun(path, policyPath, denylistPath string) (*RunResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scenario %s: %w", path, err)
	}

	var s Scenario
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse scenario %s: %w", path, err)
	}

	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}

	dl, err := denylist.Load(denylistPath)
	if err != nil {
		return nil, fmt.Errorf("load denylist: %w", err)
	}

	result := Run(&s, cfg, dl)
	result.File = path

	return result, nil
}
