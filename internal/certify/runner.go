package certify

import (
	"fmt"
	"strings"

	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/policy"
	"github.com/ppiankov/chainwatch/internal/profile"
	"github.com/ppiankov/chainwatch/internal/scenario"
)

// CategoryResult holds pass/fail results for one category.
type CategoryResult struct {
	Name   string                `json:"name"`
	Total  int                   `json:"total"`
	Passed int                   `json:"passed"`
	Failed int                   `json:"failed"`
	Cases  []scenario.CaseResult `json:"cases"`
}

// CertResult holds the full certification outcome.
type CertResult struct {
	Suite      string           `json:"suite"`
	Version    string           `json:"version"`
	Profile    string           `json:"profile"`
	Total      int              `json:"total"`
	Passed     int              `json:"passed"`
	Failed     int              `json:"failed"`
	Categories []CategoryResult `json:"categories"`
}

// Run executes a certification suite against a profile and returns results.
func Run(suite *Suite, profileName, policyPath, denylistPath string) (*CertResult, error) {
	p, err := profile.Load(profileName)
	if err != nil {
		return nil, fmt.Errorf("load profile %q: %w", profileName, err)
	}

	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}

	dl, err := denylist.Load(denylistPath)
	if err != nil {
		return nil, fmt.Errorf("load denylist: %w", err)
	}

	cfg = profile.ApplyToPolicy(p, cfg)
	profile.ApplyToDenylist(p, dl)

	result := &CertResult{
		Suite:   suite.Name,
		Version: suite.Version,
		Profile: profileName,
	}

	for _, cat := range suite.Categories {
		cr := runCategory(cat, cfg, dl)
		result.Total += cr.Total
		result.Passed += cr.Passed
		result.Failed += cr.Failed
		result.Categories = append(result.Categories, cr)
	}

	return result, nil
}

func runCategory(cat Category, cfg *policy.PolicyConfig, dl *denylist.Denylist) CategoryResult {
	cr := CategoryResult{
		Name:  cat.Name,
		Total: len(cat.Cases),
	}

	for i, c := range cat.Cases {
		state := model.NewTraceState(fmt.Sprintf("cert-%s-%d", cat.Name, i))

		action := &model.Action{
			Tool:      c.Action.Tool,
			Resource:  c.Action.Resource,
			Operation: c.Action.Operation,
		}

		evalResult := policy.Evaluate(action, state, c.Purpose, c.Agent, dl, cfg)
		actual := string(evalResult.Decision)
		expected := strings.ToLower(c.Expect)

		caseResult := scenario.CaseResult{
			Index:    i + 1,
			Tool:     c.Action.Tool,
			Resource: c.Action.Resource,
			Expected: expected,
			Actual:   actual,
			Reason:   evalResult.Reason,
		}

		if actual == expected {
			caseResult.Passed = true
			cr.Passed++
		} else {
			cr.Failed++
		}

		cr.Cases = append(cr.Cases, caseResult)
	}

	return cr
}
