package profile

import (
	"regexp"
	"strings"

	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/policy"
)

// ApplyToDenylist merges profile execution_boundaries into the denylist.
// Uses existing denylist.AddPattern() — additive, no removal.
func ApplyToDenylist(p *Profile, dl *denylist.Denylist) {
	for _, u := range p.ExecutionBoundaries.URLs {
		dl.AddPattern("urls", u)
	}
	for _, f := range p.ExecutionBoundaries.Files {
		dl.AddPattern("files", f)
	}
	for _, c := range p.ExecutionBoundaries.Commands {
		dl.AddPattern("commands", c)
	}
}

// ApplyToPolicy merges profile policy rules into config.
// Profile rules are prepended (higher priority in first-match-wins order).
// Returns a new config — does not mutate the input.
func ApplyToPolicy(p *Profile, cfg *policy.PolicyConfig) *policy.PolicyConfig {
	if p.Policy == nil || len(p.Policy.Rules) == 0 {
		return cfg
	}

	merged := *cfg
	merged.Rules = make([]policy.Rule, 0, len(p.Policy.Rules)+len(cfg.Rules))
	merged.Rules = append(merged.Rules, p.Policy.Rules...)
	merged.Rules = append(merged.Rules, cfg.Rules...)
	return &merged
}

// MatchesAuthority checks instruction text against authority boundary patterns.
// Returns (matched, reason). Fail-closed: invalid regex is treated as a match.
func MatchesAuthority(p *Profile, instruction string) (bool, string) {
	lower := strings.ToLower(instruction)
	for _, ap := range p.AuthorityBoundaries {
		re, err := regexp.Compile("(?i)" + ap.Pattern)
		if err != nil {
			// Fail-closed: invalid regex blocks
			return true, ap.Reason + " (pattern compile error)"
		}
		if re.MatchString(lower) {
			return true, ap.Reason
		}
	}
	return false, ""
}
