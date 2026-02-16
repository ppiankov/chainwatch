package profile

import "fmt"

// InitProfile returns a commented YAML starter template for a new profile.
func InitProfile(name string) string {
	return fmt.Sprintf(`name: %s
description: Custom safety profile

# Authority boundaries — instruction-level regex patterns.
# Matched against instruction text via MatchesAuthority().
authority_boundaries:
  - pattern: "execute.*from.*webpage"
    reason: "Cross-context instruction injection"
  # - pattern: "your-pattern-here"
  #   reason: "Explain why this is blocked"

# Execution boundaries — merged into denylist at runtime.
execution_boundaries:
  urls:
    - "*/admin*"
    # - "*/your-pattern*"
  files:
    - "**/.env"
    - "**/credentials*"
    # - "**/your-pattern*"
  commands:
    - "rm -rf"
    - "sudo"
    # - "your-command"

# Policy rules — prepended to config rules (first-match-wins).
# Decisions: allow, deny, require_approval, redact
# policy:
#   rules:
#     - purpose: "*"
#       resource_pattern: "*sensitive*"
#       decision: deny
#       reason: "blocked by %s profile"
`, name, name)
}
