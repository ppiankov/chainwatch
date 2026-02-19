package maildrop

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Allowlist checks sender addresses against a configured list.
type Allowlist struct {
	patterns []string
}

// LoadAllowlist reads an allowlist file. One pattern per line.
// Lines starting with # are comments. Empty lines are skipped.
// Patterns are either exact email addresses or @domain.com wildcards.
func LoadAllowlist(path string) (*Allowlist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open allowlist: %w", err)
	}
	defer func() { _ = f.Close() }()

	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, strings.ToLower(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}
	return &Allowlist{patterns: patterns}, nil
}

// IsAllowed returns true if the sender matches any pattern in the allowlist.
// Matching is case-insensitive. Supports exact match and @domain.com wildcards.
func (a *Allowlist) IsAllowed(sender string) bool {
	sender = strings.ToLower(sender)
	for _, p := range a.patterns {
		if p == sender {
			return true
		}
		// Domain wildcard: @example.com matches any user@example.com.
		if strings.HasPrefix(p, "@") && strings.HasSuffix(sender, p) {
			return true
		}
	}
	return false
}
