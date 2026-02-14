package monitor

import (
	"strings"

	"github.com/ppiankov/chainwatch/internal/profile"
)

// Rule defines a blocked root-level operation.
type Rule struct {
	Pattern     string // substring match against cmdline (case-insensitive)
	Category    string // e.g. "privilege_escalation", "permission_weakening"
	ApprovalKey string // if non-empty, check approval store before blocking
}

// DefaultRules returns the built-in root operation rules.
func DefaultRules() []Rule {
	return []Rule{
		// Privilege escalation
		{Pattern: "sudo ", Category: "privilege_escalation", ApprovalKey: "root_sudo"},
		{Pattern: "su ", Category: "privilege_escalation", ApprovalKey: "root_sudo"},
		{Pattern: "doas ", Category: "privilege_escalation", ApprovalKey: "root_sudo"},

		// Permission weakening
		{Pattern: "chmod 777", Category: "permission_weakening"},
		{Pattern: "chmod +s", Category: "permission_weakening"},
		{Pattern: "chmod u+s", Category: "permission_weakening"},
		{Pattern: "chmod g+s", Category: "permission_weakening"},

		// Ownership escalation
		{Pattern: "chown root", Category: "ownership_escalation"},

		// Service persistence
		{Pattern: "systemctl enable", Category: "service_persistence"},
		{Pattern: "systemctl start", Category: "service_persistence"},

		// Firewall modification
		{Pattern: "iptables ", Category: "firewall_modification"},
		{Pattern: "ip6tables ", Category: "firewall_modification"},
		{Pattern: "nft ", Category: "firewall_modification"},
		{Pattern: "ufw ", Category: "firewall_modification"},

		// Account manipulation
		{Pattern: "useradd ", Category: "account_manipulation"},
		{Pattern: "usermod ", Category: "account_manipulation"},
		{Pattern: "passwd ", Category: "account_manipulation"},
		{Pattern: "groupadd ", Category: "account_manipulation"},

		// Filesystem manipulation
		{Pattern: "mount ", Category: "filesystem_manipulation"},
		{Pattern: "umount ", Category: "filesystem_manipulation"},

		// Package managers (system-level)
		{Pattern: "apt install", Category: "package_installation"},
		{Pattern: "apt-get install", Category: "package_installation"},
		{Pattern: "yum install", Category: "package_installation"},
		{Pattern: "dnf install", Category: "package_installation"},
		{Pattern: "pip install --system", Category: "package_installation"},
	}
}

// RulesFromProfile converts profile command patterns into monitor rules.
func RulesFromProfile(prof *profile.Profile) []Rule {
	var rules []Rule
	for _, cmd := range prof.ExecutionBoundaries.Commands {
		rules = append(rules, Rule{
			Pattern:  cmd,
			Category: "profile_" + prof.Name,
		})
	}
	return rules
}

// Match checks a command line against rules. Returns the first matching rule.
func Match(cmdline string, rules []Rule) (Rule, bool) {
	lower := strings.ToLower(cmdline)

	// Pipe-to-shell detection (structural, not substring)
	if isPipeToShell(lower) {
		return Rule{
			Pattern:  "pipe-to-shell",
			Category: "remote_code_execution",
		}, true
	}

	for _, r := range rules {
		if strings.Contains(lower, strings.ToLower(r.Pattern)) {
			return r, true
		}
	}
	return Rule{}, false
}

// isPipeToShell detects curl|sh, wget|bash, etc.
func isPipeToShell(cmd string) bool {
	if !strings.Contains(cmd, "|") {
		return false
	}
	shells := []string{"sh", "bash", "zsh", "fish"}
	downloaders := []string{"curl", "wget"}

	hasDownloader := false
	for _, d := range downloaders {
		if strings.Contains(cmd, d) {
			hasDownloader = true
			break
		}
	}
	if !hasDownloader {
		return false
	}

	parts := strings.Split(cmd, "|")
	for i := 1; i < len(parts); i++ {
		trimmed := strings.TrimSpace(parts[i])
		for _, s := range shells {
			if trimmed == s || strings.HasPrefix(trimmed, s+" ") {
				return true
			}
		}
	}
	return false
}
