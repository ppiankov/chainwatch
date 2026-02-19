package redact

import (
	"regexp"
	"sort"
	"strings"
)

// PatternType identifies the category of sensitive data.
type PatternType string

const (
	PatternPath  PatternType = "PATH"
	PatternIP    PatternType = "IP"
	PatternHost  PatternType = "HOST"
	PatternCred  PatternType = "CRED"
	PatternEmail PatternType = "EMAIL"
	PatternUser  PatternType = "USER"
)

// Match is a single occurrence of sensitive data in text.
type Match struct {
	Type  PatternType
	Value string
	Start int
	End   int
}

// Compiled patterns for sensitive data detection.
var (
	// Paths starting with common Linux directories, capturing until whitespace.
	pathRe = regexp.MustCompile(`(/(?:home|var|etc|root|usr|tmp|opt)/\S+)`)

	// IPv4 addresses (simple: 4 octets, no validation of range).
	ipv4Re = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

	// Hostnames: FQDN with at least one dot and valid TLD.
	hostRe = regexp.MustCompile(`\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[-a-zA-Z0-9]+\.[a-zA-Z]{2,})\b`)

	// Credentials: key=value pairs where key suggests a secret.
	credKVRe = regexp.MustCompile(`(?i)((?:password|passwd|secret|token|api_key|apikey|auth)[ \t]*[=:][ \t]*\S+)`)

	// Email addresses.
	emailRe = regexp.MustCompile(`\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b`)

	// Usernames from /etc/passwd lines: "username:x:uid:gid:".
	passwdUserRe = regexp.MustCompile(`(?m)^([a-zA-Z_][a-zA-Z0-9_\-]*):x:\d+:\d+:`)

	// Usernames from ~username paths.
	tildeUserRe = regexp.MustCompile(`~([a-zA-Z_][a-zA-Z0-9_\-]+)`)
)

// safeHosts are domains that should not be tokenized.
var safeHosts = map[string]bool{
	"example.com":       true,
	"example.org":       true,
	"example.net":       true,
	"localhost":         true,
	"github.com":        true,
	"golang.org":        true,
	"google.com":        true,
	"cloudflare.com":    true,
	"amazonaws.com":     true,
	"ubuntu.com":        true,
	"debian.org":        true,
	"kernel.org":        true,
	"wikipedia.org":     true,
	"stackexchange.com": true,
	"stackoverflow.com": true,
}

// safeIPs are IP addresses that should not be tokenized.
var safeIPs = map[string]bool{
	"127.0.0.1":       true,
	"0.0.0.0":         true,
	"255.255.255.255": true,
}

// Scan finds all sensitive patterns in text and returns deduplicated matches
// sorted by position (earliest first).
func Scan(text string) []Match {
	seen := make(map[string]bool)
	var matches []Match

	add := func(typ PatternType, value string, start int) {
		value = strings.TrimRight(value, ".,;:\"'`)}]")
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		matches = append(matches, Match{Type: typ, Value: value, Start: start, End: start + len(value)})
	}

	// Paths.
	for _, loc := range pathRe.FindAllStringIndex(text, -1) {
		add(PatternPath, text[loc[0]:loc[1]], loc[0])
	}

	// IPv4.
	for _, loc := range ipv4Re.FindAllStringIndex(text, -1) {
		v := text[loc[0]:loc[1]]
		if !safeIPs[v] {
			add(PatternIP, v, loc[0])
		}
	}

	// Hostnames.
	for _, loc := range hostRe.FindAllStringIndex(text, -1) {
		v := text[loc[0]:loc[1]]
		lower := strings.ToLower(v)
		if !safeHosts[lower] && !isIPLike(v) {
			add(PatternHost, v, loc[0])
		}
	}

	// Credentials.
	for _, loc := range credKVRe.FindAllStringIndex(text, -1) {
		add(PatternCred, text[loc[0]:loc[1]], loc[0])
	}

	// Emails.
	for _, loc := range emailRe.FindAllStringIndex(text, -1) {
		add(PatternEmail, text[loc[0]:loc[1]], loc[0])
	}

	// Usernames from /etc/passwd lines.
	for _, sub := range passwdUserRe.FindAllStringSubmatchIndex(text, -1) {
		if sub[2] >= 0 && sub[3] >= 0 {
			v := text[sub[2]:sub[3]]
			if v != "root" {
				add(PatternUser, v, sub[2])
			}
		}
	}

	// Usernames from ~username.
	for _, sub := range tildeUserRe.FindAllStringSubmatchIndex(text, -1) {
		if sub[2] >= 0 && sub[3] >= 0 {
			add(PatternUser, text[sub[2]:sub[3]], sub[2])
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Start < matches[j].Start
	})

	return matches
}

// isIPLike returns true if the string looks like an IP address (all digits and dots).
func isIPLike(s string) bool {
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
