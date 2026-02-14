package denylist

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Patterns holds the raw pattern strings organized by category.
type Patterns struct {
	URLs     []string `yaml:"urls"`
	Files    []string `yaml:"files"`
	Commands []string `yaml:"commands"`
}

// Denylist holds compiled patterns for fast matching.
type Denylist struct {
	urlPatterns     []*regexp.Regexp
	filePatterns    []string // glob-style, matched via containment
	commandPatterns []string // substring matching (case-insensitive)
	raw             Patterns
}

// New creates a Denylist from raw patterns, compiling regexes.
func New(p Patterns) *Denylist {
	d := &Denylist{raw: p}

	for _, u := range p.URLs {
		re := patternToRegex(u)
		if compiled, err := regexp.Compile("(?i)" + re); err == nil {
			d.urlPatterns = append(d.urlPatterns, compiled)
		}
	}

	d.filePatterns = p.Files

	d.commandPatterns = p.Commands

	return d
}

// NewDefault creates a Denylist with the hardcoded default patterns.
func NewDefault() *Denylist {
	return New(DefaultPatterns)
}

// Load reads a denylist from a YAML file. Falls back to defaults if file doesn't exist.
func Load(path string) (*Denylist, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return NewDefault(), nil
		}
		path = filepath.Join(home, ".chainwatch", "denylist.yaml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewDefault(), nil
		}
		return nil, err
	}

	var p Patterns
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}

	return New(p), nil
}

// IsBlocked checks if a resource is blocked for the given tool type.
// Returns (blocked, reason).
func (d *Denylist) IsBlocked(resource, tool string) (bool, string) {
	lowerResource := strings.ToLower(resource)
	lowerTool := strings.ToLower(tool)

	// URL patterns — checked for browser/HTTP tools and URL-like resources
	if isBrowserTool(lowerTool) || isURL(lowerResource) {
		for _, re := range d.urlPatterns {
			if re.MatchString(lowerResource) {
				return true, "URL pattern blocked: " + re.String()
			}
		}
	}

	// File patterns — checked for file operations
	if isFileTool(lowerTool) || (!isBrowserTool(lowerTool) && !isCommandTool(lowerTool)) {
		for _, pattern := range d.filePatterns {
			if matchFilePattern(lowerResource, strings.ToLower(pattern)) {
				return true, "file pattern blocked: " + pattern
			}
		}
	}

	// Command patterns — checked for shell/command tools
	if isCommandTool(lowerTool) {
		for _, pattern := range d.commandPatterns {
			if strings.Contains(lowerResource, strings.ToLower(pattern)) {
				return true, "command pattern blocked: " + pattern
			}
		}
		// Structural pipe-to-shell detection
		if isPipeToShell(lowerResource) {
			return true, "pipe-to-shell execution detected"
		}
	}

	return false, ""
}

// AddPattern adds a pattern to the denylist at runtime.
func (d *Denylist) AddPattern(category, pattern string) {
	switch category {
	case "urls":
		d.raw.URLs = append(d.raw.URLs, pattern)
		re := patternToRegex(pattern)
		if compiled, err := regexp.Compile("(?i)" + re); err == nil {
			d.urlPatterns = append(d.urlPatterns, compiled)
		}
	case "files":
		d.raw.Files = append(d.raw.Files, pattern)
		d.filePatterns = append(d.filePatterns, pattern)
	case "commands":
		d.raw.Commands = append(d.raw.Commands, pattern)
		d.commandPatterns = append(d.commandPatterns, pattern)
	}
}

// ToMap returns the raw patterns as a map for serialization.
func (d *Denylist) ToMap() map[string]any {
	return map[string]any{
		"urls":     d.raw.URLs,
		"files":    d.raw.Files,
		"commands": d.raw.Commands,
	}
}

// patternToRegex converts a simple glob-like pattern to a regex.
func patternToRegex(pattern string) string {
	escaped := regexp.QuoteMeta(pattern)
	// Restore * as .* for glob-style matching
	escaped = strings.ReplaceAll(escaped, `\*\*`, ".*")
	escaped = strings.ReplaceAll(escaped, `\*`, "[^/]*")
	return escaped
}

func matchFilePattern(resource, pattern string) bool {
	// Expand ~ in pattern for exact match
	expanded := pattern
	if strings.HasPrefix(expanded, "~/") {
		suffix := expanded[2:] // e.g. ".ssh/id_rsa"
		// Match the suffix anywhere in the resource path
		if strings.Contains(resource, suffix) {
			return true
		}
		// Also try with home dir expansion for exact path match
		if home, err := os.UserHomeDir(); err == nil {
			expanded = filepath.Join(strings.ToLower(home), suffix)
		}
	}

	// Glob-style: ** matches anything
	if strings.Contains(expanded, "**") {
		// Convert to simple substring: strip ** prefix
		suffix := strings.ReplaceAll(expanded, "**/", "")
		suffix = strings.ReplaceAll(suffix, "**", "")
		return strings.Contains(resource, suffix)
	}

	// Direct containment
	return strings.Contains(resource, expanded)
}

func isBrowserTool(tool string) bool {
	return strings.Contains(tool, "browser") || strings.Contains(tool, "http") || strings.Contains(tool, "web")
}

func isFileTool(tool string) bool {
	return strings.Contains(tool, "file") || strings.Contains(tool, "read") || strings.Contains(tool, "write")
}

func isCommandTool(tool string) bool {
	return strings.Contains(tool, "shell") || strings.Contains(tool, "command") || strings.Contains(tool, "exec")
}

func isURL(resource string) bool {
	return strings.HasPrefix(resource, "http://") || strings.HasPrefix(resource, "https://")
}

// isPipeToShell detects piped-to-shell patterns like "curl ... | sh" or "wget ... | bash".
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

	// Check if anything after pipe is a shell
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
