package observe

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Runbook is a named set of investigation steps.
type Runbook struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Aliases []string `yaml:"aliases,omitempty"`
	Steps   []Step   `yaml:"steps"`
	Source  string   `yaml:"-"` // "built-in" or "user" — set at load time
}

// Step defines a single investigation command with its purpose.
type Step struct {
	Command string `yaml:"command"`
	Purpose string `yaml:"purpose"`
}

// destructivePrefixes are command prefixes that runbook steps must not start with.
// Checked against the primary command (before pipes and fallbacks).
var destructivePrefixes = []string{
	"rm ", "mv ", "cp ", "chmod ", "chown ", "tee ", "sed -i", "kill ", "pkill ",
}

// ValidateRunbook checks that a runbook has all required fields and no
// destructive primary commands.
func ValidateRunbook(rb *Runbook) error {
	if rb.Name == "" {
		return fmt.Errorf("runbook name is required")
	}
	if rb.Type == "" {
		return fmt.Errorf("runbook type is required")
	}
	if len(rb.Steps) == 0 {
		return fmt.Errorf("runbook must have at least one step")
	}
	for i, step := range rb.Steps {
		if step.Command == "" {
			return fmt.Errorf("step %d has empty command", i)
		}
		if step.Purpose == "" {
			return fmt.Errorf("step %d has empty purpose", i)
		}
		if err := checkDestructive(step); err != nil {
			return fmt.Errorf("step %d: %w", i, err)
		}
	}
	return nil
}

// checkDestructive verifies the primary command (before pipes/fallbacks)
// does not start with a destructive operation.
func checkDestructive(step Step) error {
	primary := step.Command
	for _, sep := range []string{"||", "|", ";"} {
		if idx := strings.Index(primary, sep); idx >= 0 {
			primary = primary[:idx]
		}
	}
	primary = strings.TrimSpace(primary)
	for _, d := range destructivePrefixes {
		if strings.HasPrefix(primary, d) {
			return fmt.Errorf("destructive command %q in step %q", d, step.Purpose)
		}
	}
	return nil
}

// ParseRunbook parses a YAML runbook definition.
func ParseRunbook(data []byte) (*Runbook, error) {
	var rb Runbook
	if err := yaml.Unmarshal(data, &rb); err != nil {
		return nil, fmt.Errorf("parse runbook YAML: %w", err)
	}
	if err := ValidateRunbook(&rb); err != nil {
		return nil, fmt.Errorf("invalid runbook: %w", err)
	}
	return &rb, nil
}

// userRunbooksDir returns the path to the user's custom runbook directory.
func userRunbooksDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".chainwatch", "runbooks")
}

// loadUserRunbook attempts to load a runbook from the user's runbook directory.
func loadUserRunbook(name string) (*Runbook, error) {
	dir := userRunbooksDir()
	if dir == "" {
		return nil, fmt.Errorf("no home directory")
	}
	path := filepath.Join(dir, name+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rb, err := ParseRunbook(data)
	if err != nil {
		return nil, fmt.Errorf("user runbook %s: %w", path, err)
	}
	rb.Source = "user"
	return rb, nil
}

// LoadRunbook loads a runbook by name or alias. Resolution order:
//  1. User directory (~/.chainwatch/runbooks/<name>.yaml)
//  2. Built-in embedded runbooks
//  3. Falls back to linux if no match
func LoadRunbook(name string) *Runbook {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = "linux"
	}

	// Check user directory first (override).
	if rb, err := loadUserRunbook(name); err == nil {
		return rb
	}

	// Check built-in embedded runbooks.
	if rb, err := loadBuiltinRunbook(name); err == nil {
		rb.Source = "built-in"
		return rb
	}

	// Check aliases across all built-in runbooks.
	for _, entry := range listBuiltinRunbooks() {
		for _, alias := range entry.Aliases {
			if alias == name {
				if rb, err := loadBuiltinRunbook(entry.Type); err == nil {
					rb.Source = "built-in"
					return rb
				}
			}
		}
	}

	// Final fallback: linux.
	if name != "linux" {
		return LoadRunbook("linux")
	}

	// Hardcoded emergency fallback if embedded files are broken.
	return linuxFallback()
}

// GetRunbook returns the appropriate runbook for the given type.
// This is the primary entry point used by the daemon and observe command.
func GetRunbook(runbookType string) *Runbook {
	return LoadRunbook(runbookType)
}

// RunbookInfo holds metadata about an available runbook for listing.
type RunbookInfo struct {
	Name    string
	Type    string
	Aliases []string
	Steps   int
	Source  string
}

// ListRunbooks returns metadata for all available runbooks (built-in + user).
// User runbooks with the same type as a built-in override it.
func ListRunbooks() []RunbookInfo {
	seen := make(map[string]RunbookInfo)

	// Built-in runbooks first.
	for _, rb := range listBuiltinRunbooks() {
		seen[rb.Type] = RunbookInfo{
			Name:    rb.Name,
			Type:    rb.Type,
			Aliases: rb.Aliases,
			Steps:   len(rb.Steps),
			Source:  "built-in",
		}
	}

	// User runbooks override by type.
	dir := userRunbooksDir()
	if dir != "" {
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
					continue
				}
				path := filepath.Join(dir, e.Name())
				data, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				rb, err := ParseRunbook(data)
				if err != nil {
					continue
				}
				seen[rb.Type] = RunbookInfo{
					Name:    rb.Name,
					Type:    rb.Type,
					Aliases: rb.Aliases,
					Steps:   len(rb.Steps),
					Source:  "user",
				}
			}
		}
	}

	result := make([]RunbookInfo, 0, len(seen))
	for _, info := range seen {
		result = append(result, info)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Type < result[j].Type
	})
	return result
}

// linuxFallback is a hardcoded emergency fallback if embedded YAML is broken.
func linuxFallback() *Runbook {
	return &Runbook{
		Name:   "Linux system investigation",
		Type:   "linux",
		Source: "fallback",
		Steps: []Step{
			{Command: "uname -a", Purpose: "identify kernel and system"},
			{Command: "whoami && id", Purpose: "identify current user and groups"},
			{Command: "ps aux --sort=-%cpu | head -20", Purpose: "list top processes by CPU usage"},
			{Command: "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null", Purpose: "list listening ports and services"},
			{Command: "df -h && free -m", Purpose: "check disk and memory usage"},
		},
	}
}
