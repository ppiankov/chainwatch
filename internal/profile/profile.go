package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/ppiankov/chainwatch/internal/policy"
)

// AuthorityPattern defines an instruction-level pattern for authority boundary checks.
type AuthorityPattern struct {
	Pattern string `yaml:"pattern"`
	Reason  string `yaml:"reason"`
}

// ExecutionBoundaries holds denylist patterns organized by category.
type ExecutionBoundaries struct {
	URLs     []string `yaml:"urls"`
	Files    []string `yaml:"files"`
	Commands []string `yaml:"commands"`
}

// PolicyOverrides holds policy rules that a profile adds.
type PolicyOverrides struct {
	Rules []policy.Rule `yaml:"rules"`
}

// Profile is a named, reusable bundle of denylist patterns + policy rules.
type Profile struct {
	Name                string              `yaml:"name"`
	Description         string              `yaml:"description"`
	AuthorityBoundaries []AuthorityPattern  `yaml:"authority_boundaries"`
	ExecutionBoundaries ExecutionBoundaries `yaml:"execution_boundaries"`
	Policy              *PolicyOverrides    `yaml:"policy,omitempty"`
}

// Load loads a profile by name. Checks built-in profiles first,
// then falls back to ~/.chainwatch/profiles/<name>.yaml.
func Load(name string) (*Profile, error) {
	// Check built-in profiles
	if data, ok := builtinProfiles[name]; ok {
		var p Profile
		if err := yaml.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("failed to parse built-in profile %q: %w", name, err)
		}
		return &p, nil
	}

	// Check user profiles
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("profile %q not found (no built-in, cannot determine home dir)", name)
	}

	path := filepath.Join(home, ".chainwatch", "profiles", name+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profile %q not found", name)
	}

	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse profile %q: %w", name, err)
	}

	return &p, nil
}

// List returns sorted names of all available profiles (built-in + user).
func List() []string {
	seen := make(map[string]bool)
	for name := range builtinProfiles {
		seen[name] = true
	}

	// Scan user profiles directory
	home, err := os.UserHomeDir()
	if err == nil {
		dir := filepath.Join(home, ".chainwatch", "profiles")
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				name := e.Name()
				if ext := filepath.Ext(name); ext == ".yaml" || ext == ".yml" {
					seen[name[:len(name)-len(ext)]] = true
				}
			}
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Validate checks that a profile is well-formed.
func Validate(p *Profile) error {
	if p.Name == "" {
		return fmt.Errorf("profile name is required")
	}

	for i, ap := range p.AuthorityBoundaries {
		if _, err := regexp.Compile("(?i)" + ap.Pattern); err != nil {
			return fmt.Errorf("authority_boundaries[%d]: invalid regex %q: %w", i, ap.Pattern, err)
		}
	}

	return nil
}
