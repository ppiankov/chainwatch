package denylist

import (
	"embed"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed presets/*.yaml
var presetsFS embed.FS

// builtinPresets maps preset names to their embedded YAML content.
var builtinPresets map[string][]byte

func init() {
	builtinPresets = make(map[string][]byte)
	entries, err := presetsFS.ReadDir("presets")
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ext)
		data, err := presetsFS.ReadFile("presets/" + e.Name())
		if err != nil {
			continue
		}
		builtinPresets[name] = data
	}
}

// LoadPreset loads a preset by name and returns its patterns.
func LoadPreset(name string) (Patterns, error) {
	data, ok := builtinPresets[name]
	if !ok {
		return Patterns{}, fmt.Errorf("unknown preset %q; available: %s", name, strings.Join(ListPresets(), ", "))
	}

	var p Patterns
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Patterns{}, fmt.Errorf("parse preset %q: %w", name, err)
	}
	return p, nil
}

// ListPresets returns sorted names of all available presets.
func ListPresets() []string {
	names := make([]string, 0, len(builtinPresets))
	for name := range builtinPresets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Merge combines two Patterns, deduplicating entries.
func Merge(base, overlay Patterns) Patterns {
	return Patterns{
		URLs:     dedup(append(base.URLs, overlay.URLs...)),
		Files:    dedup(append(base.Files, overlay.Files...)),
		Commands: dedup(append(base.Commands, overlay.Commands...)),
	}
}

// dedup removes duplicate strings while preserving order.
func dedup(items []string) []string {
	seen := make(map[string]bool, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
