package certify

import (
	_ "embed"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/ppiankov/chainwatch/internal/scenario"
)

//go:embed suites/minimal.yaml
var minimalSuiteYAML []byte

//go:embed suites/enterprise.yaml
var enterpriseSuiteYAML []byte

var builtinSuites = map[string][]byte{
	"minimal":    minimalSuiteYAML,
	"enterprise": enterpriseSuiteYAML,
}

// Suite is a versioned collection of certification categories.
type Suite struct {
	Name       string     `yaml:"name"`
	Version    string     `yaml:"version"`
	Categories []Category `yaml:"categories"`
}

// Category groups related test cases under a named heading.
type Category struct {
	Name  string          `yaml:"name"`
	Cases []scenario.Case `yaml:"cases"`
}

// LoadSuite loads a built-in certification suite by name.
func LoadSuite(name string) (*Suite, error) {
	data, ok := builtinSuites[name]
	if !ok {
		return nil, fmt.Errorf("unknown certification suite: %q", name)
	}

	var s Suite
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse suite %q: %w", name, err)
	}

	return &s, nil
}

// ListSuites returns sorted names of all built-in certification suites.
func ListSuites() []string {
	names := make([]string, 0, len(builtinSuites))
	for name := range builtinSuites {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
