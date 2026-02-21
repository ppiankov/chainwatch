package redact

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// RedactConfig holds operator-defined redaction customizations.
type RedactConfig struct {
	ExtraPatterns []ExtraPatternDef `yaml:"extra_patterns"`
	SafeHosts     []string          `yaml:"safe_hosts"`
	SafeIPs       []string          `yaml:"safe_ips"`
	SafePaths     []string          `yaml:"safe_paths"`
	Literals      []string          `yaml:"literals"`
}

// ExtraPatternDef defines a custom pattern from config.
type ExtraPatternDef struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

// ExtraPattern is a compiled custom pattern ready for scanning.
type ExtraPattern struct {
	Name        string
	Regex       *regexp.Regexp
	TokenPrefix PatternType
}

// LoadConfig loads redaction config from the given path.
// If path is empty, tries NULLBOT_REDACT_CONFIG env var,
// then ~/.chainwatch/redact.yaml. Returns nil config (not error)
// if no file exists.
func LoadConfig(path string) (*RedactConfig, error) {
	if path == "" {
		path = os.Getenv("NULLBOT_REDACT_CONFIG")
	}
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, nil
		}
		path = filepath.Join(home, ".chainwatch", "redact.yaml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read redact config: %w", err)
	}

	var cfg RedactConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse redact config: %w", err)
	}

	return &cfg, nil
}

// CompilePatterns validates and compiles extra patterns from config.
func CompilePatterns(cfg *RedactConfig) ([]ExtraPattern, error) {
	if cfg == nil {
		return nil, nil
	}

	var patterns []ExtraPattern
	for i, def := range cfg.ExtraPatterns {
		if def.Name == "" {
			return nil, fmt.Errorf("extra_patterns[%d]: name is required", i)
		}
		if def.Regex == "" {
			return nil, fmt.Errorf("extra_patterns[%d]: regex is required", i)
		}
		re, err := regexp.Compile(def.Regex)
		if err != nil {
			return nil, fmt.Errorf("extra_patterns[%d] %q: invalid regex: %w", i, def.Name, err)
		}
		patterns = append(patterns, ExtraPattern{
			Name:        def.Name,
			Regex:       re,
			TokenPrefix: PatternType(strings.ToUpper(def.Name)),
		})
	}
	return patterns, nil
}
