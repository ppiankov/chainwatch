package redact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigMissing(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/path/redact.yaml")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil config for missing file")
	}
}

func TestLoadConfigValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "redact.yaml")
	content := `
extra_patterns:
  - name: DBNAME
    regex: "\\bdb_[a-z0-9_]+\\b"
  - name: AWSACCT
    regex: "\\b\\d{12}\\b"
safe_hosts:
  - internal.company.com
safe_ips:
  - "10.0.0.1"
safe_paths:
  - /opt/monitoring/
literals:
  - prod-cluster-xyz
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.ExtraPatterns) != 2 {
		t.Errorf("expected 2 extra_patterns, got %d", len(cfg.ExtraPatterns))
	}
	if cfg.ExtraPatterns[0].Name != "DBNAME" {
		t.Errorf("expected DBNAME, got %q", cfg.ExtraPatterns[0].Name)
	}
	if len(cfg.SafeHosts) != 1 || cfg.SafeHosts[0] != "internal.company.com" {
		t.Errorf("safe_hosts: %v", cfg.SafeHosts)
	}
	if len(cfg.SafeIPs) != 1 || cfg.SafeIPs[0] != "10.0.0.1" {
		t.Errorf("safe_ips: %v", cfg.SafeIPs)
	}
	if len(cfg.SafePaths) != 1 || cfg.SafePaths[0] != "/opt/monitoring/" {
		t.Errorf("safe_paths: %v", cfg.SafePaths)
	}
	if len(cfg.Literals) != 1 || cfg.Literals[0] != "prod-cluster-xyz" {
		t.Errorf("literals: %v", cfg.Literals)
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "redact.yaml")
	if err := os.WriteFile(path, []byte("{{invalid yaml"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestCompilePatternsValid(t *testing.T) {
	cfg := &RedactConfig{
		ExtraPatterns: []ExtraPatternDef{
			{Name: "DBNAME", Regex: `\bdb_[a-z0-9_]+\b`},
		},
	}

	patterns, err := CompilePatterns(cfg)
	if err != nil {
		t.Fatalf("CompilePatterns: %v", err)
	}
	if len(patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(patterns))
	}
	if patterns[0].TokenPrefix != "DBNAME" {
		t.Errorf("expected DBNAME prefix, got %q", patterns[0].TokenPrefix)
	}
	if !patterns[0].Regex.MatchString("db_production_main") {
		t.Error("regex should match db_production_main")
	}
}

func TestCompilePatternsInvalidRegex(t *testing.T) {
	cfg := &RedactConfig{
		ExtraPatterns: []ExtraPatternDef{
			{Name: "BAD", Regex: "[invalid"},
		},
	}

	_, err := CompilePatterns(cfg)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestCompilePatternsMissingName(t *testing.T) {
	cfg := &RedactConfig{
		ExtraPatterns: []ExtraPatternDef{
			{Name: "", Regex: `\w+`},
		},
	}

	_, err := CompilePatterns(cfg)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestCompilePatternsNilConfig(t *testing.T) {
	patterns, err := CompilePatterns(nil)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if patterns != nil {
		t.Fatal("expected nil patterns for nil config")
	}
}
