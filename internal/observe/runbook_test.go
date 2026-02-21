package observe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetRunbookWordPress(t *testing.T) {
	for _, name := range []string{"wordpress", "wp"} {
		rb := GetRunbook(name)
		if rb.Type != "wordpress" {
			t.Errorf("GetRunbook(%q) type = %q, want wordpress", name, rb.Type)
		}
		if len(rb.Steps) < 8 {
			t.Errorf("WordPress runbook has %d steps, want at least 8", len(rb.Steps))
		}
	}
}

func TestGetRunbookLinux(t *testing.T) {
	for _, name := range []string{"linux", "system", "generic"} {
		rb := GetRunbook(name)
		if rb.Type != "linux" {
			t.Errorf("GetRunbook(%q) type = %q, want linux", name, rb.Type)
		}
		if len(rb.Steps) < 8 {
			t.Errorf("Linux runbook has %d steps, want at least 8", len(rb.Steps))
		}
	}
}

func TestGetRunbookPostfix(t *testing.T) {
	for _, name := range []string{"postfix", "mail"} {
		rb := GetRunbook(name)
		if rb.Type != "postfix" {
			t.Errorf("GetRunbook(%q) type = %q, want postfix", name, rb.Type)
		}
		if len(rb.Steps) < 8 {
			t.Errorf("Postfix runbook has %d steps, want at least 8", len(rb.Steps))
		}
	}
}

func TestGetRunbookNginx(t *testing.T) {
	for _, name := range []string{"nginx", "web"} {
		rb := GetRunbook(name)
		if rb.Type != "nginx" {
			t.Errorf("GetRunbook(%q) type = %q, want nginx", name, rb.Type)
		}
		if len(rb.Steps) < 8 {
			t.Errorf("Nginx runbook has %d steps, want at least 8", len(rb.Steps))
		}
	}
}

func TestGetRunbookUnknownFallsToLinux(t *testing.T) {
	rb := GetRunbook("unknown-service-xyz")
	if rb.Type != "linux" {
		t.Errorf("unknown type should fall back to linux, got %q", rb.Type)
	}
}

func TestGetRunbookEmptyFallsToLinux(t *testing.T) {
	rb := GetRunbook("")
	if rb.Type != "linux" {
		t.Errorf("empty type should fall back to linux, got %q", rb.Type)
	}
}

func TestBuiltinRunbooksHaveScopePlaceholder(t *testing.T) {
	// All runbooks that investigate a target directory should use {{SCOPE}}.
	for _, name := range []string{"wordpress", "linux", "postfix", "nginx"} {
		rb := GetRunbook(name)
		hasScopePlaceholder := false
		for _, step := range rb.Steps {
			if strings.Contains(step.Command, "{{SCOPE}}") {
				hasScopePlaceholder = true
				break
			}
		}
		if !hasScopePlaceholder {
			t.Errorf("%s runbook should contain {{SCOPE}} placeholder", name)
		}
	}
}

func TestBuiltinRunbooksNoDestructiveCommands(t *testing.T) {
	for _, name := range []string{"wordpress", "linux", "postfix", "nginx"} {
		rb := GetRunbook(name)
		for _, step := range rb.Steps {
			if err := checkDestructive(step); err != nil {
				t.Errorf("%s runbook: %v", name, err)
			}
		}
	}
}

func TestBuiltinRunbooksHavePurpose(t *testing.T) {
	for _, name := range []string{"wordpress", "linux", "postfix", "nginx"} {
		rb := GetRunbook(name)
		for i, step := range rb.Steps {
			if step.Purpose == "" {
				t.Errorf("%s step %d has empty purpose", rb.Name, i)
			}
			if step.Command == "" {
				t.Errorf("%s step %d has empty command", rb.Name, i)
			}
		}
	}
}

func TestBuiltinRunbooksSource(t *testing.T) {
	rb := GetRunbook("linux")
	if rb.Source != "built-in" {
		t.Errorf("built-in runbook source = %q, want built-in", rb.Source)
	}
}

func TestListRunbooks(t *testing.T) {
	list := ListRunbooks()
	if len(list) < 4 {
		t.Errorf("ListRunbooks() returned %d runbooks, want at least 4", len(list))
	}

	types := make(map[string]bool)
	for _, info := range list {
		types[info.Type] = true
		if info.Name == "" {
			t.Errorf("runbook type %q has empty name", info.Type)
		}
		if info.Steps == 0 {
			t.Errorf("runbook type %q has 0 steps", info.Type)
		}
	}

	for _, expected := range []string{"linux", "wordpress", "postfix", "nginx"} {
		if !types[expected] {
			t.Errorf("ListRunbooks() missing type %q", expected)
		}
	}
}

func TestValidateRunbookRejectsEmpty(t *testing.T) {
	tests := []struct {
		name string
		rb   Runbook
	}{
		{"no name", Runbook{Type: "x", Steps: []Step{{Command: "ls", Purpose: "list"}}}},
		{"no type", Runbook{Name: "x", Steps: []Step{{Command: "ls", Purpose: "list"}}}},
		{"no steps", Runbook{Name: "x", Type: "x"}},
		{"empty command", Runbook{Name: "x", Type: "x", Steps: []Step{{Purpose: "list"}}}},
		{"empty purpose", Runbook{Name: "x", Type: "x", Steps: []Step{{Command: "ls"}}}},
	}
	for _, tt := range tests {
		if err := ValidateRunbook(&tt.rb); err == nil {
			t.Errorf("ValidateRunbook(%s) should fail", tt.name)
		}
	}
}

func TestValidateRunbookRejectsDestructive(t *testing.T) {
	rb := Runbook{
		Name: "bad", Type: "bad",
		Steps: []Step{{Command: "rm -rf /tmp/x", Purpose: "destroy"}},
	}
	if err := ValidateRunbook(&rb); err == nil {
		t.Error("expected rejection for destructive command")
	}
}

func TestParseRunbookYAML(t *testing.T) {
	yaml := `
name: "Test runbook"
type: test
aliases: [t, testing]
steps:
  - command: "echo hello"
    purpose: "say hello"
  - command: "ls {{SCOPE}}"
    purpose: "list scope"
`
	rb, err := ParseRunbook([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseRunbook failed: %v", err)
	}
	if rb.Name != "Test runbook" {
		t.Errorf("name = %q, want Test runbook", rb.Name)
	}
	if rb.Type != "test" {
		t.Errorf("type = %q, want test", rb.Type)
	}
	if len(rb.Aliases) != 2 {
		t.Errorf("aliases = %v, want [t testing]", rb.Aliases)
	}
	if len(rb.Steps) != 2 {
		t.Errorf("steps = %d, want 2", len(rb.Steps))
	}
}

func TestParseRunbookYAMLRejectsInvalid(t *testing.T) {
	yaml := `name: ""`
	_, err := ParseRunbook([]byte(yaml))
	if err == nil {
		t.Error("expected error for invalid YAML runbook")
	}
}

func TestUserRunbookOverride(t *testing.T) {
	// Create a temp directory to act as user runbook dir.
	dir := t.TempDir()
	customYAML := `
name: "Custom Linux"
type: linux
steps:
  - command: "echo custom"
    purpose: "custom step"
`
	path := filepath.Join(dir, "linux.yaml")
	if err := os.WriteFile(path, []byte(customYAML), 0600); err != nil {
		t.Fatal(err)
	}

	// Load directly from the temp path (simulates user override).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := ParseRunbook(data)
	if err != nil {
		t.Fatalf("ParseRunbook failed: %v", err)
	}
	if rb.Name != "Custom Linux" {
		t.Errorf("name = %q, want Custom Linux", rb.Name)
	}
	if len(rb.Steps) != 1 {
		t.Errorf("steps = %d, want 1", len(rb.Steps))
	}
}
