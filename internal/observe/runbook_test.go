package observe

import (
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

func TestGetRunbookUnknownFallsToLinux(t *testing.T) {
	rb := GetRunbook("nginx")
	if rb.Type != "linux" {
		t.Errorf("unknown type should fall back to linux, got %q", rb.Type)
	}
}

func TestWordPressRunbookContainsScopePlaceholder(t *testing.T) {
	rb := WordPressRunbook()
	hasScopePlaceholder := false
	for _, step := range rb.Steps {
		if strings.Contains(step.Command, "{{SCOPE}}") {
			hasScopePlaceholder = true
			break
		}
	}
	if !hasScopePlaceholder {
		t.Error("WordPress runbook should contain {{SCOPE}} placeholder")
	}
}

func TestWordPressRunbookNoDestructiveCommands(t *testing.T) {
	rb := WordPressRunbook()
	for _, step := range rb.Steps {
		assertNoDestructivePrimary(t, rb.Name, step)
	}
}

func TestLinuxRunbookNoDestructiveCommands(t *testing.T) {
	rb := LinuxRunbook()
	for _, step := range rb.Steps {
		assertNoDestructivePrimary(t, rb.Name, step)
	}
}

// assertNoDestructivePrimary checks that the primary command (before any
// pipe or fallback) is not a destructive write operation. Fallback echo
// messages (|| echo '...') and read-only flags (-perm) are allowed.
func assertNoDestructivePrimary(t *testing.T, rbName string, step Step) {
	t.Helper()
	// Extract the primary command (before || or | or ;).
	primary := step.Command
	for _, sep := range []string{"||", "|", ";"} {
		if idx := strings.Index(primary, sep); idx >= 0 {
			primary = primary[:idx]
		}
	}
	primary = strings.TrimSpace(primary)

	destructive := []string{"rm ", "mv ", "cp ", "chmod ", "chown ", "tee ", "sed -i", "kill ", "pkill "}
	for _, d := range destructive {
		if strings.HasPrefix(primary, d) {
			t.Errorf("%s step %q: primary command starts with destructive %q", rbName, step.Purpose, d)
		}
	}
}

func TestRunbookStepsHavePurpose(t *testing.T) {
	for _, rb := range []*Runbook{WordPressRunbook(), LinuxRunbook()} {
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
