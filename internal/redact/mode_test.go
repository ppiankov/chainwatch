package redact

import "testing"

func TestDetectModeLocal(t *testing.T) {
	cases := []string{
		"http://localhost:11434/v1/chat/completions",
		"http://127.0.0.1:11434/v1/chat/completions",
		"http://LOCALHOST:8080/api",
	}
	for _, url := range cases {
		if m := DetectMode(url); m != ModeLocal {
			t.Errorf("DetectMode(%q) = %s, want local", url, m)
		}
	}
}

func TestDetectModeCloud(t *testing.T) {
	cases := []string{
		"https://api.groq.com/openai/v1/chat/completions",
		"https://api.openai.com/v1/chat/completions",
		"http://10.0.0.5:8080/v1/chat/completions",
		"https://custom-llm.company.com/api",
	}
	for _, url := range cases {
		if m := DetectMode(url); m != ModeCloud {
			t.Errorf("DetectMode(%q) = %s, want cloud", url, m)
		}
	}
}

func TestResolveModeOverride(t *testing.T) {
	// "always" forces cloud even for localhost.
	if m := ResolveMode("http://localhost:11434/api", "always"); m != ModeCloud {
		t.Errorf("override always: got %s, want cloud", m)
	}

	// "never" forces local even for cloud URL.
	if m := ResolveMode("https://api.groq.com/api", "never"); m != ModeLocal {
		t.Errorf("override never: got %s, want local", m)
	}

	// Empty override falls through to auto-detect.
	if m := ResolveMode("https://api.groq.com/api", ""); m != ModeCloud {
		t.Errorf("empty override should auto-detect cloud: got %s", m)
	}
	if m := ResolveMode("http://localhost:11434/api", ""); m != ModeLocal {
		t.Errorf("empty override should auto-detect local: got %s", m)
	}
}

func TestResolveModeWhitespace(t *testing.T) {
	// Handles whitespace in env var value.
	if m := ResolveMode("http://localhost:11434/api", "  ALWAYS  "); m != ModeCloud {
		t.Errorf("whitespace override: got %s, want cloud", m)
	}
}
