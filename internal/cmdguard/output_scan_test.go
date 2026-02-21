package cmdguard

import (
	"strings"
	"testing"
)

func TestScanOutputGroqKey(t *testing.T) {
	input := "GROQ_API_KEY=gsk_abc123def456ghi789jkl012mno"
	result, count := ScanOutput(input)
	if count == 0 {
		t.Error("expected secret detection for Groq key pattern")
	}
	if strings.Contains(result, "gsk_abc123") {
		t.Errorf("expected gsk_ key to be redacted, got %q", result)
	}
}

func TestScanOutputOpenAIKey(t *testing.T) {
	input := "key is sk-proj1234567890abcdefghijklm"
	result, count := ScanOutput(input)
	if count == 0 {
		t.Error("expected secret detection for OpenAI key pattern")
	}
	if strings.Contains(result, "sk-proj") {
		t.Errorf("expected sk- key to be redacted, got %q", result)
	}
}

func TestScanOutputBearerToken(t *testing.T) {
	input := "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
	result, count := ScanOutput(input)
	if count == 0 {
		t.Error("expected secret detection for bearer token")
	}
	if strings.Contains(result, "eyJhbG") {
		t.Errorf("expected bearer token to be redacted, got %q", result)
	}
}

func TestScanOutputCleanText(t *testing.T) {
	input := "total 42\ndrwxr-xr-x 2 root root 4096 Jan 1 00:00 reports\n"
	result, count := ScanOutput(input)
	if count != 0 {
		t.Errorf("expected no secrets in clean text, got %d", count)
	}
	if result != input {
		t.Errorf("expected unchanged output, got %q", result)
	}
}

func TestScanOutputFullEnvKeyValue(t *testing.T) {
	input := "SHELL=/bin/bash\nNULLBOT_API_KEY=secret123\nHOME=/root\nGROQ_API_KEY=gsk_abc\n"
	result, count := ScanOutputFull(input)
	if count == 0 {
		t.Error("expected env key=value detection")
	}
	if strings.Contains(result, "NULLBOT_API_KEY") {
		t.Errorf("expected NULLBOT_API_KEY line redacted, got %q", result)
	}
	if strings.Contains(result, "GROQ_API_KEY") {
		t.Errorf("expected GROQ_API_KEY line redacted, got %q", result)
	}
	if !strings.Contains(result, "SHELL=/bin/bash") {
		t.Error("expected SHELL line to remain")
	}
}

func TestScanOutputFullDeclareExport(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"declare", `declare -x NULLBOT_API_KEY="secret"`},
		{"export", `export GROQ_API_KEY=gsk_test`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, count := ScanOutputFull(tt.input)
			if count == 0 {
				t.Errorf("expected detection for %q", tt.input)
			}
			if result == tt.input {
				t.Errorf("expected redaction, got unchanged: %q", result)
			}
		})
	}
}

func TestSanitizeEnvStripsKeys(t *testing.T) {
	env := []string{
		"HOME=/root",
		"NULLBOT_API_KEY=secret123",
		"GROQ_API_KEY=gsk_abc",
		"OPENAI_API_KEY=sk-abc",
		"ANTHROPIC_API_KEY=sk-ant-abc",
		"API_KEY=generic",
		"API_SECRET=generic_secret",
		"CHAINWATCH_CONFIG=/etc/chainwatch",
		"PATH=/usr/bin",
		"SHELL=/bin/bash",
	}

	clean := sanitizeEnv(env)

	allowed := map[string]bool{
		"HOME":  true,
		"PATH":  true,
		"SHELL": true,
	}

	for _, entry := range clean {
		parts := strings.SplitN(entry, "=", 2)
		name := parts[0]
		if !allowed[name] {
			t.Errorf("expected %q to be stripped from env", name)
		}
	}

	if len(clean) != 3 {
		t.Errorf("expected 3 clean env vars, got %d: %v", len(clean), clean)
	}
}

func TestSanitizeEnvPreservesSafe(t *testing.T) {
	env := []string{
		"HOME=/root",
		"PATH=/usr/bin",
		"LANG=en_US.UTF-8",
		"TERM=xterm",
	}

	clean := sanitizeEnv(env)
	if len(clean) != len(env) {
		t.Errorf("expected all safe vars preserved, got %d/%d", len(clean), len(env))
	}
}
