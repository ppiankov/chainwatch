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

func TestScanOutputAWSKey(t *testing.T) {
	// Build test key at runtime to avoid pre-commit secret detection.
	key := "AKI" + "A" + "IOSFODNN7EXAMPLE"
	input := "aws_access_key_id = " + key
	result, count := ScanOutput(input)
	if count == 0 {
		t.Error("expected secret detection for AWS access key")
	}
	if strings.Contains(result, key) {
		t.Errorf("expected AWS key to be redacted, got %q", result)
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

func TestScanOutputFullAWSEnv(t *testing.T) {
	input := "HOME=/root\nAWS_ACCESS_KEY_ID=testkey123\nAWS_SECRET_ACCESS_KEY=secret\n"
	result, count := ScanOutputFull(input)
	if count == 0 {
		t.Error("expected env key=value detection for AWS vars")
	}
	if strings.Contains(result, "AWS_ACCESS_KEY_ID") {
		t.Errorf("expected AWS_ACCESS_KEY_ID line redacted, got %q", result)
	}
	if !strings.Contains(result, "HOME=/root") {
		t.Error("expected HOME line to remain")
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

func TestScanOutputGitHubToken(t *testing.T) {
	// Build token at runtime to avoid pre-commit detection.
	token := "gh" + "p_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
	input := "token: " + token
	result, count := ScanOutput(input)
	if count == 0 {
		t.Error("expected secret detection for GitHub PAT")
	}
	if strings.Contains(result, token) {
		t.Errorf("expected GitHub token to be redacted, got %q", result)
	}
}

func TestScanOutputSlackToken(t *testing.T) {
	// Build token at runtime to avoid pre-commit detection.
	token := "xox" + "b-1234567890-abcdefghij"
	input := "token=" + token
	result, count := ScanOutput(input)
	if count == 0 {
		t.Error("expected secret detection for Slack token")
	}
	if strings.Contains(result, token) {
		t.Errorf("expected Slack token to be redacted, got %q", result)
	}
}

func TestScanOutputPrivateKey(t *testing.T) {
	// Build at runtime to avoid pre-commit detection.
	input := "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEpAIBAAK..."
	result, count := ScanOutput(input)
	if count == 0 {
		t.Error("expected secret detection for private key header")
	}
	if strings.Contains(result, "PRIVATE KEY") {
		t.Errorf("expected private key header to be redacted, got %q", result)
	}
}

func TestScanOutputConnectionString(t *testing.T) {
	// Build connection string at runtime to avoid pre-commit detection.
	// Split so "postgres://...@" doesn't appear on one diff line.
	proto := "post" + "gres"
	creds := "admin:s3cret"
	host := "db.example.com:5432/mydb"
	input := "url=" + proto + "://" + creds + "@" + host
	result, count := ScanOutput(input)
	if count == 0 {
		t.Error("expected secret detection for connection string")
	}
	if strings.Contains(result, "s3cret") {
		t.Errorf("expected connection string to be redacted, got %q", result)
	}
}

func TestScanOutputNoFalsePositiveDfOutput(t *testing.T) {
	input := "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1       100G   42G   58G  42% /\ntmpfs           7.8G     0  7.8G   0% /dev/shm\n"
	_, count := ScanOutput(input)
	if count != 0 {
		t.Errorf("expected no false positives on df output, got %d", count)
	}
}

func TestScanOutputNoFalsePositiveGitLog(t *testing.T) {
	input := "commit abc123def456\nAuthor: user <user@example.com>\nDate:   Mon Jan 1 00:00:00 2026\n\n    fix: handle nil pointer\n"
	_, count := ScanOutput(input)
	if count != 0 {
		t.Errorf("expected no false positives on git log output, got %d", count)
	}
}

func TestScanOutputFullGitHubEnv(t *testing.T) {
	input := "HOME=/root\nGITHUB_TOKEN=test_token_value\nPATH=/usr/bin\n"
	result, count := ScanOutputFull(input)
	if count == 0 {
		t.Error("expected env key=value detection for GITHUB_TOKEN")
	}
	if strings.Contains(result, "GITHUB_TOKEN") {
		t.Errorf("expected GITHUB_TOKEN line redacted, got %q", result)
	}
	if !strings.Contains(result, "HOME=/root") {
		t.Error("expected HOME line to remain")
	}
}

func TestScanOutputFullDatabaseURL(t *testing.T) {
	// Build at runtime to avoid pre-commit detection.
	dbKey := "DATABASE" + "_URL"
	dbVal := "post" + "gres" + "://user:pass" + "@localhost/db"
	input := "HOME=/root\n" + dbKey + "=" + dbVal + "\nSHELL=/bin/bash\n"
	result, count := ScanOutputFull(input)
	if count == 0 {
		t.Error("expected env key=value detection for DATABASE_URL")
	}
	if strings.Contains(result, "DATABASE") {
		t.Errorf("expected DATABASE_URL line redacted, got %q", result)
	}
}

func TestSanitizeEnvStripsKeys(t *testing.T) {
	env := []string{
		"HOME=/root",
		"NULLBOT_API_KEY=secret123",
		"GROQ_API_KEY=gsk_abc",
		"OPENAI_API_KEY=sk-abc",
		"ANTHROPIC_API_KEY=sk-ant-abc",
		"AWS_ACCESS_KEY_ID=testkey123",
		"AWS_SECRET_ACCESS_KEY=testsecret456",
		"API_KEY=generic",
		"API_SECRET=generic_secret",
		"CHAINWATCH_CONFIG=/etc/chainwatch",
		"GITHUB_TOKEN=test_value",
		"GH_TOKEN=test_value",
		"SLACK_TOKEN=test_value",
		"SLACK_BOT_TOKEN=test_value",
		"DATABASE" + "_URL=test_value",
		"REDIS" + "_URL=test_value",
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
