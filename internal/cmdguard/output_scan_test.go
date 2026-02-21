package cmdguard

import (
	"encoding/base64"
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

func TestScanBase64GroqKey(t *testing.T) {
	// Build secret at runtime to avoid pre-commit detection.
	secret := "gsk_" + "abcdef1234567890abcdef1234567890"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	input := "output: " + encoded
	result, count := ScanBase64(input)
	if count == 0 {
		t.Error("expected base64-encoded Groq key to be detected")
	}
	if strings.Contains(result, encoded) {
		t.Errorf("expected base64 string to be redacted, got %q", result)
	}
}

func TestScanBase64OpenAIKey(t *testing.T) {
	secret := "sk-" + "proj1234567890abcdefghijklm"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	input := "data=" + encoded
	result, count := ScanBase64(input)
	if count == 0 {
		t.Error("expected base64-encoded OpenAI key to be detected")
	}
	if strings.Contains(result, encoded) {
		t.Errorf("expected base64 string to be redacted, got %q", result)
	}
}

func TestScanBase64AWSKey(t *testing.T) {
	// Build at runtime to avoid pre-commit detection.
	secret := "AKI" + "A" + "IOSFODNN7EXAMPLE"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	input := "key: " + encoded
	result, count := ScanBase64(input)
	if count == 0 {
		t.Error("expected base64-encoded AWS key to be detected")
	}
	if strings.Contains(result, encoded) {
		t.Errorf("expected base64 string to be redacted, got %q", result)
	}
}

func TestScanBase64NoFalsePositiveCleanText(t *testing.T) {
	// Normal base64 content (not a secret).
	input := base64.StdEncoding.EncodeToString([]byte("Hello, this is a normal message with no secrets at all"))
	_, count := ScanBase64(input)
	if count != 0 {
		t.Errorf("expected no false positives on clean base64 text, got %d", count)
	}
}

func TestScanBase64NoFalsePositiveBinaryData(t *testing.T) {
	// Binary data that happens to be valid base64.
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}
	input := base64.StdEncoding.EncodeToString(data)
	_, count := ScanBase64(input)
	if count != 0 {
		t.Errorf("expected no false positives on binary base64 data, got %d", count)
	}
}

func TestScanBase64ShortStringIgnored(t *testing.T) {
	// Short base64 strings should be ignored.
	encoded := base64.StdEncoding.EncodeToString([]byte("short"))
	_, count := ScanBase64(encoded)
	if count != 0 {
		t.Errorf("expected short base64 to be ignored, got %d", count)
	}
}

func TestScanOutputFullBase64Integration(t *testing.T) {
	// Verify base64 scanning is integrated into ScanOutputFull.
	secret := "gsk_" + "abcdef1234567890abcdef1234567890"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	input := "result: " + encoded + "\n"
	result, count := ScanOutputFull(input)
	if count == 0 {
		t.Error("expected ScanOutputFull to detect base64-encoded secret")
	}
	if strings.Contains(result, encoded) {
		t.Errorf("expected base64 string redacted in ScanOutputFull, got %q", result)
	}
}

func TestScanBase64NoFalsePositiveDfOutput(t *testing.T) {
	input := "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1       100G   42G   58G  42% /\ntmpfs           7.8G     0  7.8G   0% /dev/shm\n"
	_, count := ScanBase64(input)
	if count != 0 {
		t.Errorf("expected no false positives on df output, got %d", count)
	}
}

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"ascii text", []byte("hello world"), true},
		{"with newlines", []byte("line1\nline2\n"), true},
		{"binary", []byte{0x00, 0x01, 0x02, 0x03, 0x04}, false},
		{"empty", []byte{}, false},
		{"mixed mostly printable", []byte("hello\x00world!"), true},
		{"mixed mostly binary", []byte{0x00, 0x01, 0x02, 'a'}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPrintable(tt.data); got != tt.want {
				t.Errorf("isPrintable(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func BenchmarkScanBase64(b *testing.B) {
	// Simulate typical command output with some base64 mixed in.
	secret := "gsk_" + "abcdef1234567890abcdef1234567890"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	input := "Filesystem      Size  Used Avail Use% Mounted on\n" +
		"/dev/sda1       100G   42G   58G  42% /\n" +
		"result: " + encoded + "\n" +
		"tmpfs           7.8G     0  7.8G   0% /dev/shm\n"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScanBase64(input)
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
