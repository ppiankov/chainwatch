package cmdguard

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// secretPatterns match known API key and token formats in command output.
// These detect actual credential values, not variable names.
var secretPatterns = []*regexp.Regexp{
	// Groq keys: gsk_...
	regexp.MustCompile(`gsk_[a-zA-Z0-9]{20,}`),
	// OpenAI keys: sk-...
	regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
	// Anthropic keys: sk-ant-...
	regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-]{20,}`),
	// Generic long hex tokens (64+ chars) that look like API keys
	regexp.MustCompile(`\b[a-f0-9]{64,}\b`),
	// AWS access key IDs: AKIA...
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	// Bearer tokens
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-_.]{20,}`),
	// GitHub tokens: ghp_ (PAT), gho_ (OAuth), ghs_ (server), ghr_ (refresh)
	regexp.MustCompile(`(?:ghp|gho|ghs|ghr)_[a-zA-Z0-9]{36,}`),
	// Slack tokens: xoxb-, xoxp-, xoxa-, xoxr-, xoxs-
	regexp.MustCompile(`xox[bpars]-[a-zA-Z0-9\-]{10,}`),
	// Private key headers (PEM format)
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	// TLS certificate and CSR headers (PEM format)
	regexp.MustCompile(`-----BEGIN CERTIFICATE(?:\s+REQUEST)?-----`),
	// Connection strings with credentials
	regexp.MustCompile(`(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^\s:]+:[^\s@]+@[^\s]+`),
}

// redactPlaceholder replaces matched secrets in output.
const redactPlaceholder = "[REDACTED]"

// ScanOutput checks command output for leaked secrets and returns a
// redacted copy. The second return value is the number of secrets found.
func ScanOutput(output string) (string, int) {
	count := 0
	result := output
	for _, re := range secretPatterns {
		matches := re.FindAllString(result, -1)
		if len(matches) > 0 {
			count += len(matches)
			result = re.ReplaceAllString(result, redactPlaceholder)
		}
	}
	return result, count
}

// base64Pattern matches candidate base64-encoded strings.
// Minimum 16 chars to avoid false positives on short strings.
// Requires valid base64 charset and proper padding.
var base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)

// minDecodedLen is the minimum decoded length to consider for secret scanning.
// Secrets under 8 bytes are unlikely to be real credentials.
const minDecodedLen = 8

// ScanBase64 finds candidate base64 strings, decodes them, and checks
// the decoded content against secret patterns. Returns the output with
// any base64-encoded secrets redacted and the count of secrets found.
func ScanBase64(output string) (string, int) {
	count := 0
	result := base64Pattern.ReplaceAllStringFunc(output, func(match string) string {
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err != nil {
			// Try RawStdEncoding (no padding).
			decoded, err = base64.RawStdEncoding.DecodeString(match)
			if err != nil {
				return match
			}
		}

		if len(decoded) < minDecodedLen {
			return match
		}

		// Check if decoded content is mostly printable text.
		// Binary data (images, compressed) should not be scanned.
		if !isPrintable(decoded) {
			return match
		}

		decodedStr := string(decoded)
		for _, re := range secretPatterns {
			if re.MatchString(decodedStr) {
				count++
				return redactPlaceholder
			}
		}
		return match
	})
	return result, count
}

// isPrintable returns true if at least 80% of bytes are printable ASCII
// or common whitespace. This filters out binary data that happens to be
// valid base64.
func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if (b >= 0x20 && b <= 0x7E) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) >= 0.8
}

// EnvKeyValuePattern matches KEY=VALUE lines where KEY is a known
// sensitive env var name. This catches output from `set`, `export -p`,
// `declare -p`, and similar shell builtins.
var envKeyValuePattern = regexp.MustCompile(
	`(?im)^(?:declare -x |export )?` +
		`(NULLBOT_\w*|GROQ_\w*|OPENAI_\w*|ANTHROPIC_\w*|AWS_\w*|GITHUB_TOKEN\w*|GH_TOKEN\w*|SLACK_TOKEN\w*|SLACK_BOT\w*|DATABASE_URL\w*|REDIS_URL\w*|API_KEY|API_SECRET|CHAINWATCH_\w*)` +
		`[= ].*$`,
)

// pemBlockPattern matches complete PEM-encoded blocks (certificates, private
// keys, CSRs). This catches the entire block including the base64 body, not
// just the header line. Prevents TLS certs and keys from leaking to the LLM.
var pemBlockPattern = regexp.MustCompile(
	`(?s)-----BEGIN [A-Z][A-Z0-9 ]*-----\n[A-Za-z0-9+/=\n]+-----END [A-Z][A-Z0-9 ]*-----`,
)

// ScanOutputFull runs PEM block, secret pattern, base64, and env key=value scanning.
// PEM blocks are scanned first so full cert/key blocks are redacted before
// line-level patterns consume only the header line.
func ScanOutputFull(output string) (string, int) {
	count := 0

	// Redact full PEM blocks (certs, keys, CSRs) before line-level scanning.
	result := output
	pemMatches := pemBlockPattern.FindAllString(result, -1)
	if len(pemMatches) > 0 {
		count += len(pemMatches)
		result = pemBlockPattern.ReplaceAllString(result, redactPlaceholder)
	}

	// Line-level secret patterns.
	r, n := ScanOutput(result)
	result = r
	count += n

	// Scan for base64-encoded secrets.
	r, n = ScanBase64(result)
	result = r
	count += n

	// Also redact env var lines with sensitive names
	envMatches := envKeyValuePattern.FindAllString(result, -1)
	if len(envMatches) > 0 {
		count += len(envMatches)
		result = envKeyValuePattern.ReplaceAllString(result, redactPlaceholder)
	}

	// Collapse consecutive redacted lines
	for strings.Contains(result, redactPlaceholder+"\n"+redactPlaceholder) {
		result = strings.ReplaceAll(result, redactPlaceholder+"\n"+redactPlaceholder, redactPlaceholder)
	}

	return result, count
}
