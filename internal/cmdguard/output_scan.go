package cmdguard

import (
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

// EnvKeyValuePattern matches KEY=VALUE lines where KEY is a known
// sensitive env var name. This catches output from `set`, `export -p`,
// `declare -p`, and similar shell builtins.
var envKeyValuePattern = regexp.MustCompile(
	`(?im)^(?:declare -x |export )?` +
		`(NULLBOT_\w*|GROQ_\w*|OPENAI_\w*|ANTHROPIC_\w*|AWS_\w*|GITHUB_TOKEN\w*|GH_TOKEN\w*|SLACK_TOKEN\w*|SLACK_BOT\w*|DATABASE_URL\w*|REDIS_URL\w*|API_KEY|API_SECRET|CHAINWATCH_\w*)` +
		`[= ].*$`,
)

// ScanOutputFull runs both secret pattern scanning and env key=value scanning.
func ScanOutputFull(output string) (string, int) {
	result, count := ScanOutput(output)

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
