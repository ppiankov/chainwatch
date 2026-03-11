package observe

import "regexp"

// RedactRule defines a pattern to redact from evidence before LLM classification.
type RedactRule struct {
	Name        string // human-readable rule name
	Pattern     *regexp.Regexp
	Replacement string
}

// DefaultRedactRules returns built-in redaction rules for ClickHouse XML configs.
// Covers credentials, usernames, and hostnames.
func DefaultRedactRules() []RedactRule {
	return []RedactRule{
		// Credentials
		{
			Name:        "password",
			Pattern:     regexp.MustCompile(`<password>([^<]+)</password>`),
			Replacement: "<password>[REDACTED]</password>",
		},
		{
			Name:        "password_sha256_hex",
			Pattern:     regexp.MustCompile(`<password_sha256_hex>([^<]+)</password_sha256_hex>`),
			Replacement: "<password_sha256_hex>[REDACTED]</password_sha256_hex>",
		},
		{
			Name:        "password_double_sha1_hex",
			Pattern:     regexp.MustCompile(`<password_double_sha1_hex>([^<]+)</password_double_sha1_hex>`),
			Replacement: "<password_double_sha1_hex>[REDACTED]</password_double_sha1_hex>",
		},
		{
			Name:        "access_key_id",
			Pattern:     regexp.MustCompile(`<access_key_id>([^<]+)</access_key_id>`),
			Replacement: "<access_key_id>[REDACTED]</access_key_id>",
		},
		{
			Name:        "secret_access_key",
			Pattern:     regexp.MustCompile(`<secret_access_key>([^<]+)</secret_access_key>`),
			Replacement: "<secret_access_key>[REDACTED]</secret_access_key>",
		},
		// Generic credential tags
		{
			Name:        "generic_secret_tag",
			Pattern:     regexp.MustCompile(`<(secret[^>]*)>([^<]+)</secret[^>]*>`),
			Replacement: "<${1}>[REDACTED]</${1}>",
		},
		{
			Name:        "generic_token_tag",
			Pattern:     regexp.MustCompile(`<(token[^>]*)>([^<]+)</token[^>]*>`),
			Replacement: "<${1}>[REDACTED]</${1}>",
		},
		// Usernames
		{
			Name:        "xml_user_tag",
			Pattern:     regexp.MustCompile(`<user>([^<]+)</user>`),
			Replacement: "<user>[REDACTED_USER]</user>",
		},
		{
			Name:        "quota_key",
			Pattern:     regexp.MustCompile(`<quota_key>([^<]+)</quota_key>`),
			Replacement: "<quota_key>[REDACTED_USER]</quota_key>",
		},
		// Hostnames
		{
			Name:        "host_tag",
			Pattern:     regexp.MustCompile(`<host>([^<]+)</host>`),
			Replacement: "<host>[REDACTED_HOST]</host>",
		},
		{
			Name:        "hostname_tag",
			Pattern:     regexp.MustCompile(`<hostname>([^<]+)</hostname>`),
			Replacement: "<hostname>[REDACTED_HOST]</hostname>",
		},
		{
			Name:        "interserver_http_host",
			Pattern:     regexp.MustCompile(`<interserver_http_host>([^<]+)</interserver_http_host>`),
			Replacement: "<interserver_http_host>[REDACTED_HOST]</interserver_http_host>",
		},
	}
}

// RedactEvidence applies redaction rules to evidence text.
// Returns the redacted text and the number of redactions applied.
func RedactEvidence(evidence string, rules []RedactRule) (string, int) {
	total := 0
	for _, rule := range rules {
		matches := rule.Pattern.FindAllStringIndex(evidence, -1)
		total += len(matches)
		evidence = rule.Pattern.ReplaceAllString(evidence, rule.Replacement)
	}
	return evidence, total
}
