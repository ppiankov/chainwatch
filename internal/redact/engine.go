package redact

import "strings"

// Redact scans text for sensitive patterns, allocates tokens in tm, and
// returns the text with all sensitive values replaced by tokens.
// Replacements are greedy: longer matches are replaced first so that
// "/var/www/site/wp-config.php" is replaced before "/var/www/site".
func Redact(text string, tm *TokenMap) string {
	matches := Scan(text)
	if len(matches) == 0 {
		return text
	}

	// Allocate tokens for every match.
	for _, m := range matches {
		tm.Token(m.Type, m.Value)
	}

	// Replace longest values first to avoid partial substitution.
	result := text
	for _, val := range tm.Values() {
		tok := tm.forward[val]
		result = strings.ReplaceAll(result, val, tok)
	}

	return result
}

// RedactWithConfig is like Redact but uses custom patterns and safe lists.
// If cfg is nil and extra is nil, behaves identically to Redact.
func RedactWithConfig(text string, tm *TokenMap, cfg *RedactConfig, extra []ExtraPattern) string {
	matches := ScanWithConfig(text, cfg, extra)
	if len(matches) == 0 {
		return text
	}

	for _, m := range matches {
		tm.Token(m.Type, m.Value)
	}

	result := text
	for _, val := range tm.Values() {
		tok := tm.forward[val]
		result = strings.ReplaceAll(result, val, tok)
	}

	return result
}

// Detoken replaces all tokens in text with their original values.
func Detoken(text string, tm *TokenMap) string {
	result := text
	for _, tok := range tm.Tokens() {
		val, _ := tm.Resolve(tok)
		result = strings.ReplaceAll(result, tok, val)
	}
	return result
}

// CheckLeaks scans an LLM response for literal sensitive values that should
// have been redacted. Returns the list of leaked values. An empty slice means
// no leaks detected. This implements R2 from RES-03: post-validation with
// hard reject on leaks.
func CheckLeaks(response string, tm *TokenMap) []string {
	var leaks []string
	for _, val := range tm.Values() {
		if strings.Contains(response, val) {
			leaks = append(leaks, val)
		}
	}
	return leaks
}
