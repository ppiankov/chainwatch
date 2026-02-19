package redact

import (
	"strings"
	"testing"
)

func TestRedactAndDetoken(t *testing.T) {
	original := `Server 192.168.1.42 has compromised file at /var/www/site/wp-config.php.
Contact admin@company.com for details. Check /etc/nginx/nginx.conf too.`

	tm := NewTokenMap("test-roundtrip")
	redacted := Redact(original, tm)

	// Verify sensitive data is gone.
	if strings.Contains(redacted, "192.168.1.42") {
		t.Error("IP not redacted")
	}
	if strings.Contains(redacted, "/var/www/site/wp-config.php") {
		t.Error("path not redacted")
	}
	if strings.Contains(redacted, "admin@company.com") {
		t.Error("email not redacted")
	}

	// Verify tokens are present.
	if !strings.Contains(redacted, "<<IP_") {
		t.Error("no IP token in redacted text")
	}
	if !strings.Contains(redacted, "<<PATH_") {
		t.Error("no PATH token in redacted text")
	}

	// Round-trip: detoken should restore original.
	restored := Detoken(redacted, tm)
	if restored != original {
		t.Errorf("round-trip failed:\n  original: %s\n  restored: %s", original, restored)
	}
}

func TestRedactGreedyOrder(t *testing.T) {
	// The longer path should be replaced first to avoid partial substitution.
	text := "Check /var/www/site/wp-config.php and /var/www/site"

	tm := NewTokenMap("test-greedy")
	redacted := Redact(text, tm)

	// Both should be tokenized. The longer path should not be partially replaced.
	if strings.Contains(redacted, "/var/www") {
		t.Errorf("greedy replacement failed, /var/www still present: %s", redacted)
	}

	// The tokens should be distinct.
	pathTokens := 0
	for _, tok := range tm.Tokens() {
		if strings.HasPrefix(tok, "<<PATH_") {
			pathTokens++
		}
	}
	if pathTokens != 2 {
		t.Errorf("expected 2 path tokens, got %d", pathTokens)
	}
}

func TestRedactNoSensitiveData(t *testing.T) {
	text := "This text has no sensitive data at all."
	tm := NewTokenMap("test-clean")
	redacted := Redact(text, tm)

	if redacted != text {
		t.Errorf("clean text should be unchanged: %s", redacted)
	}
	if tm.Len() != 0 {
		t.Errorf("no tokens should be allocated for clean text, got %d", tm.Len())
	}
}

func TestRedactIdempotentTokens(t *testing.T) {
	text := "/var/www/site appears twice: /var/www/site"
	tm := NewTokenMap("test-idem")
	redacted := Redact(text, tm)

	// Same path should map to same token.
	if tm.Len() != 1 {
		t.Errorf("expected 1 token for duplicate paths, got %d", tm.Len())
	}

	// The redacted text should have the same token twice.
	count := strings.Count(redacted, "<<PATH_1>>")
	if count != 2 {
		t.Errorf("expected <<PATH_1>> twice, got %d occurrences", count)
	}
}

func TestDetokenEmpty(t *testing.T) {
	tm := NewTokenMap("test-empty")
	result := Detoken("no tokens here", tm)
	if result != "no tokens here" {
		t.Error("detoken with empty map should return original")
	}
}

func TestCheckLeaksDetectsLeak(t *testing.T) {
	tm := NewTokenMap("test-leak")
	tm.Token(PatternPath, "/var/www/site")
	tm.Token(PatternIP, "192.168.1.42")

	// LLM response that contains a literal sensitive value — this is a leak.
	response := `Remove the file at /var/www/site/exploit.php and block <<IP_1>>`

	leaks := CheckLeaks(response, tm)
	if len(leaks) != 1 {
		t.Fatalf("expected 1 leak, got %d: %v", len(leaks), leaks)
	}
	if leaks[0] != "/var/www/site" {
		t.Errorf("unexpected leaked value: %s", leaks[0])
	}
}

func TestCheckLeaksNoLeaks(t *testing.T) {
	tm := NewTokenMap("test-noleak")
	tm.Token(PatternPath, "/var/www/site")
	tm.Token(PatternIP, "192.168.1.42")

	// Clean response using only tokens.
	response := `rm <<PATH_1>>/exploit.php && iptables -A INPUT -s <<IP_1>> -j DROP`

	leaks := CheckLeaks(response, tm)
	if len(leaks) != 0 {
		t.Errorf("expected 0 leaks, got %d: %v", len(leaks), leaks)
	}
}

func TestCheckLeaksEmptyMap(t *testing.T) {
	tm := NewTokenMap("test-empty-leak")
	leaks := CheckLeaks("any response text", tm)
	if len(leaks) != 0 {
		t.Errorf("expected 0 leaks with empty map, got %d", len(leaks))
	}
}

func TestRedactComplexScenario(t *testing.T) {
	// A realistic WordPress investigation output.
	text := `$ find /var/www/site/wp-content -name "*.php" -newer /var/www/site/wp-includes/version.php
/var/www/site/wp-content/plugins/akismet/x.php

$ grep -r "eval(base64_decode" /var/www/site/wp-content/
/var/www/site/wp-content/plugins/akismet/x.php:<?php eval(base64_decode("aWYoaXNzZXQoJF9..."));

$ curl -sL -D - http://prod-web-03.internal.company.com -o /dev/null
HTTP/1.1 302 Found
Location: https://casino-redirect.evil.com/promo

wpadmin2:x:0:0::/root:/bin/bash
Contact: webmaster@company.com
Server IP: 10.99.88.77`

	tm := NewTokenMap("test-complex")
	redacted := Redact(text, tm)

	// Verify no sensitive data remains.
	sensitiveValues := []string{
		"/var/www/site",
		"10.99.88.77",
		"webmaster@company.com",
		"wpadmin2",
	}
	for _, sv := range sensitiveValues {
		if strings.Contains(redacted, sv) {
			t.Errorf("sensitive value not redacted: %s", sv)
		}
	}

	// Round-trip.
	restored := Detoken(redacted, tm)
	if restored != text {
		t.Error("complex scenario round-trip failed")
	}
}
