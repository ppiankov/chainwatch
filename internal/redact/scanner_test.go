package redact

import (
	"regexp"
	"strings"
	"testing"
)

func TestScanPaths(t *testing.T) {
	text := `Found files:
/var/www/site/wp-config.php
/etc/nginx/nginx.conf
/home/admin/.bashrc
/tmp/exploit.sh
/usr/local/bin/custom
/opt/app/config.yml
/root/.ssh/authorized_keys`

	matches := Scan(text)
	paths := filterByType(matches, PatternPath)

	if len(paths) < 7 {
		t.Errorf("expected at least 7 paths, got %d: %v", len(paths), paths)
	}

	wantPaths := []string{
		"/var/www/site/wp-config.php",
		"/etc/nginx/nginx.conf",
		"/home/admin/.bashrc",
		"/tmp/exploit.sh",
		"/usr/local/bin/custom",
		"/opt/app/config.yml",
		"/root/.ssh/authorized_keys",
	}
	for _, w := range wantPaths {
		if !containsValue(paths, w) {
			t.Errorf("missing path: %s", w)
		}
	}
}

func TestScanIPv4(t *testing.T) {
	text := "Server at 192.168.1.42 connects to 10.0.0.1 via 127.0.0.1"
	matches := Scan(text)
	ips := filterByType(matches, PatternIP)

	// 127.0.0.1 is a safe IP and should be excluded.
	if len(ips) != 2 {
		t.Errorf("expected 2 IPs, got %d: %v", len(ips), ips)
	}
	if !containsValue(ips, "192.168.1.42") {
		t.Error("missing IP: 192.168.1.42")
	}
	if !containsValue(ips, "10.0.0.1") {
		t.Error("missing IP: 10.0.0.1")
	}
}

func TestScanHostnames(t *testing.T) {
	text := "Redirect to casino-winner.evil.com and phishing-site.xyz.net but github.com is fine"
	matches := Scan(text)
	hosts := filterByType(matches, PatternHost)

	if !containsValue(hosts, "casino-winner.evil.com") {
		t.Error("missing host: casino-winner.evil.com")
	}
	if !containsValue(hosts, "phishing-site.xyz.net") {
		t.Error("missing host: phishing-site.xyz.net")
	}
	// github.com is a safe host and should be excluded.
	if containsValue(hosts, "github.com") {
		t.Error("github.com should be excluded as safe host")
	}
}

func TestScanCredentials(t *testing.T) {
	text := `password=s3cret_value
DB_SECRET=hunter2
token=abc123def456
api_key: sk-1234567890`

	matches := Scan(text)
	creds := filterByType(matches, PatternCred)

	if len(creds) < 3 {
		t.Errorf("expected at least 3 credentials, got %d: %v", len(creds), creds)
	}
}

func TestScanEmails(t *testing.T) {
	text := "Contact admin@company.com or security-team@incident.org for help"
	matches := Scan(text)
	emails := filterByType(matches, PatternEmail)

	if len(emails) != 2 {
		t.Errorf("expected 2 emails, got %d: %v", len(emails), emails)
	}
}

func TestScanPasswdUsers(t *testing.T) {
	text := `root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
wpadmin2:x:0:0::/root:/bin/bash
nullbot:x:1001:1001:Nullbot Service:/home/nullbot:/bin/bash`

	matches := Scan(text)
	users := filterByType(matches, PatternUser)

	// root is excluded by design.
	if containsValue(users, "root") {
		t.Error("root should be excluded from user detection")
	}
	if !containsValue(users, "wpadmin2") {
		t.Error("missing user: wpadmin2")
	}
	if !containsValue(users, "nullbot") {
		t.Error("missing user: nullbot")
	}
}

func TestScanTildeUsers(t *testing.T) {
	text := "Check ~admin/.ssh/authorized_keys and ~www-data/public_html"
	matches := Scan(text)
	users := filterByType(matches, PatternUser)

	if !containsValue(users, "admin") {
		t.Error("missing tilde user: admin")
	}
	if !containsValue(users, "www-data") {
		t.Error("missing tilde user: www-data")
	}
}

func TestScanDedup(t *testing.T) {
	text := "/var/www/site appears twice: /var/www/site"
	matches := Scan(text)
	paths := filterByType(matches, PatternPath)

	if len(paths) != 1 {
		t.Errorf("expected 1 deduplicated path, got %d", len(paths))
	}
}

func TestScanSortedByPosition(t *testing.T) {
	text := "IP 10.0.0.1 then path /var/www then email test@host.com"
	matches := Scan(text)

	for i := 1; i < len(matches); i++ {
		if matches[i].Start < matches[i-1].Start {
			t.Errorf("matches not sorted: %v at %d before %v at %d",
				matches[i-1].Value, matches[i-1].Start,
				matches[i].Value, matches[i].Start)
		}
	}
}

func TestScanEmpty(t *testing.T) {
	matches := Scan("")
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty string, got %d", len(matches))
	}
}

func TestScanNoSensitiveData(t *testing.T) {
	text := "This is a plain text with no sensitive information at all."
	matches := Scan(text)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for non-sensitive text, got %d: %v", len(matches), matches)
	}
}

func TestScanWithConfigNil(t *testing.T) {
	text := "Server 192.168.1.42 at /var/www/site"
	m1 := Scan(text)
	m2 := ScanWithConfig(text, nil, nil)

	if len(m1) != len(m2) {
		t.Errorf("nil config: Scan found %d, ScanWithConfig found %d", len(m1), len(m2))
	}
}

func TestScanWithConfigExtraPattern(t *testing.T) {
	text := "Connect to db_production_main and db_analytics"
	extra := []ExtraPattern{
		{Name: "DBNAME", Regex: regexp.MustCompile(`\bdb_[a-z0-9_]+\b`), TokenPrefix: "DBNAME"},
	}
	matches := ScanWithConfig(text, &RedactConfig{}, extra)
	dbMatches := filterByType(matches, "DBNAME")

	if len(dbMatches) != 2 {
		t.Errorf("expected 2 DBNAME matches, got %d", len(dbMatches))
	}
}

func TestScanWithConfigLiterals(t *testing.T) {
	text := "Cluster prod-cluster-xyz is running on prod-cluster-abc"
	cfg := &RedactConfig{
		Literals: []string{"prod-cluster-xyz"},
	}
	matches := ScanWithConfig(text, cfg, nil)
	litMatches := filterByType(matches, "LITERAL")

	if len(litMatches) != 1 {
		t.Errorf("expected 1 LITERAL match, got %d", len(litMatches))
	}
	if len(litMatches) > 0 && litMatches[0].Value != "prod-cluster-xyz" {
		t.Errorf("expected prod-cluster-xyz, got %q", litMatches[0].Value)
	}
}

func TestScanWithConfigSafeHosts(t *testing.T) {
	text := "Request to casino-winner.evil.com and internal.company.com"
	cfg := &RedactConfig{
		SafeHosts: []string{"internal.company.com"},
	}
	matches := ScanWithConfig(text, cfg, nil)

	for _, m := range matches {
		if m.Value == "internal.company.com" {
			t.Error("internal.company.com should be safe-listed")
		}
	}
	if !containsValue(matches, "casino-winner.evil.com") {
		t.Error("casino-winner.evil.com should still be detected")
	}
}

func TestScanWithConfigSafeIPs(t *testing.T) {
	text := "Server at 10.0.0.1 and 192.168.1.42"
	cfg := &RedactConfig{
		SafeIPs: []string{"10.0.0.1"},
	}
	matches := ScanWithConfig(text, cfg, nil)

	for _, m := range matches {
		if m.Value == "10.0.0.1" {
			t.Error("10.0.0.1 should be safe-listed")
		}
	}
	if !containsValue(matches, "192.168.1.42") {
		t.Error("192.168.1.42 should still be detected")
	}
}

func TestScanWithConfigSafePaths(t *testing.T) {
	text := "Log at /var/log/syslog and config at /var/www/site/wp-config.php"
	cfg := &RedactConfig{
		SafePaths: []string{"/var/log/"},
	}
	matches := ScanWithConfig(text, cfg, nil)

	for _, m := range matches {
		if strings.HasPrefix(m.Value, "/var/log/") {
			t.Errorf("/var/log/ paths should be safe-listed, got: %s", m.Value)
		}
	}
	if !containsValue(matches, "/var/www/site/wp-config.php") {
		t.Error("/var/www/site/wp-config.php should still be detected")
	}
}

// helpers

func filterByType(matches []Match, typ PatternType) []Match {
	var result []Match
	for _, m := range matches {
		if m.Type == typ {
			result = append(result, m)
		}
	}
	return result
}

func containsValue(matches []Match, value string) bool {
	for _, m := range matches {
		if m.Value == value {
			return true
		}
	}
	return false
}
