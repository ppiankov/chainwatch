//go:build research

// Package redaction tests whether LLMs can produce correct remediation plans
// from tokenized (redacted) Work Orders. This is the gate for CW49/CW50/CW51.
//
// Run: go test -tags research -v -timeout 5m ./internal/research/redaction/
//
// Env:
//
//	RESEARCH_API_URL  — LLM endpoint (default: http://localhost:11434/v1/chat/completions)
//	RESEARCH_MODEL    — model name (default: qwen2.5-coder:32b)
//	RESEARCH_API_KEY  — API key (optional, not needed for ollama)
package redaction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	defaultAPIURL = "http://localhost:11434/v1/chat/completions"
	defaultModel  = "qwen2.5-coder:32b"
)

// tokenizedWO is a sample Work Order with all sensitive data replaced by tokens.
type tokenizedWO struct {
	name        string
	system      string
	prompt      string
	wantTokens  []string // tokens that MUST appear in the response commands
	denyLiteral []string // literal strings that must NOT appear (leak detection)
}

// tokenLegend is prepended to every prompt so the LLM knows the mapping format.
const tokenLegend = `IMPORTANT: All paths, hostnames, and IPs in this Work Order are redacted with tokens like <<PATH_1>>, <<HOST_1>>, <<IP_1>>. You MUST use these exact tokens in your commands. Do NOT invent real paths or IPs. The tokens will be replaced with real values before execution.

Token reference:
  <<HOST_1>>  = target web server hostname
  <<PATH_1>>  = web root directory
  <<PATH_2>>  = wp-content/plugins directory
  <<PATH_3>>  = header.php file
  <<IP_1>>    = server IP address
  <<CRED_1>>  = database password (redacted)
`

var testCases = []tokenizedWO{
	{
		name:   "wordpress_compromise_simple",
		system: "You are a system remediation agent. Return ONLY valid JSON, no markdown fences.",
		prompt: tokenLegend + `
Work Order WO-001:
Target: <<HOST_1>> at <<PATH_1>>
Observations:
  1. Malicious redirect to casino-domain.com detected in <<PATH_3>> at line 42
  2. Unknown plugin file <<PATH_2>>/x.php with obfuscated code (eval+base64_decode)
  3. Unauthorized admin user "wpadmin2" created 2026-02-17
Constraints:
  - Only modify files under <<PATH_1>>
  - No sudo
  - No network access
  - Max 6 commands
Proposed goals:
  - Remove malicious plugin file
  - Clean injected redirect from header
  - Remove unauthorized user

Return JSON: {"goal":"...","steps":[{"cmd":"...","why":"..."}]}`,
		wantTokens:  []string{"<<PATH_1>>", "<<PATH_2>>", "<<PATH_3>>"},
		denyLiteral: []string{"/var/www", "/home/", "192.168", "10.0."},
	},
	{
		name:   "wordpress_compromise_dense_tokens",
		system: "You are a system remediation agent. Return ONLY valid JSON, no markdown fences.",
		prompt: tokenLegend + `
Additional tokens:
  <<PATH_4>>  = WordPress core directory
  <<PATH_5>>  = .htaccess file
  <<PATH_6>>  = wp-config.php
  <<PATH_7>>  = mu-plugins directory
  <<USER_1>>  = web server system user
  <<DB_1>>    = database name

Work Order WO-002:
Target: <<HOST_1>> (<<IP_1>>) at <<PATH_1>>
Observations:
  1. Redirect chain: <<HOST_1>> → casino-redirect.com via injected JS in <<PATH_3>>
  2. Rogue file: <<PATH_2>>/backdoor.php (size 0 bytes, suspicious)
  3. Modified .htaccess: <<PATH_5>> contains rewrite rules pointing to external domain
  4. Unknown mu-plugin: <<PATH_7>>/loader.php with gzinflate+str_rot13
  5. wp-config.php (<<PATH_6>>) last modified 2026-02-17 (unexpected)
  6. Cron entry for <<USER_1>>: wget to external URL every 5 minutes
  7. 3 unauthorized admin users in <<DB_1>>
Constraints:
  - Only modify files under <<PATH_1>>
  - Read-only access to <<PATH_6>> (do not modify wp-config)
  - No sudo, no network, no package installs
  - Max 8 commands
Proposed goals:
  - Remove all malicious files
  - Restore clean .htaccess
  - Remove unauthorized cron entry
  - List unauthorized DB users for manual removal

Return JSON: {"goal":"...","steps":[{"cmd":"...","why":"..."}]}`,
		wantTokens:  []string{"<<PATH_1>>", "<<PATH_2>>", "<<PATH_5>>", "<<PATH_7>>"},
		denyLiteral: []string{"/var/www", "/home/", "192.168", "10.0.", "/etc/"},
	},
	{
		name:   "generic_linux_investigation",
		system: "You are a system remediation agent. Return ONLY valid JSON, no markdown fences.",
		prompt: tokenLegend + `
Additional tokens:
  <<PATH_4>>  = suspicious cron script
  <<PATH_5>>  = nginx config directory
  <<USER_1>>  = compromised user account

Work Order WO-003:
Target: <<HOST_1>> (<<IP_1>>)
Observations:
  1. Outbound connections to <<IP_1>>:4444 from unknown process
  2. Cron job running <<PATH_4>> every minute as <<USER_1>>
  3. Nginx config in <<PATH_5>> modified to proxy traffic to external host
  4. SSH authorized_keys for <<USER_1>> contains unknown public key
Constraints:
  - Investigation only: list and check, do not delete
  - No sudo
  - Max 5 commands
Proposed goals:
  - List the cron script contents
  - Show nginx config diff
  - List SSH authorized keys
  - Check running processes

Return JSON: {"goal":"...","steps":[{"cmd":"...","why":"..."}]}`,
		wantTokens:  []string{"<<PATH_4>>", "<<PATH_5>>", "<<USER_1>>"},
		denyLiteral: []string{"/var/www", "/home/admin", "/root", "192.168"},
	},
}

type step struct {
	Cmd string `json:"cmd"`
	Why string `json:"why"`
}

type plan struct {
	Goal  string `json:"goal"`
	Steps []step `json:"steps"`
}

type result struct {
	name          string
	rawResponse   string
	parsedOK      bool
	tokenHits     int
	tokenTotal    int
	leaks         []string
	stepCount     int
	jsonValid     bool
	parseError    string
	latencyMS     int64
	tokensMissing []string
}

func TestRedactionFidelity(t *testing.T) {
	apiURL := envOr("RESEARCH_API_URL", defaultAPIURL)
	model := envOr("RESEARCH_MODEL", defaultModel)
	apiKey := os.Getenv("RESEARCH_API_KEY")

	t.Logf("Endpoint: %s", apiURL)
	t.Logf("Model:    %s", model)

	// Quick connectivity check.
	if _, err := callLLM(apiURL, apiKey, model, "You are a test.", "Say OK.", 50); err != nil {
		t.Fatalf("LLM not reachable: %v", err)
	}

	var results []result

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			raw, err := callLLM(apiURL, apiKey, model, tc.system, tc.prompt, 800)
			latency := time.Since(start).Milliseconds()

			r := result{
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

			// Parse JSON.
			cleaned := cleanJSON(raw)
			var p plan
			if err := json.Unmarshal([]byte(cleaned), &p); err != nil {
				r.jsonValid = false
				r.parseError = err.Error()
				t.Logf("JSON parse failed: %v", err)
				results = append(results, r)
				return
			}

			r.jsonValid = true
			r.parsedOK = true
			r.stepCount = len(p.Steps)

			// Check token usage in commands.
			allCmds := ""
			for _, s := range p.Steps {
				allCmds += s.Cmd + " "
			}

			r.tokenTotal = len(tc.wantTokens)
			for _, tok := range tc.wantTokens {
				if strings.Contains(allCmds, tok) {
					r.tokenHits++
				} else {
					r.tokensMissing = append(r.tokensMissing, tok)
				}
			}

			// Check for literal leaks.
			for _, deny := range tc.denyLiteral {
				if strings.Contains(allCmds, deny) {
					r.leaks = append(r.leaks, deny)
				}
			}

			t.Logf("Tokens: %d/%d used correctly", r.tokenHits, r.tokenTotal)
			if len(r.tokensMissing) > 0 {
				t.Logf("Missing tokens: %v", r.tokensMissing)
			}
			if len(r.leaks) > 0 {
				t.Logf("LEAKS detected: %v", r.leaks)
			}
			t.Logf("Steps: %d, Goal: %s", r.stepCount, p.Goal)

			results = append(results, r)
		})
	}

	// Summary.
	t.Log("\n=== FIDELITY SUMMARY ===")
	t.Logf("Model: %s", model)
	totalTokens := 0
	totalHits := 0
	totalLeaks := 0
	totalJSON := 0
	for _, r := range results {
		if r.jsonValid {
			totalJSON++
		}
		totalTokens += r.tokenTotal
		totalHits += r.tokenHits
		totalLeaks += len(r.leaks)
		status := "PASS"
		if !r.jsonValid {
			status = "FAIL(json)"
		} else if r.tokenHits < r.tokenTotal {
			status = fmt.Sprintf("PARTIAL(%d/%d)", r.tokenHits, r.tokenTotal)
		}
		if len(r.leaks) > 0 {
			status += "+LEAK"
		}
		t.Logf("  %-40s %s  %dms", r.name, status, r.latencyMS)
	}
	t.Logf("JSON valid: %d/%d", totalJSON, len(results))
	t.Logf("Token fidelity: %d/%d (%.0f%%)", totalHits, totalTokens, float64(totalHits)/float64(totalTokens)*100)
	t.Logf("Literal leaks: %d", totalLeaks)

	if totalHits < totalTokens {
		t.Logf("VERDICT: Token fidelity below 100%% — prompt engineering or schema changes needed")
	} else if totalLeaks > 0 {
		t.Logf("VERDICT: Leaks detected — redaction insufficient, LLM invents real paths")
	} else {
		t.Logf("VERDICT: PASS — LLM correctly uses tokens, no leaks")
	}
}

func callLLM(apiURL, apiKey, model, systemMsg, userMsg string, maxTokens int) (string, error) {
	messages := []map[string]string{
		{"role": "system", "content": systemMsg},
		{"role": "user", "content": userMsg},
	}

	body, _ := json.Marshal(map[string]interface{}{
		"model":       model,
		"messages":    messages,
		"max_tokens":  maxTokens,
		"temperature": 0,
	})

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &chatResp); err != nil || len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return strings.TrimSpace(chatResp.Choices[0].Message.Content), nil
}

func cleanJSON(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
