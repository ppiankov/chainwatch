package observe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ppiankov/chainwatch/internal/wo"
)

// ClassifierConfig holds parameters for LLM-based observation classification.
type ClassifierConfig struct {
	APIURL    string
	APIKey    string
	Model     string
	MaxTokens int
	Timeout   time.Duration
}

// classificationResponse is the expected JSON from the LLM.
type classificationResponse struct {
	Observations []classifiedObs `json:"observations"`
}

type classifiedObs struct {
	Type     string `json:"type"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

const classifySystemPrompt = `You are a security investigation classifier. You receive raw command output from a system investigation and must classify findings into structured observations.

Valid observation types:
- file_hash_mismatch: core file differs from known-good
- redirect_detected: HTTP redirect to suspicious domain
- unauthorized_user: rogue user account (especially UID 0)
- suspicious_code: obfuscated code (eval, base64_decode, gzinflate)
- config_modified: configuration file tampered with
- unknown_file: file that should not exist (PHP in uploads, etc.)
- permission_anomaly: world-writable config, wrong ownership
- cron_anomaly: suspicious cron job
- process_anomaly: unexpected process or service
- network_anomaly: unexpected listening port or connection

Valid severity levels: low, medium, high, critical

Return ONLY valid JSON, no markdown fences, no commentary:
{"observations":[{"type":"<type>","detail":"<description>","severity":"<level>"}]}

If you find nothing suspicious, return: {"observations":[]}
Report ALL findings, not just the first one.`

// Classify sends collected evidence to a local LLM for structured classification.
// Returns typed observations ready for WO generation.
func Classify(cfg ClassifierConfig, evidence string) ([]wo.Observation, error) {
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 600
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}

	messages := []map[string]string{
		{"role": "system", "content": classifySystemPrompt},
		{"role": "user", "content": evidence},
	}

	body, _ := json.Marshal(map[string]interface{}{
		"model":       cfg.Model,
		"messages":    messages,
		"max_tokens":  cfg.MaxTokens,
		"temperature": 0,
	})

	req, err := http.NewRequest("POST", cfg.APIURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: cfg.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("classify request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("classify HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil || len(result.Choices) == 0 {
		return nil, fmt.Errorf("empty classify response")
	}

	raw := strings.TrimSpace(result.Choices[0].Message.Content)
	return parseClassification(raw)
}

// parseClassification extracts observations from LLM response JSON.
// Handles both {"observations":[...]} and raw array [{...}] formats.
func parseClassification(raw string) ([]wo.Observation, error) {
	raw = cleanJSON(raw)

	// Try wrapped format first.
	var cr classificationResponse
	if err := json.Unmarshal([]byte(raw), &cr); err == nil && len(cr.Observations) >= 0 {
		return convertObs(cr.Observations), nil
	}

	// Try raw array format (some models return this).
	var arr []classifiedObs
	if err := json.Unmarshal([]byte(raw), &arr); err == nil {
		return convertObs(arr), nil
	}

	return nil, fmt.Errorf("cannot parse classification response: %s", truncate(raw, 200))
}

// convertObs maps classified observations to typed wo.Observation structs.
// Unknown types and severities are preserved as-is for downstream validation.
func convertObs(classified []classifiedObs) []wo.Observation {
	obs := make([]wo.Observation, 0, len(classified))
	for _, c := range classified {
		obs = append(obs, wo.Observation{
			Type:     wo.ObservationType(c.Type),
			Severity: wo.Severity(c.Severity),
			Detail:   c.Detail,
		})
	}
	return obs
}

// cleanJSON strips markdown fences and leading/trailing whitespace.
func cleanJSON(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
