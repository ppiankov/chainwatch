package observe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ppiankov/chainwatch/internal/wo"
	"github.com/ppiankov/neurorouter"
)

// poolCounter distributes requests across pool providers via round-robin.
var poolCounter uint64

// LLMProvider holds connection details for a single LLM endpoint.
type LLMProvider struct {
	URL   string
	Key   string
	Model string
}

// ClassifierConfig holds parameters for LLM-based observation classification.
type ClassifierConfig struct {
	APIURL           string
	APIKey           string
	Model            string
	MaxTokens        int
	Timeout          time.Duration
	LLMRateLimit     int // requests per minute; 0 = unlimited
	Fallbacks        []LLMProvider
	Pool             []LLMProvider // round-robin distribution across providers
	Sensitivity      string        // "local" restricts to localhost providers only
	DiagnosticWriter io.Writer     // if non-nil, raw LLM response is written here
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
- email_delivered: message successfully delivered to recipient
- email_blocked: message rejected by policy, antispam, or antivirus
- email_deferred: message delivery delayed, will retry
- email_bounced: message delivery failed permanently

Valid severity levels: low, medium, high, critical

Return ONLY valid JSON, no markdown fences, no commentary:
{"observations":[{"type":"<type>","detail":"<description>","severity":"<level>"}]}

If you find nothing suspicious, return: {"observations":[]}
Report ALL findings, not just the first one.`

// isLocalProvider returns true if the provider URL points to localhost.
func isLocalProvider(p LLMProvider) bool {
	lower := strings.ToLower(p.URL)
	return strings.Contains(lower, "localhost") || strings.Contains(lower, "127.0.0.1")
}

// Classify sends collected evidence to an LLM for structured classification.
// When Pool is non-empty, distributes requests round-robin across pool members.
// When Pool is empty, uses the primary provider + fallbacks (legacy behavior).
// When Sensitivity is "local", filters providers to localhost-only.
func Classify(cfg ClassifierConfig, evidence string) ([]wo.Observation, error) {
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 600
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	// Build provider list.
	var providers []LLMProvider
	if len(cfg.Pool) > 0 {
		// Round-robin: start from next pool index, wrap around all members.
		idx := int(atomic.AddUint64(&poolCounter, 1) - 1)
		for i := 0; i < len(cfg.Pool); i++ {
			providers = append(providers, cfg.Pool[(idx+i)%len(cfg.Pool)])
		}
		providers = append(providers, cfg.Fallbacks...)
	} else {
		// Legacy: primary + fallbacks.
		providers = []LLMProvider{{URL: cfg.APIURL, Key: cfg.APIKey, Model: cfg.Model}}
		providers = append(providers, cfg.Fallbacks...)
	}

	// Sensitivity filtering: "local" restricts to localhost providers only.
	if cfg.Sensitivity == "local" {
		var filtered []LLMProvider
		for _, p := range providers {
			if isLocalProvider(p) {
				filtered = append(filtered, p)
			}
		}
		if len(filtered) == 0 {
			return nil, fmt.Errorf("sensitivity=local but no localhost providers available")
		}
		providers = filtered
	}

	var lastErr error
	for _, p := range providers {
		obs, err := classifyWith(p, timeout, cfg.MaxTokens, cfg.LLMRateLimit, evidence, cfg.DiagnosticWriter)
		if err == nil {
			return obs, nil
		}
		lastErr = err
		// Rate limiting is not a provider failure — propagate immediately.
		if errors.Is(err, neurorouter.ErrRateLimited) {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "classify: provider %s failed: %v\n", p.URL, err)
	}
	return nil, lastErr
}

func classifyWith(p LLMProvider, timeout time.Duration, maxTokens, rateLimit int, evidence string, diagW io.Writer) ([]wo.Observation, error) {
	client := &neurorouter.Client{
		BaseURL:    p.URL,
		APIKey:     p.Key,
		Model:      p.Model,
		HTTPClient: &http.Client{Timeout: timeout},
	}
	if rateLimit > 0 {
		client.RateLimit = &neurorouter.RateLimit{RequestsPerMinute: rateLimit}
	}

	temp := float64(0)
	resp, err := client.Complete(context.Background(), &neurorouter.CompletionRequest{
		Messages: []neurorouter.ChatMessage{
			{Role: "system", Content: classifySystemPrompt},
			{Role: "user", Content: evidence},
		},
		MaxTokens:   maxTokens,
		Temperature: &temp,
	})
	if err != nil {
		return nil, fmt.Errorf("classify: %w", err)
	}

	if diagW != nil {
		fmt.Fprintf(diagW, "=== RECEIVED: RAW LLM RESPONSE ===\n%s\n=== END RECEIVED ===\n\n", resp.Content)
	}

	return parseClassification(resp.Content)
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
