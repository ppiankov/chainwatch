package alert

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ppiankov/chainwatch/internal/redact"
)

const (
	requestTimeout = 5 * time.Second
	maxRetries     = 3
)

var httpClient = &http.Client{Timeout: requestTimeout}

// shouldRedactWebhook returns true when the webhook URL points to a
// remote (non-localhost) endpoint. Mirrors redact.ResolveMode logic.
func shouldRedactWebhook(url string) bool {
	lower := strings.ToLower(url)
	return !strings.Contains(lower, "localhost") && !strings.Contains(lower, "127.0.0.1")
}

// redactEvent strips sensitive values from Resource and Reason fields.
// Uses a throwaway TokenMap — webhook payloads are one-way, no detoken needed.
func redactEvent(event AlertEvent) AlertEvent {
	tm := redact.NewTokenMap("webhook")
	event.Resource = redact.Redact(event.Resource, tm)
	event.Reason = redact.Redact(event.Reason, tm)
	return event
}

// Send posts an alert event to a webhook endpoint with retry on 5xx.
func Send(cfg AlertConfig, event AlertEvent) error {
	if shouldRedactWebhook(cfg.URL) {
		event = redactEvent(event)
	}

	body, err := FormatPayload(cfg.Format, event)
	if err != nil {
		return fmt.Errorf("format payload: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		req, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range cfg.Headers {
			req.Header.Set(k, v)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return fmt.Errorf("webhook rejected: HTTP %d", resp.StatusCode)
		}
		// 5xx — retry
		lastErr = fmt.Errorf("webhook server error: HTTP %d", resp.StatusCode)
	}

	return fmt.Errorf("webhook failed after %d attempts: %w", maxRetries, lastErr)
}
