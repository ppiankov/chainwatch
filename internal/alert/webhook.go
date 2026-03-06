package alert

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"
)

var httpClient = &http.Client{Timeout: requestTimeout}

// shouldRedactWebhook returns true when the webhook URL points to a
// remote (non-localhost) endpoint. Mirrors redact.ResolveMode logic.
func shouldRedactWebhook(url string) bool {
	return shouldRedactEndpoint(url)
}

// redactEvent strips sensitive values from Resource and Reason fields.
// Uses a throwaway TokenMap — webhook payloads are one-way, no detoken needed.
func redactEvent(event AlertEvent) AlertEvent {
	return redactEventForChannel(event, channelWebhook)
}

// WebhookAlerter sends alert events to HTTP webhook endpoints.
type WebhookAlerter struct {
	cfg AlertConfig
}

// NewWebhookAlerter returns a webhook alerter for a single alert config.
func NewWebhookAlerter(cfg AlertConfig) *WebhookAlerter {
	return &WebhookAlerter{cfg: cfg}
}

// Name returns the transport name.
func (a *WebhookAlerter) Name() string {
	return channelWebhook
}

// Send posts an alert event to a webhook endpoint with retry on 5xx.
func (a *WebhookAlerter) Send(ctx context.Context, event AlertEvent) error {
	if shouldRedactWebhook(a.cfg.URL) {
		event = redactEvent(event)
	}

	body, err := FormatPayload(a.cfg.Format, event)
	if err != nil {
		return fmt.Errorf("format payload: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.URL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range a.cfg.Headers {
			req.Header.Set(k, v)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return fmt.Errorf("webhook rejected: HTTP %d", resp.StatusCode)
		}
		// 5xx — retry
		lastErr = fmt.Errorf("webhook server error: HTTP %d", resp.StatusCode)
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no webhook attempts completed")
	}
	return fmt.Errorf("webhook failed after %d attempts: %w", maxRetries, lastErr)
}

// Send posts an alert event to a webhook endpoint with retry on 5xx.
// Backward-compatible helper for existing callers/tests.
func Send(cfg AlertConfig, event AlertEvent) error {
	return NewWebhookAlerter(cfg).Send(context.Background(), event)
}
