package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const defaultTelegramAPIURL = "https://api.telegram.org"

// TelegramAlerter delivers alerts through Telegram Bot API.
type TelegramAlerter struct {
	cfg AlertConfig
}

// NewTelegramAlerter returns a Telegram alerter for a single alert config.
func NewTelegramAlerter(cfg AlertConfig) *TelegramAlerter {
	return &TelegramAlerter{cfg: cfg}
}

// Name returns the transport name.
func (a *TelegramAlerter) Name() string {
	return channelTelegram
}

// Send posts an alert event to Telegram sendMessage API.
func (a *TelegramAlerter) Send(ctx context.Context, event AlertEvent) error {
	apiURL := a.apiURL()
	if shouldRedactTelegram(apiURL) {
		event = redactEventForChannel(event, channelTelegram)
	}

	if strings.TrimSpace(a.cfg.Telegram.BotToken) == "" {
		return fmt.Errorf("telegram bot token is required")
	}
	if strings.TrimSpace(a.cfg.Telegram.ChatID) == "" {
		return fmt.Errorf("telegram chat_id is required")
	}

	payload := map[string]any{
		"chat_id": a.cfg.Telegram.ChatID,
		"text":    formatTelegramMessage(event),
	}
	if strings.TrimSpace(a.cfg.Telegram.ParseMode) != "" {
		payload["parse_mode"] = strings.TrimSpace(a.cfg.Telegram.ParseMode)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal telegram payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", strings.TrimRight(apiURL, "/"), a.cfg.Telegram.BotToken)
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create telegram request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

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
			return fmt.Errorf("telegram rejected: HTTP %d", resp.StatusCode)
		}
		lastErr = fmt.Errorf("telegram server error: HTTP %d", resp.StatusCode)
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no telegram attempts completed")
	}
	return fmt.Errorf("telegram failed after %d attempts: %w", maxRetries, lastErr)
}

func (a *TelegramAlerter) apiURL() string {
	if strings.TrimSpace(a.cfg.Telegram.APIURL) == "" {
		return defaultTelegramAPIURL
	}
	return strings.TrimSpace(a.cfg.Telegram.APIURL)
}

func shouldRedactTelegram(apiURL string) bool {
	return shouldRedactEndpoint(apiURL)
}

func formatTelegramMessage(event AlertEvent) string {
	return fmt.Sprintf(
		"chainwatch %s\nTool: %s\nResource: %s\nTier: %d\nReason: %s\nTraceID: %s",
		event.Decision,
		event.Tool,
		event.Resource,
		event.Tier,
		event.Reason,
		event.TraceID,
	)
}
