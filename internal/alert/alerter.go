package alert

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ppiankov/chainwatch/internal/redact"
)

const (
	requestTimeout = 5 * time.Second
	maxRetries     = 3
)

// Alerter is a transport-specific alert sender.
type Alerter interface {
	Send(ctx context.Context, event AlertEvent) error
	Name() string
}

// MultiAlerter fan-outs an event to multiple channels.
type MultiAlerter struct {
	alerters []Alerter
}

// NewMultiAlerter creates a MultiAlerter. Returns nil when empty.
func NewMultiAlerter(alerters []Alerter) *MultiAlerter {
	if len(alerters) == 0 {
		return nil
	}
	return &MultiAlerter{alerters: alerters}
}

// Send delivers event to all configured alerters and joins send errors.
func (m *MultiAlerter) Send(ctx context.Context, event AlertEvent) error {
	if m == nil {
		return nil
	}

	var errs []error
	for _, alerter := range m.alerters {
		if err := alerter.Send(ctx, event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Name returns the dispatcher name.
func (m *MultiAlerter) Name() string {
	return "multi"
}

func buildAlerter(cfg AlertConfig) Alerter {
	switch cfg.ChannelName() {
	case channelWebhook:
		return NewWebhookAlerter(cfg)
	case channelTelegram:
		return NewTelegramAlerter(cfg)
	case channelEmail:
		return NewEmailAlerter(cfg)
	default:
		return nil
	}
}

func parseActiveChannels(value string) map[string]struct{} {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	channels := make(map[string]struct{})
	for _, part := range strings.Split(value, ",") {
		channel := strings.ToLower(strings.TrimSpace(part))
		if channel == "" {
			continue
		}
		channels[channel] = struct{}{}
	}

	if len(channels) == 0 {
		return nil
	}
	return channels
}

func activeChannelsFromEnv() map[string]struct{} {
	return parseActiveChannels(os.Getenv("NULLBOT_ALERT_CHANNELS"))
}

func channelEnabled(channel string, enabled map[string]struct{}) bool {
	if len(enabled) == 0 {
		return true
	}
	_, ok := enabled[channel]
	return ok
}

func shouldRedactEndpoint(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return true
	}

	host := target
	if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
		host = parsed.Hostname()
	} else if splitHost, _, err := net.SplitHostPort(target); err == nil {
		host = splitHost
	}

	switch strings.ToLower(strings.Trim(host, "[]")) {
	case "localhost", "127.0.0.1", "::1":
		return false
	default:
		return true
	}
}

func redactEventForChannel(event AlertEvent, channel string) AlertEvent {
	tm := redact.NewTokenMap(channel)
	event.Resource = redact.Redact(event.Resource, tm)
	event.Reason = redact.Redact(event.Reason, tm)
	return event
}
