package alert

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	_ Alerter = (*WebhookAlerter)(nil)
	_ Alerter = (*TelegramAlerter)(nil)
	_ Alerter = (*EmailAlerter)(nil)
	_ Alerter = (*MultiAlerter)(nil)
)

type testAlerter struct {
	name string
	err  error
	sent atomic.Int32
}

func (a *testAlerter) Send(context.Context, AlertEvent) error {
	a.sent.Add(1)
	return a.err
}

func (a *testAlerter) Name() string {
	return a.name
}

func TestMultiAlerterSendFanoutAndErrors(t *testing.T) {
	first := &testAlerter{name: "first"}
	second := &testAlerter{name: "second", err: io.EOF}
	m := NewMultiAlerter([]Alerter{first, second})

	err := m.Send(context.Background(), AlertEvent{Decision: "deny"})
	if err == nil {
		t.Fatal("expected joined error from second alerter")
	}
	if !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("expected EOF in error, got %v", err)
	}
	if got := first.sent.Load(); got != 1 {
		t.Fatalf("expected first alerter to send once, got %d", got)
	}
	if got := second.sent.Load(); got != 1 {
		t.Fatalf("expected second alerter to send once, got %d", got)
	}
}

func TestNewMultiAlerterNilOnEmpty(t *testing.T) {
	if got := NewMultiAlerter(nil); got != nil {
		t.Fatalf("expected nil for nil alerters, got %#v", got)
	}
	if got := NewMultiAlerter([]Alerter{}); got != nil {
		t.Fatalf("expected nil for empty alerters, got %#v", got)
	}
}

func TestParseActiveChannels(t *testing.T) {
	got := parseActiveChannels(" webhook, telegram ,email ")
	if len(got) != 3 {
		t.Fatalf("expected 3 channels, got %d", len(got))
	}
	if _, ok := got[channelWebhook]; !ok {
		t.Fatal("expected webhook channel in parsed set")
	}
	if _, ok := got[channelTelegram]; !ok {
		t.Fatal("expected telegram channel in parsed set")
	}
	if _, ok := got[channelEmail]; !ok {
		t.Fatal("expected email channel in parsed set")
	}
	if parseActiveChannels("") != nil {
		t.Fatal("expected nil for empty input")
	}
}

func TestDispatcherHonorsActiveChannelsEnv(t *testing.T) {
	t.Setenv("NULLBOT_ALERT_CHANNELS", "telegram")

	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	var webhookCalls atomic.Int32
	var telegramCalls atomic.Int32
	httpClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "webhook.example" {
				webhookCalls.Add(1)
			}
			if req.URL.Host == "telegram.example" {
				telegramCalls.Add(1)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			}, nil
		}),
	}

	d := NewDispatcher([]AlertConfig{
		{URL: "https://webhook.example/alert", Format: "generic", Events: []string{"deny"}},
		{
			Channel: channelTelegram,
			Events:  []string{"deny"},
			Telegram: TelegramConfig{
				BotToken: "token",
				ChatID:   "123",
				APIURL:   "https://telegram.example",
			},
		},
	})

	if d == nil {
		t.Fatal("expected non-nil dispatcher")
	}

	d.Dispatch(AlertEvent{Decision: "deny", Tool: "command", Resource: "rm -rf /"})
	time.Sleep(200 * time.Millisecond)

	if got := webhookCalls.Load(); got != 0 {
		t.Fatalf("expected webhook disabled by env filter, got %d calls", got)
	}
	if got := telegramCalls.Load(); got != 1 {
		t.Fatalf("expected telegram call count 1, got %d", got)
	}
}

func TestDispatcherFanoutAcrossWebhookAndTelegram(t *testing.T) {
	t.Setenv("NULLBOT_ALERT_CHANNELS", "")

	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	var webhookCalls atomic.Int32
	var telegramCalls atomic.Int32
	httpClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "webhook.example" {
				webhookCalls.Add(1)
			}
			if req.URL.Host == "telegram.example" {
				telegramCalls.Add(1)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			}, nil
		}),
	}

	d := NewDispatcher([]AlertConfig{
		{URL: "https://webhook.example/alert", Format: "generic", Events: []string{"deny"}},
		{
			Channel: channelTelegram,
			Events:  []string{"deny"},
			Telegram: TelegramConfig{
				BotToken: "token",
				ChatID:   "123",
				APIURL:   "https://telegram.example",
			},
		},
	})

	d.Dispatch(AlertEvent{Decision: "deny", Tool: "command", Resource: "rm -rf /"})
	time.Sleep(200 * time.Millisecond)

	if got := webhookCalls.Load(); got != 1 {
		t.Fatalf("expected webhook call count 1, got %d", got)
	}
	if got := telegramCalls.Load(); got != 1 {
		t.Fatalf("expected telegram call count 1, got %d", got)
	}
}

func TestTelegramAlerterRedactsRemoteEndpoints(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	var body string
	httpClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			data, _ := io.ReadAll(req.Body)
			body = string(data)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			}, nil
		}),
	}

	alerter := NewTelegramAlerter(AlertConfig{
		Channel: channelTelegram,
		Telegram: TelegramConfig{
			BotToken: "test-token",
			ChatID:   "42",
			APIURL:   "https://api.telegram.org",
		},
	})

	err := alerter.Send(context.Background(), AlertEvent{
		Decision: "deny",
		Resource: "/etc/shadow",
		Reason:   "path /etc/shadow is denied",
	})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	if strings.Contains(body, "/etc/shadow") {
		t.Fatalf("expected remote telegram payload redacted, got %q", body)
	}
}

func TestTelegramAlerterSkipsRedactionOnLocalEndpoints(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	var body string
	httpClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			data, _ := io.ReadAll(req.Body)
			body = string(data)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			}, nil
		}),
	}

	alerter := NewTelegramAlerter(AlertConfig{
		Channel: channelTelegram,
		Telegram: TelegramConfig{
			BotToken: "test-token",
			ChatID:   "42",
			APIURL:   "http://localhost:8080",
		},
	})

	err := alerter.Send(context.Background(), AlertEvent{
		Decision: "deny",
		Resource: "/etc/shadow",
		Reason:   "path /etc/shadow is denied",
	})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	if !strings.Contains(body, "/etc/shadow") {
		t.Fatalf("expected local telegram payload unredacted, got %q", body)
	}
}

func TestEmailAlerterRedactsRemoteSMTP(t *testing.T) {
	alerter := NewEmailAlerter(AlertConfig{
		Channel: channelEmail,
		Email: EmailConfig{
			SMTPHost: "smtp.example.com",
			From:     "chainwatch@example.com",
			To:       []string{"ops@example.com"},
		},
	})

	var body string
	alerter.sender = func(_ context.Context, _ EmailConfig, msg []byte, _ []string) error {
		body = string(msg)
		return nil
	}

	err := alerter.Send(context.Background(), AlertEvent{
		Decision: "deny",
		Resource: "/etc/shadow",
		Reason:   "path /etc/shadow is denied",
	})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	if strings.Contains(body, "/etc/shadow") {
		t.Fatalf("expected remote email payload redacted, got %q", body)
	}
}

func TestEmailAlerterSkipsRedactionOnLocalSMTP(t *testing.T) {
	alerter := NewEmailAlerter(AlertConfig{
		Channel: channelEmail,
		Email: EmailConfig{
			SMTPHost: "localhost",
			From:     "chainwatch@example.com",
			To:       []string{"ops@example.com"},
		},
	})

	var body string
	alerter.sender = func(_ context.Context, _ EmailConfig, msg []byte, _ []string) error {
		body = string(msg)
		return nil
	}

	err := alerter.Send(context.Background(), AlertEvent{
		Decision: "deny",
		Resource: "/etc/shadow",
		Reason:   "path /etc/shadow is denied",
	})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	if !strings.Contains(body, "/etc/shadow") {
		t.Fatalf("expected local email payload unredacted, got %q", body)
	}
}

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
