package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestBuildMessagesRoutesBySeverityAndDigest(t *testing.T) {
	now := time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		Channel:         "#infra-ops",
		CriticalChannel: "#infra-critical",
		DigestSchedule:  "0 9 * * 1-5",
		StalePRHours:    24,
	}
	in := Input{
		Findings: []FindingEvent{
			{
				Cluster:  "dev-analytics",
				Summary:  "Replication lag on shard 2",
				Finding:  "active_replicas < total_replicas on 3 tables",
				WOID:     "WO-CH-005",
				JIRALink: "https://jira.example/INFRA-1",
				Severity: "critical",
			},
			{
				Cluster:  "dev-analytics",
				Summary:  "Stale readonly user",
				WOID:     "WO-CH-006",
				JIRALink: "https://jira.example/INFRA-2",
				Severity: "low",
			},
		},
	}

	messages := BuildMessages(in, cfg, now)
	if len(messages) != 2 {
		t.Fatalf("len(messages) = %d, want 2", len(messages))
	}

	if messages[0].Channel != "#infra-critical" {
		t.Fatalf("critical channel = %q, want #infra-critical", messages[0].Channel)
	}
	if !strings.Contains(messages[0].Text, "WO: WO-CH-005") {
		t.Fatalf("expected WO ID in immediate message, got:\n%s", messages[0].Text)
	}
	if !strings.Contains(messages[0].Text, "JIRA: https://jira.example/INFRA-1") {
		t.Fatalf("expected JIRA link in immediate message, got:\n%s", messages[0].Text)
	}
	if !strings.Contains(messages[0].Text, "Severity: critical") {
		t.Fatalf("expected severity in immediate message, got:\n%s", messages[0].Text)
	}

	if messages[1].Channel != "#infra-ops" {
		t.Fatalf("digest channel = %q, want #infra-ops", messages[1].Channel)
	}
	if !strings.Contains(messages[1].Text, "Daily findings digest") {
		t.Fatalf("expected digest header, got:\n%s", messages[1].Text)
	}
	if !strings.Contains(messages[1].Text, "WO: WO-CH-006") {
		t.Fatalf("expected WO ID in digest message, got:\n%s", messages[1].Text)
	}
	if !strings.Contains(messages[1].Text, "JIRA: https://jira.example/INFRA-2") {
		t.Fatalf("expected JIRA link in digest message, got:\n%s", messages[1].Text)
	}
	if !strings.Contains(messages[1].Text, "Severity: low") {
		t.Fatalf("expected severity in digest message, got:\n%s", messages[1].Text)
	}
}

func TestBuildMessagesAddsStaleReminderAfterThreshold(t *testing.T) {
	now := time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)
	in := Input{
		Lifecycle: []LifecycleEvent{
			{
				Event:     "pr_opened",
				Cluster:   "dev-analytics",
				Summary:   "Add TTL to events table",
				WOID:      "WO-CH-001",
				JIRALink:  "https://jira.example/INFRA-3",
				PRLink:    "https://github.com/org/repo/pull/42",
				Severity:  "high",
				EventTime: now.Add(-25 * time.Hour),
			},
		},
	}
	cfg := Config{
		Channel:         "#infra-ops",
		CriticalChannel: "#infra-critical",
		DigestSchedule:  "0 9 * * 1-5",
		StalePRHours:    24,
	}

	messages := BuildMessages(in, cfg, now)
	if len(messages) != 2 {
		t.Fatalf("len(messages) = %d, want 2", len(messages))
	}
	if !strings.Contains(messages[0].Text, "WO lifecycle event: pr_opened") {
		t.Fatalf("expected pr_opened message, got:\n%s", messages[0].Text)
	}
	if !strings.Contains(messages[1].Text, "WO lifecycle event: stale") {
		t.Fatalf("expected stale reminder, got:\n%s", messages[1].Text)
	}
}

func TestBuildMessagesDoesNotDuplicateExplicitStale(t *testing.T) {
	now := time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)
	in := Input{
		Lifecycle: []LifecycleEvent{
			{
				Event:     "pr_opened",
				WOID:      "WO-CH-001",
				EventTime: now.Add(-25 * time.Hour),
			},
			{
				Event: "stale",
				WOID:  "WO-CH-001",
			},
		},
	}
	cfg := Config{
		Channel:         "#infra-ops",
		CriticalChannel: "#infra-critical",
		StalePRHours:    24,
	}

	messages := BuildMessages(in, cfg, now)
	if len(messages) != 2 {
		t.Fatalf("len(messages) = %d, want 2", len(messages))
	}
}

func TestVerificationMessageIncludesResolveTime(t *testing.T) {
	findingTime := time.Date(2026, 3, 6, 8, 0, 0, 0, time.UTC)
	verifiedTime := findingTime.Add(4*time.Hour + 23*time.Minute)
	in := Input{
		Lifecycle: []LifecycleEvent{
			{
				Event:       "verified",
				Cluster:     "dev-analytics",
				Summary:     "TTL policy on events table confirmed active",
				WOID:        "WO-CH-001",
				JIRALink:    "https://jira.example/INFRA-3",
				Severity:    "medium",
				FindingTime: findingTime,
				EventTime:   verifiedTime,
			},
		},
	}
	cfg := Config{
		Channel:         "#infra-ops",
		CriticalChannel: "#infra-critical",
		StalePRHours:    24,
	}

	messages := BuildMessages(in, cfg, verifiedTime)
	if len(messages) != 1 {
		t.Fatalf("len(messages) = %d, want 1", len(messages))
	}
	if !strings.Contains(messages[0].Text, "Time to resolve: 4h 23m") {
		t.Fatalf("expected time-to-resolve metric, got:\n%s", messages[0].Text)
	}
}

func TestParseInputEmptyReader(t *testing.T) {
	in, err := ParseInput(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseInput returned error: %v", err)
	}
	if len(in.Findings) != 0 || len(in.AllLifecycleEvents()) != 0 {
		t.Fatalf("expected empty input, got: %+v", in)
	}
}

func TestServiceDryRunSkipsSender(t *testing.T) {
	calls := 0
	service := NewService(mockSender{
		sendFn: func(_ context.Context, _ Message) error {
			calls++
			return nil
		},
	}, func() time.Time {
		return time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)
	})

	in := Input{
		Findings: []FindingEvent{
			{
				Summary:  "Critical finding",
				WOID:     "WO-1",
				JIRALink: "https://jira.example/INFRA-1",
				Severity: "critical",
			},
		},
	}
	cfg := Config{
		Channel:         "#infra-ops",
		CriticalChannel: "#infra-critical",
		StalePRHours:    24,
	}

	result, err := service.Notify(context.Background(), in, cfg, true)
	if err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}
	if calls != 0 {
		t.Fatalf("sender calls = %d, want 0", calls)
	}
	if len(result.Messages) != 1 {
		t.Fatalf("len(result.Messages) = %d, want 1", len(result.Messages))
	}
}

func TestSlackWebhookSender(t *testing.T) {
	var payload Message
	client := &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json", got)
			}
			if r.Method != http.MethodPost {
				t.Fatalf("method = %q, want POST", r.Method)
			}

			defer func() {
				_ = r.Body.Close()
			}()

			var got Message
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			payload = got

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`ok`)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	sender := NewSlackWebhookSender("https://hooks.slack.test/123", client)
	msg := Message{
		Channel: "#infra-ops",
		Text:    "hello",
	}

	if err := sender.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	if payload.Channel != "#infra-ops" || payload.Text != "hello" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestSlackWebhookSenderRejectsNon2xx(t *testing.T) {
	client := &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			defer func() {
				_ = r.Body.Close()
			}()

			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBufferString(`bad`)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	sender := NewSlackWebhookSender("https://hooks.slack.test/123", client)
	err := sender.Send(context.Background(), Message{Channel: "#infra-ops", Text: "hello"})
	if err == nil {
		t.Fatal("expected Send to fail on non-2xx response")
	}
	if !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

type mockSender struct {
	sendFn func(context.Context, Message) error
}

func (m mockSender) Send(ctx context.Context, msg Message) error {
	return m.sendFn(ctx, msg)
}
