package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDispatchMatchesEvents(t *testing.T) {
	var called atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewDispatcher([]AlertConfig{
		{URL: srv.URL, Format: "generic", Events: []string{"deny"}},
	})

	d.Dispatch(AlertEvent{Decision: "deny", Tool: "command", Resource: "rm -rf /"})
	time.Sleep(200 * time.Millisecond)

	if called.Load() != 1 {
		t.Errorf("expected 1 call, got %d", called.Load())
	}
}

func TestDispatchSkipsNonMatching(t *testing.T) {
	var called atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewDispatcher([]AlertConfig{
		{URL: srv.URL, Format: "generic", Events: []string{"deny"}},
	})

	d.Dispatch(AlertEvent{Decision: "allow", Tool: "file_read", Resource: "/tmp/safe.txt"})
	time.Sleep(200 * time.Millisecond)

	if called.Load() != 0 {
		t.Errorf("expected 0 calls for non-matching event, got %d", called.Load())
	}
}

func TestDispatchMultipleWebhooks(t *testing.T) {
	var called atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	srv1 := httptest.NewServer(handler)
	defer srv1.Close()
	srv2 := httptest.NewServer(handler)
	defer srv2.Close()

	d := NewDispatcher([]AlertConfig{
		{URL: srv1.URL, Format: "generic", Events: []string{"deny"}},
		{URL: srv2.URL, Format: "generic", Events: []string{"deny", "require_approval"}},
	})

	d.Dispatch(AlertEvent{Decision: "deny", Tool: "command", Resource: "rm -rf /"})
	time.Sleep(200 * time.Millisecond)

	if called.Load() != 2 {
		t.Errorf("expected 2 calls (both webhooks match), got %d", called.Load())
	}
}

func TestDispatchMatchesBreakGlassType(t *testing.T) {
	var called atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewDispatcher([]AlertConfig{
		{URL: srv.URL, Format: "generic", Events: []string{"break_glass_used"}},
	})

	d.Dispatch(AlertEvent{Decision: "allow", Type: "break_glass_used", Tool: "command", Resource: "sudo reboot"})
	time.Sleep(200 * time.Millisecond)

	if called.Load() != 1 {
		t.Errorf("expected 1 call for break_glass_used type match, got %d", called.Load())
	}
}

func TestRetryOnServerError(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := Send(AlertConfig{URL: srv.URL, Format: "generic"}, AlertEvent{Decision: "deny"})
	if err != nil {
		t.Errorf("expected success after retries, got: %v", err)
	}
	if attempts.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts.Load())
	}
}

func TestNoRetryOnClientError(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	err := Send(AlertConfig{URL: srv.URL, Format: "generic"}, AlertEvent{Decision: "deny"})
	if err == nil {
		t.Error("expected error on 400, got nil")
	}
	if attempts.Load() != 1 {
		t.Errorf("expected 1 attempt (no retry on 4xx), got %d", attempts.Load())
	}
}

func TestFormatGenericJSON(t *testing.T) {
	event := AlertEvent{
		Timestamp: "2025-01-15T14:00:00.000Z",
		TraceID:   "t-123",
		Tool:      "command",
		Resource:  "rm -rf /",
		Decision:  "deny",
		Reason:    "denylist match",
		Tier:      3,
	}

	data, err := FormatPayload("generic", event)
	if err != nil {
		t.Fatal(err)
	}

	var parsed AlertEvent
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("generic format is not valid JSON: %v", err)
	}
	if parsed.TraceID != "t-123" {
		t.Errorf("expected trace_id t-123, got %s", parsed.TraceID)
	}
	if parsed.Decision != "deny" {
		t.Errorf("expected decision deny, got %s", parsed.Decision)
	}
}

func TestFormatSlackBlockKit(t *testing.T) {
	event := AlertEvent{
		Tool:     "command",
		Resource: "rm -rf /",
		Decision: "deny",
		Reason:   "denylist match",
		Tier:     3,
	}

	data, err := FormatPayload("slack", event)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("slack format is not valid JSON: %v", err)
	}

	blocks, ok := parsed["blocks"].([]any)
	if !ok {
		t.Fatal("expected blocks array in slack payload")
	}
	if len(blocks) < 2 {
		t.Fatalf("expected at least 2 blocks, got %d", len(blocks))
	}

	// Check header block
	header, _ := blocks[0].(map[string]any)
	if header["type"] != "header" {
		t.Errorf("expected header block, got %s", header["type"])
	}

	// Check section block has fields
	section, _ := blocks[1].(map[string]any)
	if section["type"] != "section" {
		t.Errorf("expected section block, got %s", section["type"])
	}
	fields, ok := section["fields"].([]any)
	if !ok || len(fields) < 4 {
		t.Errorf("expected at least 4 fields in section, got %v", fields)
	}
}

func TestFormatPagerDuty(t *testing.T) {
	event := AlertEvent{
		Tool:     "command",
		Resource: "rm -rf /",
		Decision: "deny",
		Reason:   "denylist match",
		Tier:     3,
	}

	data, err := FormatPayload("pagerduty", event)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("pagerduty format is not valid JSON: %v", err)
	}

	if parsed["event_action"] != "trigger" {
		t.Errorf("expected event_action trigger, got %v", parsed["event_action"])
	}

	payload, ok := parsed["payload"].(map[string]any)
	if !ok {
		t.Fatal("expected payload object")
	}
	if payload["severity"] != "critical" {
		t.Errorf("expected severity critical for tier 3, got %v", payload["severity"])
	}
	if payload["source"] != "chainwatch" {
		t.Errorf("expected source chainwatch, got %v", payload["source"])
	}
}

func TestNewDispatcherNilOnEmpty(t *testing.T) {
	d := NewDispatcher(nil)
	if d != nil {
		t.Error("expected nil dispatcher for empty configs")
	}

	d = NewDispatcher([]AlertConfig{})
	if d != nil {
		t.Error("expected nil dispatcher for zero-length configs")
	}
}

func TestShouldRedactWebhook(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://localhost:8080/hook", false},
		{"http://127.0.0.1:9090/alert", false},
		{"https://hooks.slack.com/services/xxx", true},
		{"https://events.pagerduty.com/v2/enqueue", true},
		{"http://Localhost:8080/hook", false},
	}
	for _, tt := range tests {
		if got := shouldRedactWebhook(tt.url); got != tt.want {
			t.Errorf("shouldRedactWebhook(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestSendRedactsCloudWebhook(t *testing.T) {
	var received AlertEvent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	event := AlertEvent{
		TraceID:  "t-001",
		Tool:     "command",
		Resource: "/var/www/site/wp-config.php",
		Decision: "deny",
		Reason:   "path /etc/shadow in denylist",
		Tier:     3,
	}

	// The httptest server uses 127.0.0.1 — override for cloud simulation.
	// We test the redaction function directly instead.
	redacted := redactEvent(event)

	if redacted.Resource == "/var/www/site/wp-config.php" {
		t.Error("expected Resource to be redacted, got raw path")
	}
	if redacted.Reason == "path /etc/shadow in denylist" {
		t.Error("expected Reason to be redacted, got raw path")
	}
	// Non-sensitive fields must be preserved.
	if redacted.TraceID != "t-001" {
		t.Errorf("TraceID changed: got %q", redacted.TraceID)
	}
	if redacted.Tool != "command" {
		t.Errorf("Tool changed: got %q", redacted.Tool)
	}
	if redacted.Decision != "deny" {
		t.Errorf("Decision changed: got %q", redacted.Decision)
	}
	if redacted.Tier != 3 {
		t.Errorf("Tier changed: got %d", redacted.Tier)
	}
}

func TestSendSkipsRedactLocalhost(t *testing.T) {
	var received AlertEvent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	event := AlertEvent{
		Tool:     "command",
		Resource: "/var/www/site/wp-config.php",
		Decision: "deny",
		Reason:   "path /etc/shadow in denylist",
	}

	// httptest server is 127.0.0.1 — should NOT redact.
	err := Send(AlertConfig{URL: srv.URL, Format: "generic"}, event)
	if err != nil {
		t.Fatal(err)
	}

	if received.Resource != "/var/www/site/wp-config.php" {
		t.Errorf("expected raw Resource for localhost, got %q", received.Resource)
	}
	if received.Reason != "path /etc/shadow in denylist" {
		t.Errorf("expected raw Reason for localhost, got %q", received.Reason)
	}
}
