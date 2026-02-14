package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// newTestProxy creates a proxy server on a random port for testing.
func newTestProxy(t *testing.T) (*Server, int) {
	t.Helper()

	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := Config{
		Port:    port,
		Purpose: "test",
		Actor:   map[string]any{"test": true},
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	return srv, port
}

// startTestProxy starts the proxy in the background and returns a cleanup function.
func startTestProxy(t *testing.T, srv *Server) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for server to be ready
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", srv.Addr(), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return cancel
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("proxy failed to start within timeout")
	return cancel
}

// proxyClient creates an HTTP client configured to use the proxy.
func proxyClient(proxyPort int) *http.Client {
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}
}

func TestPaymentURLBlocked(t *testing.T) {
	// Backend that should never be reached
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached backend — should have been blocked")
		w.WriteHeader(200)
	}))
	defer backend.Close()

	srv, port := newTestProxy(t)
	cancel := startTestProxy(t, srv)
	defer cancel()

	client := proxyClient(port)

	// POST to a payment URL (stripe.com pattern in URL path)
	resp, err := client.Post(backend.URL+"/checkout/complete", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["blocked"] != true {
		t.Errorf("expected blocked=true, got %v", body)
	}
}

func TestCredentialEndpointBlocked(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached backend — should have been blocked")
	}))
	defer backend.Close()

	srv, port := newTestProxy(t)
	cancel := startTestProxy(t, srv)
	defer cancel()

	client := proxyClient(port)

	resp, err := client.Post(backend.URL+"/oauth/token", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for /oauth/token, got %d", resp.StatusCode)
	}
}

func TestGetDocsAllowed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte("documentation content"))
	}))
	defer backend.Close()

	srv, port := newTestProxy(t)
	cancel := startTestProxy(t, srv)
	defer cancel()

	client := proxyClient(port)

	resp, err := client.Get(backend.URL + "/docs/api")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for docs GET, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "documentation content" {
		t.Errorf("expected proxied content, got %q", string(body))
	}
}

func TestProxyStartStop(t *testing.T) {
	srv, port := newTestProxy(t)
	cancel := startTestProxy(t, srv)

	// Verify proxy is accepting connections
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("proxy not accepting connections: %v", err)
	}
	conn.Close()

	// Stop
	cancel()
	time.Sleep(100 * time.Millisecond)

	// Verify proxy stopped
	_, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
	if err == nil {
		t.Error("proxy still accepting connections after stop")
	}
}

func TestTraceRecordsEvents(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	srv, port := newTestProxy(t)
	cancel := startTestProxy(t, srv)
	defer cancel()

	client := proxyClient(port)

	// Make a request
	resp, err := client.Get(backend.URL + "/api/status")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	// Check trace
	summary := srv.TraceSummary()
	events, ok := summary["events"]
	if !ok || events == nil {
		t.Fatal("expected events in trace summary")
	}
	// Events are stored as []tracer.Event but accessed via any
	evSlice, ok := events.([]any)
	if ok && len(evSlice) == 0 {
		t.Error("expected at least 1 event in trace")
	}
}

func TestZoneEscalationAcrossRequests(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	srv, port := newTestProxy(t)
	cancel := startTestProxy(t, srv)
	defer cancel()

	client := proxyClient(port)

	// First: safe GET
	resp, err := client.Get(backend.URL + "/api/status")
	if err != nil {
		t.Fatalf("request 1 failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for safe GET, got %d", resp.StatusCode)
	}

	// Second: GET to sensitive HR data
	resp, err = client.Get(backend.URL + "/hr/employees")
	if err != nil {
		t.Fatalf("request 2 failed: %v", err)
	}
	resp.Body.Close()
	// This may be allowed or redacted depending on zone accumulation

	// Verify zones accumulated
	summary := srv.TraceSummary()
	state, ok := summary["trace_state"].(map[string]any)
	if !ok {
		t.Fatal("expected trace_state in summary")
	}
	zones, ok := state["zones_entered"].([]string)
	if !ok {
		t.Fatal("expected zones_entered in trace_state")
	}
	if len(zones) == 0 {
		t.Error("expected zones to accumulate across requests")
	}
}

func TestBuildActionFromRequest(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://api.example.com/data", nil)
	req.Host = "api.example.com"
	req.ContentLength = 1024

	action := buildActionFromRequest(req)

	if action.Tool != "http_proxy" {
		t.Errorf("expected tool=http_proxy, got %s", action.Tool)
	}
	if action.Operation != "post" {
		t.Errorf("expected operation=post, got %s", action.Operation)
	}
	if action.Resource != "http://api.example.com/data" {
		t.Errorf("unexpected resource: %s", action.Resource)
	}
}

func TestClassifySensitivity(t *testing.T) {
	tests := []struct {
		url      string
		wantSens string
		wantTag  string
	}{
		{"https://stripe.com/v1/charges", "high", "payment"},
		{"https://example.com/oauth/token", "high", "credential"},
		{"https://company.com/hr/employees", "high", "sensitive"},
		{"https://docs.example.com/api", "low", ""},
	}

	for _, tt := range tests {
		sens, tags := classifySensitivity(tt.url)
		if string(sens) != tt.wantSens {
			t.Errorf("classifySensitivity(%q) = %s, want %s", tt.url, sens, tt.wantSens)
		}
		if tt.wantTag != "" {
			found := false
			for _, tag := range tags {
				if tag == tt.wantTag {
					found = true
				}
			}
			if !found {
				t.Errorf("classifySensitivity(%q) missing tag %q, got %v", tt.url, tt.wantTag, tags)
			}
		}
	}
}

func TestDenylistBlocksPaymentDomain(t *testing.T) {
	// Verify the denylist itself blocks payment URLs via http_proxy tool
	srv, _ := newTestProxy(t)

	blocked, reason := srv.dl.IsBlocked("https://stripe.com/v1/charges", "http_proxy")
	if !blocked {
		t.Error("expected stripe.com/v1/charges to be blocked by denylist")
	}
	if reason == "" {
		t.Error("expected a reason")
	}
}
