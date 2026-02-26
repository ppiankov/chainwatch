package observe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ppiankov/chainwatch/internal/wo"
)

func TestParseClassificationWrapped(t *testing.T) {
	raw := `{"observations":[
		{"type":"suspicious_code","detail":"eval(base64_decode found","severity":"high"},
		{"type":"unauthorized_user","detail":"rogue UID 0 user wpadmin2","severity":"critical"}
	]}`

	obs, err := parseClassification(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(obs))
	}
	if obs[0].Type != wo.SuspiciousCode {
		t.Errorf("obs[0] type: got %s, want suspicious_code", obs[0].Type)
	}
	if obs[1].Severity != wo.SeverityCritical {
		t.Errorf("obs[1] severity: got %s, want critical", obs[1].Severity)
	}
}

func TestParseClassificationRawArray(t *testing.T) {
	raw := `[
		{"type":"cron_anomaly","detail":"wget beacon in crontab","severity":"high"},
		{"type":"process_anomaly","detail":"nc listening on port 4444","severity":"critical"}
	]`

	obs, err := parseClassification(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(obs))
	}
	if obs[0].Type != wo.CronAnomaly {
		t.Errorf("obs[0] type: got %s, want cron_anomaly", obs[0].Type)
	}
}

func TestParseClassificationMarkdownFenced(t *testing.T) {
	raw := "```json\n{\"observations\":[{\"type\":\"unknown_file\",\"detail\":\"shell.php in uploads\",\"severity\":\"high\"}]}\n```"

	obs, err := parseClassification(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Type != wo.UnknownFile {
		t.Errorf("type: got %s, want unknown_file", obs[0].Type)
	}
}

func TestParseClassificationEmpty(t *testing.T) {
	raw := `{"observations":[]}`
	obs, err := parseClassification(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("expected 0 observations, got %d", len(obs))
	}
}

func TestParseClassificationInvalid(t *testing.T) {
	_, err := parseClassification("this is not json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseClassificationAllTypes(t *testing.T) {
	types := []string{
		"file_hash_mismatch", "redirect_detected", "unauthorized_user",
		"suspicious_code", "config_modified", "unknown_file",
		"permission_anomaly", "cron_anomaly", "process_anomaly", "network_anomaly",
	}

	for _, typ := range types {
		raw := `{"observations":[{"type":"` + typ + `","detail":"test","severity":"medium"}]}`
		obs, err := parseClassification(raw)
		if err != nil {
			t.Errorf("parse failed for type %s: %v", typ, err)
			continue
		}
		if len(obs) != 1 {
			t.Errorf("type %s: expected 1 observation, got %d", typ, len(obs))
			continue
		}
		if string(obs[0].Type) != typ {
			t.Errorf("type mismatch: got %s, want %s", obs[0].Type, typ)
		}
	}
}

func TestCleanJSON(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{`{"a":1}`, `{"a":1}`},
		{"```json\n{\"a\":1}\n```", `{"a":1}`},
		{"```\n{\"a\":1}\n```", `{"a":1}`},
		{"  \n{\"a\":1}\n  ", `{"a":1}`},
	}
	for _, c := range cases {
		got := cleanJSON(c.input)
		if got != c.want {
			t.Errorf("cleanJSON(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("short string: got %q", got)
	}
	if got := truncate("hello world", 5); got != "hello..." {
		t.Errorf("long string: got %q", got)
	}
}

// newClassifyServer returns a test server that responds with valid classification JSON.
func newClassifyServer(t *testing.T, label string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := fmt.Sprintf(`{"choices":[{"message":{"content":"{\"observations\":[{\"type\":\"unknown_file\",\"detail\":\"%s\",\"severity\":\"low\"}]}"}}]}`, label)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(resp))
	}))
}

// newFailServer returns a test server that always returns 500.
func newFailServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "fail"})
	}))
}

func TestIsLocalProvider(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://localhost:11434/v1", true},
		{"http://127.0.0.1:11434/v1", true},
		{"http://LOCALHOST:8080/v1", true},
		{"https://api.openai.com/v1", false},
		{"https://api.anthropic.com/v1", false},
		{"http://10.0.0.5:11434/v1", false},
	}
	for _, tt := range tests {
		got := isLocalProvider(LLMProvider{URL: tt.url})
		if got != tt.want {
			t.Errorf("isLocalProvider(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestClassifyPoolRotation(t *testing.T) {
	// Reset counter for deterministic test.
	atomic.StoreUint64(&poolCounter, 0)

	srv1 := newClassifyServer(t, "server1")
	defer srv1.Close()
	srv2 := newClassifyServer(t, "server2")
	defer srv2.Close()

	pool := []LLMProvider{
		{URL: srv1.URL, Key: "k1", Model: "m1"},
		{URL: srv2.URL, Key: "k2", Model: "m2"},
	}

	// Call twice — should hit different servers due to round-robin.
	obs1, err := Classify(ClassifierConfig{Pool: pool}, "test evidence 1")
	if err != nil {
		t.Fatalf("classify 1: %v", err)
	}
	obs2, err := Classify(ClassifierConfig{Pool: pool}, "test evidence 2")
	if err != nil {
		t.Fatalf("classify 2: %v", err)
	}

	// Both should return valid observations.
	if len(obs1) != 1 || len(obs2) != 1 {
		t.Fatalf("expected 1 obs each, got %d and %d", len(obs1), len(obs2))
	}

	// Details should differ (server1 vs server2) proving rotation.
	if obs1[0].Detail == obs2[0].Detail {
		t.Errorf("pool rotation did not distribute: both returned %q", obs1[0].Detail)
	}
}

func TestClassifyPoolFailover(t *testing.T) {
	atomic.StoreUint64(&poolCounter, 0)

	fail := newFailServer(t)
	defer fail.Close()
	good := newClassifyServer(t, "good-server")
	defer good.Close()

	pool := []LLMProvider{
		{URL: fail.URL, Key: "k1", Model: "m1"},
		{URL: good.URL, Key: "k2", Model: "m2"},
	}

	obs, err := Classify(ClassifierConfig{Pool: pool}, "test evidence")
	if err != nil {
		t.Fatalf("classify should succeed via failover: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Detail != "good-server" {
		t.Errorf("expected good-server detail, got %q", obs[0].Detail)
	}
}

func TestClassifyEmptyPoolLegacy(t *testing.T) {
	srv := newClassifyServer(t, "primary")
	defer srv.Close()

	// Empty Pool — should use primary APIURL.
	obs, err := Classify(ClassifierConfig{
		APIURL: srv.URL,
		APIKey: "key",
		Model:  "model",
	}, "test evidence")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if len(obs) != 1 || obs[0].Detail != "primary" {
		t.Errorf("expected primary, got %v", obs)
	}
}

func TestClassifySensitivityLocalFilters(t *testing.T) {
	atomic.StoreUint64(&poolCounter, 0)

	local := newClassifyServer(t, "local-result")
	defer local.Close()

	// Cloud provider has an unreachable URL — filtered by sensitivity before connection.
	pool := []LLMProvider{
		{URL: "https://api.cloud.example.com/v1", Key: "k1", Model: "m1"},
		{URL: local.URL, Key: "k2", Model: "m2"}, // 127.0.0.1 → passes isLocalProvider
	}

	obs, err := Classify(ClassifierConfig{
		Pool:        pool,
		Sensitivity: "local",
	}, "test evidence")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Detail != "local-result" {
		t.Errorf("expected local-result, got %q — sensitivity filter did not exclude cloud", obs[0].Detail)
	}
}

func TestClassifySensitivityLocalNoProviders(t *testing.T) {
	atomic.StoreUint64(&poolCounter, 0)

	// Only cloud URLs — no localhost providers at all.
	pool := []LLMProvider{
		{URL: "https://api.openai.com/v1", Key: "k1", Model: "m1"},
		{URL: "https://api.anthropic.com/v1", Key: "k2", Model: "m2"},
	}

	_, err := Classify(ClassifierConfig{
		Pool:        pool,
		Sensitivity: "local",
	}, "test evidence")
	if err == nil {
		t.Fatal("expected error when sensitivity=local but no localhost providers")
	}
	if got := err.Error(); got != "sensitivity=local but no localhost providers available" {
		t.Errorf("unexpected error: %s", got)
	}
}
