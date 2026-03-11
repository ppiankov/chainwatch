package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestCreatePR(t *testing.T) {
	t.Setenv(envChainwatchGitHubToken, "")
	t.Setenv(envGitHubToken, "")

	type requestRecord struct {
		Method string
		Path   string
		Auth   string
		Accept string
		Type   string
		Body   []byte
	}

	var mu sync.Mutex
	records := make([]requestRecord, 0, 2)
	var unexpectedPath string
	client := newMockHTTPClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = r.Body.Close()

		mu.Lock()
		records = append(records, requestRecord{
			Method: r.Method,
			Path:   r.URL.Path,
			Auth:   r.Header.Get("Authorization"),
			Accept: r.Header.Get("Accept"),
			Type:   r.Header.Get("Content-Type"),
			Body:   body,
		})
		mu.Unlock()

		switch r.URL.Path {
		case "/repos/test-owner/test-repo/pulls":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"number":42,"html_url":"https://github.com/test-owner/test-repo/pull/42","state":"open"}`))
		case "/repos/test-owner/test-repo/issues/42/labels":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		default:
			mu.Lock()
			unexpectedPath = r.URL.Path
			mu.Unlock()
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	prClient := NewGitHubPRClient(GitHubConfig{
		Owner:      "test-owner",
		Repo:       "test-repo",
		Token:      "cfg-token",
		BaseURL:    "https://api.github.test",
		HTTPClient: client,
	})

	pr, err := prClient.CreatePR(context.Background(), CreatePRInput{
		Head:   "chainwatch/WO-001",
		Base:   "main",
		Title:  "[chainwatch] Fix drift (WO-001)",
		Body:   "Apply remediation safely.",
		Labels: []string{"chainwatch", "auto-dispatched", "terraform"},
		Draft:  true,
	})
	if err != nil {
		t.Fatalf("CreatePR returned error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if unexpectedPath != "" {
		t.Fatalf("unexpected request path: %s", unexpectedPath)
	}
	if pr.Number != 42 {
		t.Fatalf("PR number = %d, want 42", pr.Number)
	}
	if pr.URL != "https://github.com/test-owner/test-repo/pull/42" {
		t.Fatalf("PR URL = %q, want GitHub PR URL", pr.URL)
	}
	if pr.State != "open" {
		t.Fatalf("PR state = %q, want %q", pr.State, "open")
	}
	if len(records) != 2 {
		t.Fatalf("request count = %d, want 2", len(records))
	}

	createReq := records[0]
	if createReq.Method != http.MethodPost {
		t.Fatalf("create request method = %q, want POST", createReq.Method)
	}
	if createReq.Path != "/repos/test-owner/test-repo/pulls" {
		t.Fatalf("create request path = %q, want pulls path", createReq.Path)
	}
	if createReq.Auth != "Bearer cfg-token" {
		t.Fatalf("create request auth = %q, want bearer token", createReq.Auth)
	}
	if createReq.Accept != "application/vnd.github+json" {
		t.Fatalf("create request accept = %q, want GitHub accept header", createReq.Accept)
	}
	if createReq.Type != "application/json" {
		t.Fatalf("create request content-type = %q, want application/json", createReq.Type)
	}

	var createBody map[string]any
	if err := json.Unmarshal(createReq.Body, &createBody); err != nil {
		t.Fatalf("unmarshal create request body: %v", err)
	}
	if createBody["head"] != "chainwatch/WO-001" {
		t.Fatalf("head = %#v, want branch name", createBody["head"])
	}
	if createBody["base"] != "main" {
		t.Fatalf("base = %#v, want main", createBody["base"])
	}
	if createBody["title"] != "[chainwatch] Fix drift (WO-001)" {
		t.Fatalf("title = %#v, want PR title", createBody["title"])
	}
	if createBody["body"] != "Apply remediation safely." {
		t.Fatalf("body = %#v, want prompt body", createBody["body"])
	}
	if createBody["draft"] != true {
		t.Fatalf("draft = %#v, want true", createBody["draft"])
	}

	labelReq := records[1]
	if labelReq.Path != "/repos/test-owner/test-repo/issues/42/labels" {
		t.Fatalf("label request path = %q, want labels path", labelReq.Path)
	}
	if labelReq.Auth != "Bearer cfg-token" {
		t.Fatalf("label request auth = %q, want bearer token", labelReq.Auth)
	}

	var labelBody map[string][]string
	if err := json.Unmarshal(labelReq.Body, &labelBody); err != nil {
		t.Fatalf("unmarshal label request body: %v", err)
	}
	wantLabels := []string{"chainwatch", "auto-dispatched", "terraform"}
	if got := strings.Join(labelBody["labels"], ","); got != strings.Join(wantLabels, ",") {
		t.Fatalf("labels = %v, want %v", labelBody["labels"], wantLabels)
	}
}

func TestCreatePRError(t *testing.T) {
	t.Setenv(envChainwatchGitHubToken, "")
	t.Setenv(envGitHubToken, "")

	client := newMockHTTPClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Validation Failed"}`))
	}))

	prClient := NewGitHubPRClient(GitHubConfig{
		Owner:      "test-owner",
		Repo:       "test-repo",
		Token:      "cfg-token",
		BaseURL:    "https://api.github.test",
		HTTPClient: client,
	})

	pr, err := prClient.CreatePR(context.Background(), CreatePRInput{
		Head:  "chainwatch/WO-002",
		Base:  "main",
		Title: "[chainwatch] Invalid PR (WO-002)",
	})
	if err == nil {
		t.Fatal("CreatePR error = nil, want non-nil")
	}
	if pr != nil {
		t.Fatalf("PR = %#v, want nil on create failure", pr)
	}
	if !strings.Contains(err.Error(), "github returned 422") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "Validation Failed") {
		t.Fatalf("expected API message in error, got: %v", err)
	}
}

func TestCreatePRTokenResolution(t *testing.T) {
	t.Run("chainwatch token wins", func(t *testing.T) {
		t.Setenv(envChainwatchGitHubToken, "chainwatch-token")
		t.Setenv(envGitHubToken, "github-token")
		assertTokenUsed(t, "config-token", "chainwatch-token")
	})

	t.Run("github token falls back", func(t *testing.T) {
		t.Setenv(envChainwatchGitHubToken, "")
		t.Setenv(envGitHubToken, "github-token")
		assertTokenUsed(t, "config-token", "github-token")
	})

	t.Run("config token last fallback", func(t *testing.T) {
		t.Setenv(envChainwatchGitHubToken, "")
		t.Setenv(envGitHubToken, "")
		assertTokenUsed(t, "config-token", "config-token")
	})
}

func TestPRURLFormat(t *testing.T) {
	client := NewGitHubPRClient(GitHubConfig{
		Owner:   "test-owner",
		Repo:    "test-repo",
		Token:   "cfg-token",
		BaseURL: "https://github.example.com/api/v3/",
	})

	if got := client.prURL(17, ""); got != "https://github.example.com/test-owner/test-repo/pull/17" {
		t.Fatalf("prURL = %q, want enterprise GitHub web URL", got)
	}
	if got := client.pullsURL(); got != "https://github.example.com/api/v3/repos/test-owner/test-repo/pulls" {
		t.Fatalf("pullsURL = %q, want API pulls URL", got)
	}
}

func assertTokenUsed(t *testing.T, configToken string, wantToken string) {
	t.Helper()

	var mu sync.Mutex
	var authHeader string
	client := newMockHTTPClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authHeader = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":5,"state":"open"}`))
	}))

	prClient := NewGitHubPRClient(GitHubConfig{
		Owner:      "test-owner",
		Repo:       "test-repo",
		Token:      configToken,
		BaseURL:    "https://api.github.test",
		HTTPClient: client,
	})

	pr, err := prClient.CreatePR(context.Background(), CreatePRInput{
		Head:  "chainwatch/WO-003",
		Base:  "main",
		Title: "[chainwatch] Token test (WO-003)",
	})
	if err != nil {
		t.Fatalf("CreatePR returned error: %v", err)
	}
	if pr == nil {
		t.Fatal("PR = nil, want created PR")
	}
	mu.Lock()
	defer mu.Unlock()
	if authHeader != "Bearer "+wantToken {
		t.Fatalf("Authorization = %q, want %q", authHeader, "Bearer "+wantToken)
	}
}

func newMockHTTPClient(handler http.Handler) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			return recorder.Result(), nil
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
