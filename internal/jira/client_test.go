package jira

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	_ Creator = (*Client)(nil)
	_ Closer  = (*Client)(nil)
)

const (
	testToken    = "test-token"
	testProject  = "CHAIN"
	testAssignee = "nullbot"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()

	httpClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, r)

			resp := recorder.Result()
			resp.Request = r
			return resp, nil
		}),
	}

	return NewClient(ClientConfig{
		BaseURL:  "http://jira.test",
		Token:    testToken,
		Project:  testProject,
		Assignee: testAssignee,
		Client:   httpClient,
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func assertStandardHeaders(t *testing.T, r *http.Request) {
	t.Helper()

	if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
		t.Fatalf("Authorization header = %q, want %q", got, "Bearer "+testToken)
	}
	if got := r.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type header = %q, want %q", got, "application/json")
	}
	if got := r.Header.Get("Accept"); got != "application/json" {
		t.Fatalf("Accept header = %q, want %q", got, "application/json")
	}
}

func decodeJSONBody(t *testing.T, r *http.Request, dst any) {
	t.Helper()

	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
}

func TestCreateIssue(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want %s", r.Method, http.MethodPost)
		}
		if r.URL.Path != "/rest/api/2/issue" {
			t.Fatalf("path = %s, want %s", r.URL.Path, "/rest/api/2/issue")
		}
		assertStandardHeaders(t, r)

		var payload struct {
			Fields struct {
				Project struct {
					Key string `json:"key"`
				} `json:"project"`
				IssueType struct {
					Name string `json:"name"`
				} `json:"issuetype"`
				Summary     string `json:"summary"`
				Description string `json:"description"`
				Priority    struct {
					Name string `json:"name"`
				} `json:"priority"`
				Assignee struct {
					Name string `json:"name"`
				} `json:"assignee"`
				Labels []string `json:"labels"`
			} `json:"fields"`
		}
		decodeJSONBody(t, r, &payload)

		if payload.Fields.Project.Key != testProject {
			t.Fatalf("project key = %q, want %q", payload.Fields.Project.Key, testProject)
		}
		if payload.Fields.IssueType.Name != "Task" {
			t.Fatalf("issue type = %q, want %q", payload.Fields.IssueType.Name, "Task")
		}
		if payload.Fields.Summary != "Investigate high-risk finding" {
			t.Fatalf("summary = %q, want %q", payload.Fields.Summary, "Investigate high-risk finding")
		}
		if payload.Fields.Description != "Track remediation in JIRA" {
			t.Fatalf("description = %q, want %q", payload.Fields.Description, "Track remediation in JIRA")
		}
		if payload.Fields.Priority.Name != "Highest" {
			t.Fatalf("priority = %q, want %q", payload.Fields.Priority.Name, "Highest")
		}
		if payload.Fields.Assignee.Name != testAssignee {
			t.Fatalf("assignee = %q, want %q", payload.Fields.Assignee.Name, testAssignee)
		}

		wantLabels := []string{"nullbot", "automated", "triage", "security", "wo:wo-123"}
		if !reflect.DeepEqual(payload.Fields.Labels, wantLabels) {
			t.Fatalf("labels = %#v, want %#v", payload.Fields.Labels, wantLabels)
		}

		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(map[string]string{"key": "CHAIN-42"}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	})

	issue, err := client.CreateIssue(context.Background(), CreateIssueInput{
		Summary:     "Investigate high-risk finding",
		Description: "Track remediation in JIRA",
		Priority:    "Highest",
		Labels:      []string{"triage", "security"},
		WOID:        "wo-123",
	})
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}

	wantLabels := []string{"nullbot", "automated", "triage", "security", "wo:wo-123"}
	if issue.Key != "CHAIN-42" {
		t.Fatalf("issue key = %q, want %q", issue.Key, "CHAIN-42")
	}
	if issue.Summary != "Investigate high-risk finding" {
		t.Fatalf("summary = %q, want %q", issue.Summary, "Investigate high-risk finding")
	}
	if issue.Description != "Track remediation in JIRA" {
		t.Fatalf("description = %q, want %q", issue.Description, "Track remediation in JIRA")
	}
	if issue.Priority != "Highest" {
		t.Fatalf("priority = %q, want %q", issue.Priority, "Highest")
	}
	if issue.WOID != "wo-123" {
		t.Fatalf("WOID = %q, want %q", issue.WOID, "wo-123")
	}
	if !reflect.DeepEqual(issue.Labels, wantLabels) {
		t.Fatalf("labels = %#v, want %#v", issue.Labels, wantLabels)
	}
}

func TestCreateIssueHTTPError(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want %s", r.Method, http.MethodPost)
		}
		if r.URL.Path != "/rest/api/2/issue" {
			t.Fatalf("path = %s, want %s", r.URL.Path, "/rest/api/2/issue")
		}
		assertStandardHeaders(t, r)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid issue payload"))
	})

	_, err := client.CreateIssue(context.Background(), CreateIssueInput{
		Summary:  "broken",
		Priority: "High",
	})
	if err == nil {
		t.Fatal("CreateIssue error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "JIRA API POST /rest/api/2/issue: 400 invalid issue payload") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateIssueInvalidJSONResponse(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want %s", r.Method, http.MethodPost)
		}
		if r.URL.Path != "/rest/api/2/issue" {
			t.Fatalf("path = %s, want %s", r.URL.Path, "/rest/api/2/issue")
		}
		assertStandardHeaders(t, r)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"key"`))
	})

	_, err := client.CreateIssue(context.Background(), CreateIssueInput{
		Summary:  "invalid json",
		Priority: "High",
	})
	if err == nil {
		t.Fatal("CreateIssue error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "decode create issue response") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetIssue(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want %s", r.Method, http.MethodGet)
		}
		if r.URL.Path != "/rest/api/2/issue/CHAIN-42" {
			t.Fatalf("path = %s, want %s", r.URL.Path, "/rest/api/2/issue/CHAIN-42")
		}
		assertStandardHeaders(t, r)

		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"key": "CHAIN-42",
			"fields": map[string]any{
				"summary":     "Investigate high-risk finding",
				"description": "Track remediation in JIRA",
				"status":      map[string]string{"name": "In Progress"},
				"priority":    map[string]string{"name": "Highest"},
				"assignee":    map[string]string{"name": "alice"},
				"labels":      []string{"nullbot", "automated", "triage", "wo:wo-123"},
			},
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	})

	issue, err := client.GetIssue(context.Background(), "CHAIN-42")
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}

	if issue.Key != "CHAIN-42" {
		t.Fatalf("issue key = %q, want %q", issue.Key, "CHAIN-42")
	}
	if issue.Summary != "Investigate high-risk finding" {
		t.Fatalf("summary = %q, want %q", issue.Summary, "Investigate high-risk finding")
	}
	if issue.Description != "Track remediation in JIRA" {
		t.Fatalf("description = %q, want %q", issue.Description, "Track remediation in JIRA")
	}
	if issue.Status != "In Progress" {
		t.Fatalf("status = %q, want %q", issue.Status, "In Progress")
	}
	if issue.Priority != "Highest" {
		t.Fatalf("priority = %q, want %q", issue.Priority, "Highest")
	}
	if issue.Assignee != "alice" {
		t.Fatalf("assignee = %q, want %q", issue.Assignee, "alice")
	}
	if issue.WOID != "wo-123" {
		t.Fatalf("WOID = %q, want %q", issue.WOID, "wo-123")
	}

	wantLabels := []string{"nullbot", "automated", "triage", "wo:wo-123"}
	if !reflect.DeepEqual(issue.Labels, wantLabels) {
		t.Fatalf("labels = %#v, want %#v", issue.Labels, wantLabels)
	}
}

func TestGetIssueHTTPError(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want %s", r.Method, http.MethodGet)
		}
		if r.URL.Path != "/rest/api/2/issue/CHAIN-404" {
			t.Fatalf("path = %s, want %s", r.URL.Path, "/rest/api/2/issue/CHAIN-404")
		}
		assertStandardHeaders(t, r)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("issue not found"))
	})

	_, err := client.GetIssue(context.Background(), "CHAIN-404")
	if err == nil {
		t.Fatal("GetIssue error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "JIRA API GET /rest/api/2/issue/CHAIN-404: 404 issue not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetIssueInvalidJSONResponse(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want %s", r.Method, http.MethodGet)
		}
		if r.URL.Path != "/rest/api/2/issue/CHAIN-42" {
			t.Fatalf("path = %s, want %s", r.URL.Path, "/rest/api/2/issue/CHAIN-42")
		}
		assertStandardHeaders(t, r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"key":"CHAIN-42","fields":`))
	})

	_, err := client.GetIssue(context.Background(), "CHAIN-42")
	if err == nil {
		t.Fatal("GetIssue error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "decode get issue response") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddComment(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want %s", r.Method, http.MethodPost)
		}
		if r.URL.Path != "/rest/api/2/issue/CHAIN-42/comment" {
			t.Fatalf("path = %s, want %s", r.URL.Path, "/rest/api/2/issue/CHAIN-42/comment")
		}
		assertStandardHeaders(t, r)

		var payload struct {
			Body string `json:"body"`
		}
		decodeJSONBody(t, r, &payload)
		if payload.Body != "First automated comment" {
			t.Fatalf("body = %q, want %q", payload.Body, "First automated comment")
		}

		w.WriteHeader(http.StatusCreated)
	})

	if err := client.AddComment(context.Background(), "CHAIN-42", "First automated comment"); err != nil {
		t.Fatalf("AddComment: %v", err)
	}
}

func TestAddCommentHTTPError(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want %s", r.Method, http.MethodPost)
		}
		if r.URL.Path != "/rest/api/2/issue/CHAIN-42/comment" {
			t.Fatalf("path = %s, want %s", r.URL.Path, "/rest/api/2/issue/CHAIN-42/comment")
		}
		assertStandardHeaders(t, r)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("comment endpoint unavailable"))
	})

	err := client.AddComment(context.Background(), "CHAIN-42", "First automated comment")
	if err == nil {
		t.Fatal("AddComment error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "JIRA API POST /rest/api/2/issue/CHAIN-42/comment: 500 comment endpoint unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTransitionIssue(t *testing.T) {
	t.Parallel()

	var getCalls atomic.Int32
	var postCalls atomic.Int32

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assertStandardHeaders(t, r)

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/2/issue/CHAIN-42/transitions":
			getCalls.Add(1)
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(map[string]any{
				"transitions": []map[string]any{
					{
						"id":   "11",
						"name": "Start Progress",
						"to":   map[string]string{"name": "In Progress"},
					},
					{
						"id":   "31",
						"name": "Done",
						"to":   map[string]string{"name": "Done"},
					},
				},
			}); err != nil {
				t.Fatalf("encode response: %v", err)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/2/issue/CHAIN-42/transitions":
			postCalls.Add(1)

			var payload struct {
				Transition struct {
					ID string `json:"id"`
				} `json:"transition"`
			}
			decodeJSONBody(t, r, &payload)
			if payload.Transition.ID != "31" {
				t.Fatalf("transition id = %q, want %q", payload.Transition.ID, "31")
			}

			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	if err := client.TransitionIssue(context.Background(), "CHAIN-42", "done"); err != nil {
		t.Fatalf("TransitionIssue: %v", err)
	}

	if getCalls.Load() != 1 {
		t.Fatalf("transition GET calls = %d, want 1", getCalls.Load())
	}
	if postCalls.Load() != 1 {
		t.Fatalf("transition POST calls = %d, want 1", postCalls.Load())
	}
}

func TestTransitionIssueHTTPError(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assertStandardHeaders(t, r)

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/2/issue/CHAIN-42/transitions":
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(map[string]any{
				"transitions": []map[string]any{
					{
						"id":   "31",
						"name": "Done",
						"to":   map[string]string{"name": "Done"},
					},
				},
			}); err != nil {
				t.Fatalf("encode response: %v", err)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/2/issue/CHAIN-42/transitions":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("transition failed"))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	err := client.TransitionIssue(context.Background(), "CHAIN-42", "done")
	if err == nil {
		t.Fatal("TransitionIssue error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "JIRA API POST /rest/api/2/issue/CHAIN-42/transitions: 500 transition failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTransitionIssueInvalidJSONResponse(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want %s", r.Method, http.MethodGet)
		}
		if r.URL.Path != "/rest/api/2/issue/CHAIN-42/transitions" {
			t.Fatalf("path = %s, want %s", r.URL.Path, "/rest/api/2/issue/CHAIN-42/transitions")
		}
		assertStandardHeaders(t, r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"transitions":`))
	})

	err := client.TransitionIssue(context.Background(), "CHAIN-42", "done")
	if err == nil {
		t.Fatal("TransitionIssue error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "decode transitions") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTransitionIssueMissingTarget(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want %s", r.Method, http.MethodGet)
		}
		if r.URL.Path != "/rest/api/2/issue/CHAIN-42/transitions" {
			t.Fatalf("path = %s, want %s", r.URL.Path, "/rest/api/2/issue/CHAIN-42/transitions")
		}
		assertStandardHeaders(t, r)
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"transitions": []map[string]any{
				{
					"id":   "11",
					"name": "Start Progress",
					"to":   map[string]string{"name": "In Progress"},
				},
			},
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	})

	err := client.TransitionIssue(context.Background(), "CHAIN-42", "Done")
	if err == nil {
		t.Fatal("TransitionIssue error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), `no transition to "Done" found for CHAIN-42 (available: In Progress)`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientTimeout(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{
		Timeout: 50 * time.Millisecond,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s, want %s", r.Method, http.MethodGet)
			}
			if r.URL.Path != "/rest/api/2/issue/CHAIN-42" {
				t.Fatalf("path = %s, want %s", r.URL.Path, "/rest/api/2/issue/CHAIN-42")
			}
			assertStandardHeaders(t, r)
			<-r.Context().Done()
			return nil, r.Context().Err()
		}),
	}

	client := NewClient(ClientConfig{
		BaseURL:  "http://jira.test",
		Token:    testToken,
		Project:  testProject,
		Assignee: testAssignee,
		Client:   httpClient,
	})

	_, err := client.GetIssue(context.Background(), "CHAIN-42")
	if err == nil {
		t.Fatal("GetIssue error = nil, want non-nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "Client.Timeout exceeded") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestMapPriority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		severity    string
		priorityMap map[string]string
		want        string
	}{
		{
			name:        "override critical with configured value",
			severity:    "critical",
			priorityMap: map[string]string{"critical": "Blocker"},
			want:        "Blocker",
		},
		{
			name:        "use default when key missing",
			severity:    "low",
			priorityMap: map[string]string{"critical": "Highest"},
			want:        "Low",
		},
		{
			name:        "use defaults with nil map",
			severity:    "high",
			priorityMap: nil,
			want:        "High",
		},
		{
			name:        "fallback unknown severity to medium",
			severity:    "informational",
			priorityMap: map[string]string{"critical": "Highest"},
			want:        "Medium",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := MapPriority(tt.severity, tt.priorityMap); got != tt.want {
				t.Fatalf("MapPriority(%q, %v) = %q, want %q", tt.severity, tt.priorityMap, got, tt.want)
			}
		})
	}
}
