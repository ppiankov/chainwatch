package chainwatch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddlewareAllows(t *testing.T) {
	c := newTestClient(t)
	handler := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/safe/path", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("expected body 'ok', got %q", rec.Body.String())
	}
}

func TestMiddlewareBlocksDenied(t *testing.T) {
	c := newTestClient(t)
	handler := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	req := httptest.NewRequest("POST", "https://stripe.com/v1/charges", nil)
	req.Host = "stripe.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestMiddlewareJSONBody(t *testing.T) {
	c := newTestClient(t)
	handler := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	req := httptest.NewRequest("POST", "https://stripe.com/v1/charges", nil)
	req.Host = "stripe.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}
	if blocked, ok := body["blocked"].(bool); !ok || !blocked {
		t.Error("expected blocked=true in response")
	}
	if _, ok := body["decision"].(string); !ok {
		t.Error("expected decision string in response")
	}
	if _, ok := body["reason"].(string); !ok {
		t.Error("expected reason string in response")
	}
}
