package chainwatch

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

// Middleware returns an http.Handler that evaluates chainwatch policy
// on each request before passing to the next handler.
// Blocked requests receive a 403 with a JSON body.
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := actionFromRequest(r)
		result := c.Check(action)

		if result.Decision == Deny || result.Decision == RequireApproval {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{
				"blocked":      true,
				"decision":     string(result.Decision),
				"reason":       result.Reason,
				"policy_id":    result.PolicyID,
				"approval_key": result.ApprovalKey,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// actionFromRequest maps an HTTP request to an SDK Action.
func actionFromRequest(r *http.Request) Action {
	resource := r.URL.String()
	if r.URL.Host == "" && r.Host != "" {
		resource = r.Host + r.URL.RequestURI()
	}

	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	egress := "external"
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		egress = "internal"
	}

	contentLength := 0
	if r.ContentLength > 0 {
		contentLength = int(r.ContentLength)
	}

	return Action{
		Tool:      "http",
		Resource:  resource,
		Operation: strings.ToLower(r.Method),
		Meta: map[string]any{
			"sensitivity": "low",
			"egress":      egress,
			"destination": host,
			"bytes":       contentLength,
			"rows":        0,
			"tags":        []any{},
		},
	}
}
