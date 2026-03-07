package jira

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// createIssue performs the JIRA REST API call to create an issue.
func createIssue(c *Client, ctx context.Context, input CreateIssueInput) (*Issue, error) {
	labels := make([]string, 0, len(input.Labels)+2)
	labels = append(labels, "nullbot", "automated")
	labels = append(labels, input.Labels...)
	if input.WOID != "" {
		labels = append(labels, "wo:"+input.WOID)
	}

	body := map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": c.project},
			"issuetype":   map[string]string{"name": "Task"},
			"summary":     input.Summary,
			"description": input.Description,
			"priority":    map[string]string{"name": input.Priority},
			"labels":      labels,
		},
	}

	if input.Assignee != "" {
		body["fields"].(map[string]any)["assignee"] = map[string]string{"name": input.Assignee}
	} else if c.assignee != "" {
		body["fields"].(map[string]any)["assignee"] = map[string]string{"name": c.assignee}
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal create issue body: %w", err)
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/rest/api/2/issue", data)
	if err != nil {
		return nil, fmt.Errorf("create issue request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, readError(resp)
	}

	var result struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode create issue response: %w", err)
	}

	return &Issue{
		Key:         result.Key,
		Summary:     input.Summary,
		Description: input.Description,
		Priority:    input.Priority,
		Labels:      labels,
		WOID:        input.WOID,
	}, nil
}

// getIssue retrieves a JIRA issue by key.
func getIssue(c *Client, ctx context.Context, issueKey string) (*Issue, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/rest/api/2/issue/"+issueKey, nil)
	if err != nil {
		return nil, fmt.Errorf("get issue request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readError(resp)
	}

	var raw struct {
		Key    string `json:"key"`
		Fields struct {
			Summary     string `json:"summary"`
			Description string `json:"description"`
			Status      struct {
				Name string `json:"name"`
			} `json:"status"`
			Priority struct {
				Name string `json:"name"`
			} `json:"priority"`
			Assignee *struct {
				Name string `json:"name"`
			} `json:"assignee"`
			Labels []string `json:"labels"`
		} `json:"fields"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode get issue response: %w", err)
	}

	issue := &Issue{
		Key:         raw.Key,
		Summary:     raw.Fields.Summary,
		Description: raw.Fields.Description,
		Status:      raw.Fields.Status.Name,
		Priority:    raw.Fields.Priority.Name,
		Labels:      raw.Fields.Labels,
	}
	if raw.Fields.Assignee != nil {
		issue.Assignee = raw.Fields.Assignee.Name
	}
	// Extract WO ID from labels.
	for _, l := range raw.Fields.Labels {
		if strings.HasPrefix(l, "wo:") {
			issue.WOID = strings.TrimPrefix(l, "wo:")
			break
		}
	}
	return issue, nil
}

// addComment adds a comment to a JIRA issue.
func addComment(c *Client, ctx context.Context, issueKey, body string) error {
	data, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return fmt.Errorf("marshal comment body: %w", err)
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/rest/api/2/issue/"+issueKey+"/comment", data)
	if err != nil {
		return fmt.Errorf("add comment request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return readError(resp)
	}
	return nil
}

// transitionIssue transitions a JIRA issue to the target status name.
func transitionIssue(c *Client, ctx context.Context, issueKey, targetStatus string) error {
	// First, get available transitions.
	resp, err := c.doRequest(ctx, http.MethodGet, "/rest/api/2/issue/"+issueKey+"/transitions", nil)
	if err != nil {
		return fmt.Errorf("get transitions request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return readError(resp)
	}

	var transitions struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			To   struct {
				Name string `json:"name"`
			} `json:"to"`
		} `json:"transitions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&transitions); err != nil {
		return fmt.Errorf("decode transitions: %w", err)
	}

	// Find matching transition.
	target := strings.ToLower(targetStatus)
	for _, t := range transitions.Transitions {
		if strings.ToLower(t.To.Name) == target || strings.ToLower(t.Name) == target {
			data, err := json.Marshal(map[string]any{
				"transition": map[string]string{"id": t.ID},
			})
			if err != nil {
				return fmt.Errorf("marshal transition body: %w", err)
			}

			resp2, err := c.doRequest(ctx, http.MethodPost, "/rest/api/2/issue/"+issueKey+"/transitions", data)
			if err != nil {
				return fmt.Errorf("transition request: %w", err)
			}
			defer resp2.Body.Close()

			if resp2.StatusCode != http.StatusNoContent && resp2.StatusCode != http.StatusOK {
				return readError(resp2)
			}
			return nil
		}
	}

	available := make([]string, 0, len(transitions.Transitions))
	for _, t := range transitions.Transitions {
		available = append(available, t.To.Name)
	}
	return fmt.Errorf("no transition to %q found for %s (available: %s)", targetStatus, issueKey, strings.Join(available, ", "))
}

// doRequest performs an authenticated HTTP request to the JIRA API.
func (c *Client) doRequest(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	url := strings.TrimRight(c.baseURL, "/") + path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return c.httpClient.Do(req)
}

// readError extracts an error message from a non-success HTTP response.
func readError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("JIRA API %s %s: %d %s", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, string(body))
}
