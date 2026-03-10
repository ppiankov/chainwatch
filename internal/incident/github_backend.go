package incident

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// GitHubConfig holds configuration for GitHub issue creation.
type GitHubConfig struct {
	Owner      string
	Repo       string
	Token      string
	BaseURL    string // defaults to https://api.github.com
	HTTPClient *http.Client
}

// GitHubBackend creates incidents as GitHub issues.
type GitHubBackend struct {
	cfg GitHubConfig
}

// NewGitHubBackend returns a backend that creates GitHub issues.
func NewGitHubBackend(cfg GitHubConfig) *GitHubBackend {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.github.com"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &GitHubBackend{cfg: cfg}
}

func (b *GitHubBackend) Name() string { return "github" }

type ghIssueRequest struct {
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Labels []string `json:"labels"`
}

type ghIssueResponse struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
}

func (b *GitHubBackend) Create(ctx context.Context, input CreateInput) (*Incident, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/issues", b.cfg.BaseURL, b.cfg.Owner, b.cfg.Repo)

	body, err := json.Marshal(ghIssueRequest{
		Title:  input.Title,
		Body:   input.Body,
		Labels: input.Labels,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("github returned %d", resp.StatusCode)
	}

	var result ghIssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &Incident{
		Source:    "github",
		Key:       fmt.Sprintf("%d", result.Number),
		URL:       result.HTMLURL,
		CreatedAt: time.Now(),
	}, nil
}
