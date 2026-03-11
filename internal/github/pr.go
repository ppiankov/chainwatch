package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGitHubBaseURL     = "https://api.github.com"
	defaultGitHubWebBaseURL  = "https://github.com"
	defaultGitHubHTTPTimeout = 30 * time.Second
	maxGitHubErrorBodyBytes  = 4 * 1024

	envChainwatchGitHubToken = "CHAINWATCH_GITHUB_TOKEN"
	envGitHubToken           = "GITHUB_TOKEN"
)

// PRCreator creates pull requests for one repository.
type PRCreator interface {
	CreatePR(ctx context.Context, input CreatePRInput) (*PR, error)
}

// CreatePRInput describes one PR to create.
type CreatePRInput struct {
	Head   string
	Base   string
	Title  string
	Body   string
	Labels []string
	Draft  bool
}

// PR is the created pull request metadata relevant to orchestrator state.
type PR struct {
	Number int
	URL    string
	State  string
}

// GitHubConfig holds configuration for GitHub PR creation.
type GitHubConfig struct {
	Owner      string
	Repo       string
	Token      string
	BaseURL    string
	HTTPClient *http.Client
}

// GitHubPRClient creates pull requests through the GitHub REST API.
type GitHubPRClient struct {
	owner      string
	repo       string
	token      string
	baseURL    string
	httpClient *http.Client
}

type createPRRequest struct {
	Head  string `json:"head"`
	Base  string `json:"base"`
	Title string `json:"title"`
	Body  string `json:"body"`
	Draft bool   `json:"draft"`
}

type createPRResponse struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
}

type createLabelsRequest struct {
	Labels []string `json:"labels"`
}

type apiErrorResponse struct {
	Message string `json:"message"`
}

// NewGitHubPRClient creates a PR client for one repository.
func NewGitHubPRClient(cfg GitHubConfig) *GitHubPRClient {
	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		baseURL = defaultGitHubBaseURL
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultGitHubHTTPTimeout}
	}

	return &GitHubPRClient{
		owner:      strings.TrimSpace(cfg.Owner),
		repo:       strings.TrimSpace(cfg.Repo),
		token:      resolveToken(cfg.Token),
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

// CreatePR opens a draft or ready pull request and optionally applies labels.
func (c *GitHubPRClient) CreatePR(ctx context.Context, input CreatePRInput) (*PR, error) {
	if c == nil {
		return nil, fmt.Errorf("github PR client is nil")
	}
	if strings.TrimSpace(c.owner) == "" || strings.TrimSpace(c.repo) == "" {
		return nil, fmt.Errorf("github owner and repo are required")
	}
	if strings.TrimSpace(c.token) == "" {
		return nil, fmt.Errorf("github token is required")
	}

	body, err := json.Marshal(createPRRequest{
		Head:  strings.TrimSpace(input.Head),
		Base:  strings.TrimSpace(input.Base),
		Title: strings.TrimSpace(input.Title),
		Body:  input.Body,
		Draft: input.Draft,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal create PR request: %w", err)
	}

	resp, err := c.doRequest(ctx, http.MethodPost, c.pullsURL(), body)
	if err != nil {
		return nil, fmt.Errorf("create PR request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusCreated {
		return nil, decodeAPIError(resp)
	}

	var raw createPRResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode create PR response: %w", err)
	}

	pr := &PR{
		Number: raw.Number,
		URL:    c.prURL(raw.Number, raw.HTMLURL),
		State:  strings.TrimSpace(raw.State),
	}

	labels := trimNonEmpty(input.Labels)
	if len(labels) == 0 {
		return pr, nil
	}

	if err := c.applyLabels(ctx, pr.Number, labels); err != nil {
		return pr, fmt.Errorf("apply labels to PR #%d: %w", pr.Number, err)
	}

	return pr, nil
}

func (c *GitHubPRClient) applyLabels(ctx context.Context, number int, labels []string) error {
	body, err := json.Marshal(createLabelsRequest{Labels: labels})
	if err != nil {
		return fmt.Errorf("marshal labels request: %w", err)
	}

	resp, err := c.doRequest(ctx, http.MethodPost, c.labelsURL(number), body)
	if err != nil {
		return fmt.Errorf("label request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return decodeAPIError(resp)
	}
	return nil
}

func (c *GitHubPRClient) doRequest(
	ctx context.Context,
	method string,
	target string,
	body []byte,
) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *GitHubPRClient) pullsURL() string {
	return c.repoAPIURL("pulls")
}

func (c *GitHubPRClient) labelsURL(number int) string {
	return c.repoAPIURL("issues", strconv.Itoa(number), "labels")
}

func (c *GitHubPRClient) repoAPIURL(parts ...string) string {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return c.baseURL + "/repos/" + c.owner + "/" + c.repo + "/" + strings.Join(parts, "/")
	}

	allParts := []string{"/", base.Path, "repos", c.owner, c.repo}
	allParts = append(allParts, parts...)
	base.Path = path.Join(allParts...)
	return base.String()
}

func (c *GitHubPRClient) prURL(number int, htmlURL string) string {
	if trimmed := strings.TrimSpace(htmlURL); trimmed != "" {
		return trimmed
	}

	webBase := c.webBaseURL()
	return strings.TrimRight(webBase, "/") + "/" + c.owner + "/" + c.repo + "/pull/" + strconv.Itoa(number)
}

func (c *GitHubPRClient) webBaseURL() string {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return defaultGitHubWebBaseURL
	}

	if strings.EqualFold(base.Host, "api.github.com") {
		return defaultGitHubWebBaseURL
	}

	cleanPath := strings.TrimRight(base.Path, "/")
	switch {
	case strings.HasSuffix(cleanPath, "/api/v3"):
		cleanPath = strings.TrimSuffix(cleanPath, "/api/v3")
	case strings.HasSuffix(cleanPath, "/api"):
		cleanPath = strings.TrimSuffix(cleanPath, "/api")
	}
	base.Path = cleanPath
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""

	if strings.TrimSpace(base.Path) == "" {
		return strings.TrimRight(base.Scheme+"://"+base.Host, "/")
	}
	return strings.TrimRight(base.String(), "/")
}

func resolveToken(configToken string) string {
	candidates := []string{
		os.Getenv(envChainwatchGitHubToken),
		os.Getenv(envGitHubToken),
		configToken,
	}

	for _, candidate := range candidates {
		if token := strings.TrimSpace(candidate); token != "" {
			return token
		}
	}
	return ""
}

func decodeAPIError(resp *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGitHubErrorBodyBytes))
	if err != nil {
		return fmt.Errorf("github returned %d", resp.StatusCode)
	}

	var payload apiErrorResponse
	if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Message) != "" {
		return fmt.Errorf("github returned %d: %s", resp.StatusCode, payload.Message)
	}

	trimmedBody := strings.TrimSpace(string(body))
	if trimmedBody == "" {
		return fmt.Errorf("github returned %d", resp.StatusCode)
	}
	return fmt.Errorf("github returned %d: %s", resp.StatusCode, trimmedBody)
}

func trimNonEmpty(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	trimmed := make([]string, 0, len(values))
	for _, value := range values {
		if item := strings.TrimSpace(value); item != "" {
			trimmed = append(trimmed, item)
		}
	}
	if len(trimmed) == 0 {
		return nil
	}
	return trimmed
}
