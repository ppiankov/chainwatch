package bedrockruntime

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// ServiceID matches the Bedrock Runtime service identifier used by endpoint
// resolvers in the real AWS SDK.
const ServiceID = "bedrock-runtime"

// Options carries per-call options. The adapter does not currently use them.
type Options struct{}

// InvokeModelInput holds the request payload for a Bedrock model invocation.
type InvokeModelInput struct {
	Accept      *string
	Body        []byte
	ContentType *string
	ModelId     *string
}

// InvokeModelOutput holds the raw response payload from a Bedrock invocation.
type InvokeModelOutput struct {
	Body        []byte
	ContentType *string
}

// Client is a minimal Bedrock Runtime client.
type Client struct {
	cfg config.Config
}

// NewFromConfig constructs a client from shared configuration.
func NewFromConfig(cfg config.Config) *Client {
	return &Client{cfg: cfg}
}

// InvokeModel posts the request body to the resolved Bedrock invoke endpoint.
func (c *Client) InvokeModel(
	ctx context.Context,
	params *InvokeModelInput,
	_ ...func(*Options),
) (*InvokeModelOutput, error) {
	if params == nil {
		return nil, fmt.Errorf("InvokeModelInput is required")
	}
	if params.ModelId == nil || strings.TrimSpace(*params.ModelId) == "" {
		return nil, fmt.Errorf("InvokeModelInput.ModelId is required")
	}

	endpoint, err := c.resolveEndpoint()
	if err != nil {
		return nil, err
	}

	invokeURL := strings.TrimRight(endpoint.URL, "/") + "/model/" +
		url.PathEscape(*params.ModelId) + "/invoke"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, invokeURL, bytes.NewReader(params.Body))
	if err != nil {
		return nil, fmt.Errorf("create InvokeModel request: %w", err)
	}

	if params.Accept != nil {
		req.Header.Set("Accept", *params.Accept)
	}
	if params.ContentType != nil {
		req.Header.Set("Content-Type", *params.ContentType)
	}

	client := c.cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("invoke Bedrock endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read InvokeModel response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("bedrock runtime returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}

	return &InvokeModelOutput{
		Body:        body,
		ContentType: aws.String(contentType),
	}, nil
}

func (c *Client) resolveEndpoint() (aws.Endpoint, error) {
	region := c.cfg.Region
	if c.cfg.EndpointResolverWithOptions != nil {
		endpoint, err := c.cfg.EndpointResolverWithOptions.ResolveEndpoint(ServiceID, region)
		if err == nil {
			return endpoint, nil
		}

		if !isEndpointNotFound(err) {
			return aws.Endpoint{}, fmt.Errorf("resolve Bedrock endpoint: %w", err)
		}
	}

	return aws.Endpoint{
		URL:           fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com", region),
		SigningRegion: region,
	}, nil
}

func isEndpointNotFound(err error) bool {
	_, ok := err.(*aws.EndpointNotFoundError)
	return ok
}
