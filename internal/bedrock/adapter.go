// Package bedrock provides an adapter that translates OpenAI-compatible
// LLM requests to AWS Bedrock InvokeModel calls. This keeps the chainwatch
// classify pipeline unchanged while routing inference through AWS-internal
// endpoints (IAM auth, VPC endpoint, CloudTrail audit).
//
// Architecture: the adapter starts a local HTTP server that speaks the
// OpenAI /v1/chat/completions format. The neurorouter client connects to
// this local endpoint. The adapter translates requests to Bedrock's
// InvokeModel API using the AWS SDK.
package bedrock

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/ppiankov/chainwatch/internal/inventory"
)

// Provider wraps AWS Bedrock as an LLM backend for chainwatch classify.
type Provider struct {
	Region      string
	ModelID     string
	VPCEndpoint bool
	IAMRole     string

	mu     sync.Mutex
	server *Server
	client invokeModelAPI
}

// ProviderConfig holds construction parameters.
type ProviderConfig struct {
	Region      string
	ModelID     string
	VPCEndpoint bool
	IAMRole     string
}

// NewProvider creates a Bedrock provider from explicit config.
func NewProvider(cfg ProviderConfig) *Provider {
	return &Provider{
		Region:      cfg.Region,
		ModelID:     cfg.ModelID,
		VPCEndpoint: cfg.VPCEndpoint,
		IAMRole:     cfg.IAMRole,
	}
}

// NewProvidersFromInventory creates Bedrock providers from inventory config.
// Returns one provider per configured model (nullbot analysis + execution agent).
func NewProvidersFromInventory(inv *inventory.Inventory) []*Provider {
	cfg := inv.BedrockConfig()
	if cfg.Region == "" {
		return nil
	}

	var providers []*Provider

	if cfg.Models.NullbotAnalysis != "" {
		providers = append(providers, &Provider{
			Region:      cfg.Region,
			ModelID:     cfg.Models.NullbotAnalysis,
			VPCEndpoint: cfg.VPCEndpoint,
			IAMRole:     cfg.IAMRole,
		})
	}

	if cfg.Models.ExecutionAgent != "" {
		providers = append(providers, &Provider{
			Region:      cfg.Region,
			ModelID:     cfg.Models.ExecutionAgent,
			VPCEndpoint: cfg.VPCEndpoint,
			IAMRole:     cfg.IAMRole,
		})
	}

	return providers
}

// Endpoint returns the local adapter URL for use as a neurorouter provider URL.
// The adapter must be started with Start() before calling this.
func (p *Provider) Endpoint() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.server == nil {
		return ""
	}

	return p.server.Endpoint()
}

// Start launches the local OpenAI-compatible Bedrock adapter.
func (p *Provider) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.server != nil && p.server.port > 0 {
		p.mu.Unlock()
		return nil
	}

	server := &Server{Provider: p}
	p.server = server
	p.mu.Unlock()

	if err := server.Start(ctx); err != nil {
		p.mu.Lock()
		if p.server == server {
			p.server = nil
		}
		p.mu.Unlock()
		return err
	}

	return nil
}

// Stop stops the local OpenAI-compatible Bedrock adapter.
func (p *Provider) Stop() {
	p.mu.Lock()
	server := p.server
	p.server = nil
	p.mu.Unlock()

	if server != nil {
		server.Stop()
	}
}

// Complete sends a completion request to Bedrock via the AWS SDK.
// This is the core translation layer: OpenAI messages format → Bedrock InvokeModel.
func (p *Provider) Complete(ctx context.Context, messages []Message) (*CompletionResponse, error) {
	resp, err := p.completeChat(ctx, chatCompletionRequest{
		Model:    p.ModelID,
		Messages: messages,
	})
	if err != nil {
		return nil, err
	}

	return completionResponseFromChat(resp), nil
}

// Message is an OpenAI-compatible chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// CompletionResponse wraps a Bedrock model response.
type CompletionResponse struct {
	Content string `json:"content"`
	Model   string `json:"model"`
	Usage   Usage  `json:"usage"`
}

// Usage tracks token consumption for cost attribution.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type invokeModelAPI interface {
	InvokeModel(
		ctx context.Context,
		params *bedrockruntime.InvokeModelInput,
		optFns ...func(*bedrockruntime.Options),
	) (*bedrockruntime.InvokeModelOutput, error)
}

var bedrockClientFactory = func(region string, vpcEndpoint bool) (invokeModelAPI, error) {
	return NewBedrockClient(region, vpcEndpoint)
}

func (p *Provider) completeChat(
	ctx context.Context,
	req chatCompletionRequest,
) (*chatCompletionResponse, error) {
	modelID := req.Model
	if modelID == "" {
		modelID = p.ModelID
	}
	if modelID == "" {
		return nil, fmt.Errorf("bedrock model ID is required")
	}

	req.Model = modelID

	body, err := translateRequest(req)
	if err != nil {
		return nil, err
	}

	client, err := p.clientForRequest()
	if err != nil {
		return nil, err
	}

	output, err := client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		Accept:      aws.String("application/json"),
		Body:        body,
		ContentType: aws.String("application/json"),
		ModelId:     aws.String(modelID),
	})
	if err != nil {
		return nil, fmt.Errorf("invoke bedrock model %q: %w", modelID, err)
	}

	resp, err := translateResponse(output.Body)
	if err != nil {
		return nil, err
	}

	resp.Model = modelID
	return resp, nil
}

func (p *Provider) clientForRequest() (invokeModelAPI, error) {
	p.mu.Lock()
	if p.client != nil {
		client := p.client
		p.mu.Unlock()
		return client, nil
	}
	p.mu.Unlock()

	client, err := bedrockClientFactory(p.Region, p.VPCEndpoint)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client == nil {
		p.client = client
	}

	return p.client, nil
}

func completionResponseFromChat(resp *chatCompletionResponse) *CompletionResponse {
	if resp == nil || len(resp.Choices) == 0 {
		return &CompletionResponse{}
	}

	result := &CompletionResponse{
		Content: resp.Choices[0].Message.Content,
		Model:   resp.Model,
	}

	if resp.Usage == nil {
		return result
	}

	result.Usage = Usage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}

	return result
}
