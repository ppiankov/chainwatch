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

	"github.com/ppiankov/chainwatch/internal/inventory"
)

// Provider wraps AWS Bedrock as an LLM backend for chainwatch classify.
type Provider struct {
	Region      string
	ModelID     string
	VPCEndpoint bool
	IAMRole     string
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
	// Placeholder — implementation in server.go will start an HTTP server
	// and return the local URL (e.g., "http://127.0.0.1:<port>/v1/chat/completions").
	return fmt.Sprintf("bedrock://%s/%s", p.Region, p.ModelID)
}

// Complete sends a completion request to Bedrock via the AWS SDK.
// This is the core translation layer: OpenAI messages format → Bedrock InvokeModel.
func (p *Provider) Complete(ctx context.Context, messages []Message) (*CompletionResponse, error) {
	// Implementation in server.go — uses aws-sdk-go-v2/service/bedrockruntime.
	return nil, fmt.Errorf("bedrock provider not yet implemented: region=%s model=%s", p.Region, p.ModelID)
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
