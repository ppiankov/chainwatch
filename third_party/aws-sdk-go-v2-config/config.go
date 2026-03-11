package config

import (
	"context"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Config stores the shared client configuration used by the generated clients.
type Config struct {
	Region                      string
	EndpointResolverWithOptions aws.EndpointResolverWithOptions
	CredentialsProvider         aws.CredentialsProvider
	HTTPClient                  aws.HTTPClient
}

// LoadOptions collects options before they are finalized into Config.
type LoadOptions struct {
	Region                      string
	EndpointResolverWithOptions aws.EndpointResolverWithOptions
	CredentialsProvider         aws.CredentialsProvider
	HTTPClient                  aws.HTTPClient
}

// LoadDefaultConfig applies explicit options and a small env-based fallback.
func LoadDefaultConfig(_ context.Context, optFns ...func(*LoadOptions) error) (Config, error) {
	var opts LoadOptions
	for _, optFn := range optFns {
		if optFn == nil {
			continue
		}

		if err := optFn(&opts); err != nil {
			return Config{}, err
		}
	}

	if opts.Region == "" {
		opts.Region = os.Getenv("AWS_REGION")
	}
	if opts.Region == "" {
		opts.Region = os.Getenv("AWS_DEFAULT_REGION")
	}

	cfg := Config{
		Region:                      opts.Region,
		EndpointResolverWithOptions: opts.EndpointResolverWithOptions,
		CredentialsProvider:         opts.CredentialsProvider,
		HTTPClient:                  opts.HTTPClient,
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}

	return cfg, nil
}

// WithRegion pins the AWS region for the client.
func WithRegion(region string) func(*LoadOptions) error {
	return func(opts *LoadOptions) error {
		opts.Region = region
		return nil
	}
}

// WithEndpointResolverWithOptions overrides endpoint resolution.
func WithEndpointResolverWithOptions(
	resolver aws.EndpointResolverWithOptions,
) func(*LoadOptions) error {
	return func(opts *LoadOptions) error {
		opts.EndpointResolverWithOptions = resolver
		return nil
	}
}

// WithCredentialsProvider injects a credentials provider.
func WithCredentialsProvider(provider aws.CredentialsProvider) func(*LoadOptions) error {
	return func(opts *LoadOptions) error {
		opts.CredentialsProvider = provider
		return nil
	}
}

// WithHTTPClient injects a custom HTTP client.
func WithHTTPClient(client aws.HTTPClient) func(*LoadOptions) error {
	return func(opts *LoadOptions) error {
		opts.HTTPClient = client
		return nil
	}
}
