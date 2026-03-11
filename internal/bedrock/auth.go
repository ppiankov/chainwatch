package bedrock

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

// NewBedrockClient creates an AWS Bedrock Runtime client using the default
// AWS credential chain for the current environment.
func NewBedrockClient(region string, vpcEndpoint bool) (*bedrockruntime.Client, error) {
	if region == "" {
		return nil, fmt.Errorf("bedrock region is required")
	}

	loadOptions := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}
	if vpcEndpoint {
		loadOptions = append(loadOptions, config.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(func(
				service string,
				resolvedRegion string,
				_ ...interface{},
			) (aws.Endpoint, error) {
				if service != bedrockruntime.ServiceID {
					return aws.Endpoint{}, &aws.EndpointNotFoundError{}
				}

				return aws.Endpoint{
					URL:           bedrockRuntimeEndpoint(resolvedRegion),
					SigningRegion: resolvedRegion,
				}, nil
			}),
		))
	}

	cfg, err := config.LoadDefaultConfig(context.Background(), loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config for Bedrock: %w", err)
	}

	return bedrockruntime.NewFromConfig(cfg), nil
}

func bedrockRuntimeEndpoint(region string) string {
	return fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com", region)
}
