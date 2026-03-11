package credentials

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// StaticCredentialsProvider returns fixed credentials for testing or local use.
type StaticCredentialsProvider struct {
	credentials aws.Credentials
}

// NewStaticCredentialsProvider builds a fixed credentials provider.
func NewStaticCredentialsProvider(
	accessKeyID string,
	secretAccessKey string,
	sessionToken string,
) StaticCredentialsProvider {
	return StaticCredentialsProvider{
		credentials: aws.Credentials{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
			SessionToken:    sessionToken,
		},
	}
}

// Retrieve implements aws.CredentialsProvider.
func (p StaticCredentialsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return p.credentials, nil
}
