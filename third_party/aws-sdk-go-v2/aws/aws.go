package aws

import (
	"context"
	"net/http"
)

// Endpoint describes the resolved endpoint for a service request.
type Endpoint struct {
	URL               string
	SigningRegion     string
	HostnameImmutable bool
}

// EndpointResolverWithOptions resolves service endpoints.
type EndpointResolverWithOptions interface {
	ResolveEndpoint(service, region string, options ...interface{}) (Endpoint, error)
}

// EndpointResolverWithOptionsFunc adapts a function into a resolver.
type EndpointResolverWithOptionsFunc func(service, region string, options ...interface{}) (Endpoint, error)

// ResolveEndpoint implements EndpointResolverWithOptions.
func (f EndpointResolverWithOptionsFunc) ResolveEndpoint(
	service string,
	region string,
	options ...interface{},
) (Endpoint, error) {
	return f(service, region, options...)
}

// EndpointNotFoundError indicates the resolver does not have an override.
type EndpointNotFoundError struct{}

// Error implements error.
func (e *EndpointNotFoundError) Error() string {
	return "endpoint not found"
}

// HTTPClient is the minimal HTTP client contract used by the SDK.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Credentials holds access credentials for signing.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// CredentialsProvider resolves request credentials.
type CredentialsProvider interface {
	Retrieve(context.Context) (Credentials, error)
}

// String returns a pointer to the provided string.
func String(v string) *string {
	return &v
}
