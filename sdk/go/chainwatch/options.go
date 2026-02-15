package chainwatch

// Option configures a Client at creation time.
type Option func(*clientConfig)

type clientConfig struct {
	profileName  string
	policyPath   string
	denylistPath string
	purpose      string
	actor        map[string]any
}

// WithProfile sets the safety profile (e.g., "clawbot").
func WithProfile(name string) Option {
	return func(c *clientConfig) { c.profileName = name }
}

// WithPolicy sets the path to a policy YAML file.
func WithPolicy(path string) Option {
	return func(c *clientConfig) { c.policyPath = path }
}

// WithDenylist sets the path to a denylist YAML file.
func WithDenylist(path string) Option {
	return func(c *clientConfig) { c.denylistPath = path }
}

// WithPurpose sets the default purpose for policy evaluation.
func WithPurpose(purpose string) Option {
	return func(c *clientConfig) { c.purpose = purpose }
}

// WithActor sets the actor metadata for trace events.
func WithActor(actor map[string]any) Option {
	return func(c *clientConfig) { c.actor = actor }
}

// WrapOption configures a single Wrap call.
type WrapOption func(*wrapConfig)

type wrapConfig struct {
	purpose string
}

// WrapWithPurpose overrides the client-level purpose for this wrap.
func WrapWithPurpose(purpose string) WrapOption {
	return func(w *wrapConfig) { w.purpose = purpose }
}
