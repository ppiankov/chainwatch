package alert

// AlertConfig defines a webhook alert destination.
type AlertConfig struct {
	URL     string            `yaml:"url"     json:"url"`
	Format  string            `yaml:"format"  json:"format"` // "generic", "slack", "pagerduty"
	Events  []string          `yaml:"events"  json:"events"` // ["deny", "require_approval", "break_glass_used"]
	Headers map[string]string `yaml:"headers" json:"headers"`
}

// AlertEvent is the payload sent to webhook endpoints.
type AlertEvent struct {
	Timestamp  string `json:"timestamp"`
	TraceID    string `json:"trace_id"`
	Tool       string `json:"tool"`
	Resource   string `json:"resource"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	Tier       int    `json:"tier"`
	PolicyHash string `json:"policy_hash"`
	Type       string `json:"type,omitempty"` // "break_glass_used" etc.
}
