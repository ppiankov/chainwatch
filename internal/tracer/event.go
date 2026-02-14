package tracer

// Event is a JSON-serializable record of one intercepted agent action.
type Event struct {
	Timestamp    string         `json:"ts"`
	TraceID      string         `json:"trace_id"`
	SpanID       string         `json:"span_id"`
	ParentSpanID string         `json:"parent_span_id,omitempty"`
	Actor        map[string]any `json:"actor"`
	Purpose      string         `json:"purpose"`
	Action       map[string]any `json:"action"`
	Data         map[string]any `json:"data"`
	Egress       map[string]any `json:"egress"`
	Decision     map[string]any `json:"decision"`
}
