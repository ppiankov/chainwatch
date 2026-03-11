package bedrock

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

func TestServerStartStop(t *testing.T) {
	useStubListener(t, 41001)

	server := &Server{
		Provider: NewProvider(ProviderConfig{
			Region:  "us-east-1",
			ModelID: "anthropic.claude-3-sonnet-20240229-v1:0",
		}),
	}

	if err := server.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if got := server.Endpoint(); got != "http://127.0.0.1:41001/v1" {
		t.Fatalf("Endpoint() = %q, want %q", got, "http://127.0.0.1:41001/v1")
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /health status = %d, want %d", recorder.Code, http.StatusOK)
	}

	server.Stop()

	if got := server.Endpoint(); got != "" {
		t.Fatalf("Endpoint() after Stop = %q, want empty", got)
	}
}

func TestTranslateRequest(t *testing.T) {
	temperature := 0.2
	body, err := translateRequest(chatCompletionRequest{
		Model:       "anthropic.claude-3-sonnet-20240229-v1:0",
		MaxTokens:   96,
		Temperature: &temperature,
		Messages: []Message{
			{Role: userRole, Content: "hello"},
			{Role: assistantRole, Content: "world"},
		},
	})
	if err != nil {
		t.Fatalf("translateRequest() error = %v", err)
	}

	var got anthropicMessagesRequest
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if got.AnthropicVersion != anthropicVersion {
		t.Fatalf("AnthropicVersion = %q, want %q", got.AnthropicVersion, anthropicVersion)
	}
	if got.MaxTokens != 96 {
		t.Fatalf("MaxTokens = %d, want 96", got.MaxTokens)
	}
	if got.Temperature == nil || *got.Temperature != temperature {
		t.Fatalf("Temperature = %v, want %v", got.Temperature, temperature)
	}
	if len(got.Messages) != 2 {
		t.Fatalf("len(Messages) = %d, want 2", len(got.Messages))
	}
	if got.Messages[0].Role != userRole || got.Messages[0].Content != "hello" {
		t.Fatalf("Messages[0] = %+v, want user hello", got.Messages[0])
	}
	if got.Messages[1].Role != assistantRole || got.Messages[1].Content != "world" {
		t.Fatalf("Messages[1] = %+v, want assistant world", got.Messages[1])
	}
	if got.System != "" {
		t.Fatalf("System = %q, want empty", got.System)
	}
}

func TestTranslateResponse(t *testing.T) {
	resp, err := translateResponse([]byte(`{
		"content": [
			{"type": "text", "text": "hello"},
			{"type": "text", "text": " world"}
		],
		"usage": {
			"input_tokens": 11,
			"output_tokens": 4
		},
		"stop_reason": "max_tokens"
	}`))
	if err != nil {
		t.Fatalf("translateResponse() error = %v", err)
	}

	if resp.ID != chatCompletionID {
		t.Fatalf("ID = %q, want %q", resp.ID, chatCompletionID)
	}
	if resp.Object != chatCompletionType {
		t.Fatalf("Object = %q, want %q", resp.Object, chatCompletionType)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("len(Choices) = %d, want 1", len(resp.Choices))
	}
	if resp.Choices[0].Message.Role != assistantRole {
		t.Fatalf("Choices[0].Message.Role = %q, want %q", resp.Choices[0].Message.Role, assistantRole)
	}
	if resp.Choices[0].Message.Content != "hello world" {
		t.Fatalf("Choices[0].Message.Content = %q, want %q", resp.Choices[0].Message.Content, "hello world")
	}
	if resp.Choices[0].FinishReason != finishReasonLength {
		t.Fatalf("Choices[0].FinishReason = %q, want %q", resp.Choices[0].FinishReason, finishReasonLength)
	}
	if resp.Usage == nil {
		t.Fatal("Usage = nil, want token counts")
	}
	if resp.Usage.PromptTokens != 11 || resp.Usage.CompletionTokens != 4 || resp.Usage.TotalTokens != 15 {
		t.Fatalf("Usage = %+v, want prompt=11 completion=4 total=15", resp.Usage)
	}
}

func TestChatCompletionHandler(t *testing.T) {
	useStubListener(t, 41002)

	const modelID = "anthropic.claude-3-sonnet-20240229-v1:0"

	var capturedBody []byte
	bedrockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("Bedrock mock method = %s, want POST", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/model/") || !strings.Contains(r.URL.Path, "/invoke") {
			t.Fatalf("Bedrock mock path = %q, want model invoke path", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("io.ReadAll() error = %v", err)
		}
		capturedBody = body

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"content": [{"type": "text", "text": "hello from bedrock"}],
			"usage": {"input_tokens": 21, "output_tokens": 5},
			"stop_reason": "end_turn"
		}`))
	})

	provider := NewProvider(ProviderConfig{
		Region:  "us-east-1",
		ModelID: modelID,
	})
	provider.client = newTestBedrockClient(t, bedrockHandler)

	if err := provider.Start(context.Background()); err != nil {
		t.Fatalf("Provider.Start() error = %v", err)
	}
	defer provider.Stop()

	payload, err := json.Marshal(chatCompletionRequest{
		Model:       modelID,
		MaxTokens:   64,
		Temperature: floatPtr(0.1),
		Messages: []Message{
			{Role: systemRole, Content: "be terse"},
			{Role: userRole, Content: "say hello"},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	req := httptest.NewRequest(
		http.MethodPost,
		provider.Endpoint()+"/chat/completions",
		bytes.NewReader(payload),
	)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	provider.server.httpServer.Handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"POST /v1/chat/completions status = %d, body = %s",
			recorder.Code,
			strings.TrimSpace(recorder.Body.String()),
		)
	}

	var got chatCompletionResponse
	if err := json.NewDecoder(recorder.Body).Decode(&got); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if got.Model != modelID {
		t.Fatalf("Model = %q, want %q", got.Model, modelID)
	}
	if len(got.Choices) != 1 {
		t.Fatalf("len(Choices) = %d, want 1", len(got.Choices))
	}
	if got.Choices[0].Message.Content != "hello from bedrock" {
		t.Fatalf("Choices[0].Message.Content = %q, want %q", got.Choices[0].Message.Content, "hello from bedrock")
	}
	if got.Choices[0].FinishReason != finishReasonStop {
		t.Fatalf("Choices[0].FinishReason = %q, want %q", got.Choices[0].FinishReason, finishReasonStop)
	}
	if got.Usage == nil || got.Usage.TotalTokens != 26 {
		t.Fatalf("Usage = %+v, want total=26", got.Usage)
	}

	var translated anthropicMessagesRequest
	if err := json.Unmarshal(capturedBody, &translated); err != nil {
		t.Fatalf("json.Unmarshal(capturedBody) error = %v", err)
	}

	if translated.System != "be terse" {
		t.Fatalf("translated.System = %q, want %q", translated.System, "be terse")
	}
	if len(translated.Messages) != 1 {
		t.Fatalf("len(translated.Messages) = %d, want 1", len(translated.Messages))
	}
	if translated.Messages[0].Role != userRole || translated.Messages[0].Content != "say hello" {
		t.Fatalf("translated.Messages[0] = %+v, want user say hello", translated.Messages[0])
	}
}

func TestSystemMessageExtraction(t *testing.T) {
	body, err := translateRequest(chatCompletionRequest{
		Messages: []Message{
			{Role: systemRole, Content: "first"},
			{Role: userRole, Content: "question"},
			{Role: systemRole, Content: "second"},
			{Role: assistantRole, Content: "answer"},
		},
	})
	if err != nil {
		t.Fatalf("translateRequest() error = %v", err)
	}

	var got anthropicMessagesRequest
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if got.System != "first\n\nsecond" {
		t.Fatalf("System = %q, want %q", got.System, "first\n\nsecond")
	}
	if len(got.Messages) != 2 {
		t.Fatalf("len(Messages) = %d, want 2", len(got.Messages))
	}
	for i, msg := range got.Messages {
		if msg.Role == systemRole {
			t.Fatalf("Messages[%d].Role = %q, system messages should be extracted", i, msg.Role)
		}
	}
}

func TestVPCEndpointConfig(t *testing.T) {
	if got := bedrockRuntimeEndpoint("us-west-2"); got != "https://bedrock-runtime.us-west-2.amazonaws.com" {
		t.Fatalf("bedrockRuntimeEndpoint() = %q, want %q", got, "https://bedrock-runtime.us-west-2.amazonaws.com")
	}
}

func newTestBedrockClient(t *testing.T, handler http.Handler) *bedrockruntime.Client {
	t.Helper()

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			"test-access-key",
			"test-secret-key",
			"test-session-token",
		)),
		config.WithHTTPClient(&http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, req)
				return recorder.Result(), nil
			}),
		}),
	)
	if err != nil {
		t.Fatalf("config.LoadDefaultConfig() error = %v", err)
	}

	return bedrockruntime.NewFromConfig(cfg)
}

func useStubListener(t *testing.T, port int) {
	t.Helper()

	previous := localhostListen
	localhostListen = func(network, address string) (net.Listener, error) {
		return newStubListener(port), nil
	}

	t.Cleanup(func() {
		localhostListen = previous
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type stubListener struct {
	addr   net.Addr
	closed chan struct{}
	once   sync.Once
}

func newStubListener(port int) *stubListener {
	return &stubListener{
		addr: &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: port,
		},
		closed: make(chan struct{}),
	}
}

func (l *stubListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *stubListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
	})
	return nil
}

func (l *stubListener) Addr() net.Addr {
	return l.addr
}

func floatPtr(v float64) *float64 {
	return &v
}
