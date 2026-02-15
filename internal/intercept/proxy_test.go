package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/chainwatch/internal/model"
)

// --- Test helpers ---

func newTestInterceptor(t *testing.T, upstreamURL string) (*Server, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := Config{
		Port:     port,
		Upstream: upstreamURL,
		Purpose:  "test",
		Actor:    map[string]any{"test": true},
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create interceptor: %v", err)
	}
	return srv, port
}

func startTestInterceptor(t *testing.T, srv *Server) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", srv.srv.Addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return cancel
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatal("interceptor did not start in time")
	return cancel
}

func interceptClient(port int) *http.Client {
	return &http.Client{Timeout: 5 * time.Second}
}

func interceptURL(port int, path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
}

func anthropicResponse(content []any, stopReason string) []byte {
	body := map[string]any{
		"id":          "msg_test",
		"type":        "message",
		"role":        "assistant",
		"content":     content,
		"model":       "claude-3-opus-20240229",
		"stop_reason": stopReason,
	}
	out, _ := json.Marshal(body)
	return out
}

func openaiResponse(message map[string]any, finishReason string) []byte {
	body := map[string]any{
		"id":     "chatcmpl-test",
		"object": "chat.completion",
		"model":  "gpt-4",
		"choices": []any{
			map[string]any{
				"index":         0,
				"message":       message,
				"finish_reason": finishReason,
			},
		},
	}
	out, _ := json.Marshal(body)
	return out
}

// --- Format detection tests ---

func TestDetectFormatAnthropic(t *testing.T) {
	body := map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": "hello"},
		},
	}
	if f := DetectFormat(body); f != FormatAnthropic {
		t.Errorf("expected Anthropic, got %d", f)
	}
}

func TestDetectFormatOpenAI(t *testing.T) {
	body := map[string]any{
		"choices": []any{
			map[string]any{
				"message": map[string]any{"content": "hello"},
			},
		},
	}
	if f := DetectFormat(body); f != FormatOpenAI {
		t.Errorf("expected OpenAI, got %d", f)
	}
}

func TestDetectFormatUnknown(t *testing.T) {
	body := map[string]any{"random": "data"}
	if f := DetectFormat(body); f != FormatUnknown {
		t.Errorf("expected Unknown, got %d", f)
	}
}

// --- Tool call extraction tests ---

func TestExtractAnthropicToolCalls(t *testing.T) {
	body := map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": "I'll help"},
			map[string]any{
				"type":  "tool_use",
				"id":    "toolu_123",
				"name":  "run_command",
				"input": map[string]any{"command": "echo hello"},
			},
		},
	}
	calls, format := ExtractToolCalls(body)
	if format != FormatAnthropic {
		t.Errorf("expected Anthropic format")
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(calls))
	}
	if calls[0].Name != "run_command" {
		t.Errorf("expected name run_command, got %s", calls[0].Name)
	}
	if calls[0].ID != "toolu_123" {
		t.Errorf("expected id toolu_123, got %s", calls[0].ID)
	}
	if calls[0].Index != 1 {
		t.Errorf("expected index 1, got %d", calls[0].Index)
	}
}

func TestExtractOpenAIToolCalls(t *testing.T) {
	body := map[string]any{
		"choices": []any{
			map[string]any{
				"message": map[string]any{
					"tool_calls": []any{
						map[string]any{
							"id":   "call_123",
							"type": "function",
							"function": map[string]any{
								"name":      "run_command",
								"arguments": `{"command":"echo hello"}`,
							},
						},
					},
				},
			},
		},
	}
	calls, format := ExtractToolCalls(body)
	if format != FormatOpenAI {
		t.Errorf("expected OpenAI format")
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(calls))
	}
	if calls[0].Name != "run_command" {
		t.Errorf("expected name run_command, got %s", calls[0].Name)
	}
	if cmd, ok := calls[0].Arguments["command"].(string); !ok || cmd != "echo hello" {
		t.Errorf("expected command=echo hello, got %v", calls[0].Arguments)
	}
}

// --- Action building tests ---

func TestBuildActionFromCommandTool(t *testing.T) {
	tc := ToolCall{Name: "run_command", Arguments: map[string]any{"command": "rm -rf /"}}
	action := buildActionFromToolCall(tc)
	if action.Tool != "command" {
		t.Errorf("expected tool=command, got %s", action.Tool)
	}
	if action.Resource != "rm -rf /" {
		t.Errorf("expected resource=rm -rf /, got %s", action.Resource)
	}
	if action.Operation != "execute" {
		t.Errorf("expected operation=execute, got %s", action.Operation)
	}
}

func TestBuildActionFromHTTPTool(t *testing.T) {
	tc := ToolCall{Name: "http_request", Arguments: map[string]any{
		"url":    "https://stripe.com/v1/charges",
		"method": "POST",
	}}
	action := buildActionFromToolCall(tc)
	if action.Tool != "http" {
		t.Errorf("expected tool=http, got %s", action.Tool)
	}
	if action.Resource != "https://stripe.com/v1/charges" {
		t.Errorf("expected resource=stripe URL, got %s", action.Resource)
	}
	if action.Operation != "post" {
		t.Errorf("expected operation=post, got %s", action.Operation)
	}
}

func TestBuildActionFromFileTool(t *testing.T) {
	tc := ToolCall{Name: "file_write", Arguments: map[string]any{
		"path":    "~/.ssh/id_rsa",
		"content": "secret key",
	}}
	action := buildActionFromToolCall(tc)
	if action.Tool != "file_write" {
		t.Errorf("expected tool=file_write, got %s", action.Tool)
	}
	if action.Resource != "~/.ssh/id_rsa" {
		t.Errorf("expected resource=~/.ssh/id_rsa, got %s", action.Resource)
	}
}

func TestBuildActionFromUnknownTool(t *testing.T) {
	tc := ToolCall{Name: "custom_tool", Arguments: map[string]any{"data": "test"}}
	action := buildActionFromToolCall(tc)
	if action.Tool != "custom_tool" {
		t.Errorf("expected tool=custom_tool, got %s", action.Tool)
	}
}

// --- Rewrite tests ---

func TestRewriteAnthropicBlocked(t *testing.T) {
	body := map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": "I'll help"},
			map[string]any{"type": "tool_use", "id": "t1", "name": "rm", "input": map[string]any{}},
		},
		"stop_reason": "tool_use",
	}
	results := []EvalResult{{
		Call:   ToolCall{Name: "rm", Index: 1, Format: FormatAnthropic},
		Result: makeResult("deny", "blocked", "denylist.block"),
	}}
	out, changed := RewriteResponse(body, results, FormatAnthropic)
	if !changed {
		t.Fatal("expected response to be changed")
	}
	var parsed map[string]any
	json.Unmarshal(out, &parsed)

	content := parsed["content"].([]any)
	block := content[1].(map[string]any)
	if block["type"] != "text" {
		t.Errorf("expected blocked tool_use replaced with text, got %s", block["type"])
	}
	text := block["text"].(string)
	if !strings.Contains(text, "[BLOCKED by chainwatch]") {
		t.Errorf("expected block message, got %s", text)
	}
	if parsed["stop_reason"] != "end_turn" {
		t.Errorf("expected stop_reason=end_turn, got %v", parsed["stop_reason"])
	}
}

func TestRewriteAnthropicPartialBlock(t *testing.T) {
	body := map[string]any{
		"content": []any{
			map[string]any{"type": "tool_use", "id": "t1", "name": "echo", "input": map[string]any{}},
			map[string]any{"type": "tool_use", "id": "t2", "name": "rm", "input": map[string]any{}},
		},
		"stop_reason": "tool_use",
	}
	results := []EvalResult{
		{Call: ToolCall{Name: "echo", Index: 0}, Result: makeResult("allow", "ok", "")},
		{Call: ToolCall{Name: "rm", Index: 1}, Result: makeResult("deny", "blocked", "denylist.block")},
	}
	out, changed := RewriteResponse(body, results, FormatAnthropic)
	if !changed {
		t.Fatal("expected changed")
	}
	var parsed map[string]any
	json.Unmarshal(out, &parsed)

	// stop_reason should remain "tool_use" since not all were blocked
	if parsed["stop_reason"] != "tool_use" {
		t.Errorf("expected stop_reason=tool_use (partial block), got %v", parsed["stop_reason"])
	}
	content := parsed["content"].([]any)
	// First tool call should remain unchanged
	first := content[0].(map[string]any)
	if first["type"] != "tool_use" {
		t.Errorf("expected first tool_use to remain, got %s", first["type"])
	}
	// Second should be blocked text
	second := content[1].(map[string]any)
	if second["type"] != "text" {
		t.Errorf("expected second to be text, got %s", second["type"])
	}
}

func TestRewriteOpenAIBlocked(t *testing.T) {
	body := map[string]any{
		"choices": []any{
			map[string]any{
				"message": map[string]any{
					"content": nil,
					"tool_calls": []any{
						map[string]any{
							"id":   "c1",
							"type": "function",
							"function": map[string]any{
								"name":      "run_command",
								"arguments": `{"command":"rm -rf /"}`,
							},
						},
					},
				},
				"finish_reason": "tool_calls",
			},
		},
	}
	results := []EvalResult{{
		Call:   ToolCall{Name: "run_command", Index: 0, Format: FormatOpenAI},
		Result: makeResult("deny", "blocked", "denylist.block"),
	}}
	out, changed := RewriteResponse(body, results, FormatOpenAI)
	if !changed {
		t.Fatal("expected changed")
	}
	var parsed map[string]any
	json.Unmarshal(out, &parsed)

	choices := parsed["choices"].([]any)
	choice := choices[0].(map[string]any)
	msg := choice["message"].(map[string]any)

	if msg["tool_calls"] != nil {
		t.Errorf("expected tool_calls=nil, got %v", msg["tool_calls"])
	}
	content, ok := msg["content"].(string)
	if !ok || !strings.Contains(content, "[BLOCKED by chainwatch]") {
		t.Errorf("expected block message in content, got %v", msg["content"])
	}
	if choice["finish_reason"] != "stop" {
		t.Errorf("expected finish_reason=stop, got %v", choice["finish_reason"])
	}
}

func TestRewriteOpenAIPartialBlock(t *testing.T) {
	body := map[string]any{
		"choices": []any{
			map[string]any{
				"message": map[string]any{
					"content": nil,
					"tool_calls": []any{
						map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "echo", "arguments": "{}"}},
						map[string]any{"id": "c2", "type": "function", "function": map[string]any{"name": "rm", "arguments": "{}"}},
					},
				},
				"finish_reason": "tool_calls",
			},
		},
	}
	results := []EvalResult{
		{Call: ToolCall{Name: "echo", Index: 0}, Result: makeResult("allow", "ok", "")},
		{Call: ToolCall{Name: "rm", Index: 1}, Result: makeResult("deny", "blocked", "denylist.block")},
	}
	out, changed := RewriteResponse(body, results, FormatOpenAI)
	if !changed {
		t.Fatal("expected changed")
	}
	var parsed map[string]any
	json.Unmarshal(out, &parsed)

	choices := parsed["choices"].([]any)
	choice := choices[0].(map[string]any)
	// finish_reason should stay "tool_calls" since some remain
	if choice["finish_reason"] != "tool_calls" {
		t.Errorf("expected finish_reason=tool_calls, got %v", choice["finish_reason"])
	}
}

// --- End-to-end non-streaming tests ---

func TestAnthropicToolUseBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := anthropicResponse([]any{
			map[string]any{"type": "text", "text": "Let me delete that"},
			map[string]any{
				"type":  "tool_use",
				"id":    "toolu_1",
				"name":  "run_command",
				"input": map[string]any{"command": "rm -rf /"},
			},
		}, "tool_use")
		w.Write(body)
	}))
	defer upstream.Close()

	srv, port := newTestInterceptor(t, upstream.URL)
	cancel := startTestInterceptor(t, srv)
	defer cancel()

	client := interceptClient(port)
	resp, err := client.Post(interceptURL(port, "/v1/messages"), "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)

	content := body["content"].([]any)
	if len(content) != 2 {
		t.Fatalf("expected 2 content blocks, got %d", len(content))
	}

	// Second block should be text (blocked), not tool_use
	blocked := content[1].(map[string]any)
	if blocked["type"] != "text" {
		t.Errorf("expected blocked tool_use replaced with text, got %s", blocked["type"])
	}
	text, _ := blocked["text"].(string)
	if !strings.Contains(text, "[BLOCKED by chainwatch]") {
		t.Errorf("expected block message, got %s", text)
	}
	if body["stop_reason"] != "end_turn" {
		t.Errorf("expected stop_reason=end_turn, got %v", body["stop_reason"])
	}
}

func TestAnthropicToolUseAllowed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := anthropicResponse([]any{
			map[string]any{
				"type":  "tool_use",
				"id":    "toolu_1",
				"name":  "run_command",
				"input": map[string]any{"command": "echo hello"},
			},
		}, "tool_use")
		w.Write(body)
	}))
	defer upstream.Close()

	srv, port := newTestInterceptor(t, upstream.URL)
	cancel := startTestInterceptor(t, srv)
	defer cancel()

	client := interceptClient(port)
	resp, err := client.Post(interceptURL(port, "/v1/messages"), "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)

	content := body["content"].([]any)
	block := content[0].(map[string]any)
	if block["type"] != "tool_use" {
		t.Errorf("expected tool_use to pass through, got %s", block["type"])
	}
	if body["stop_reason"] != "tool_use" {
		t.Errorf("expected stop_reason=tool_use, got %v", body["stop_reason"])
	}
}

func TestAnthropicMultipleToolCalls(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := anthropicResponse([]any{
			map[string]any{"type": "tool_use", "id": "t1", "name": "run_command", "input": map[string]any{"command": "echo safe"}},
			map[string]any{"type": "tool_use", "id": "t2", "name": "run_command", "input": map[string]any{"command": "rm -rf /"}},
			map[string]any{"type": "tool_use", "id": "t3", "name": "run_command", "input": map[string]any{"command": "ls /tmp"}},
		}, "tool_use")
		w.Write(body)
	}))
	defer upstream.Close()

	srv, port := newTestInterceptor(t, upstream.URL)
	cancel := startTestInterceptor(t, srv)
	defer cancel()

	client := interceptClient(port)
	resp, err := client.Post(interceptURL(port, "/v1/messages"), "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)

	content := body["content"].([]any)
	if len(content) != 3 {
		t.Fatalf("expected 3 content blocks, got %d", len(content))
	}

	// First (echo safe) should pass through
	if content[0].(map[string]any)["type"] != "tool_use" {
		t.Error("expected first tool_use to pass through")
	}
	// Second (rm -rf /) should be blocked
	if content[1].(map[string]any)["type"] != "text" {
		t.Error("expected second (rm -rf /) to be blocked as text")
	}
	// Third (ls /tmp) should pass through
	if content[2].(map[string]any)["type"] != "tool_use" {
		t.Error("expected third tool_use to pass through")
	}
	// stop_reason should stay "tool_use" since not all blocked
	if body["stop_reason"] != "tool_use" {
		t.Errorf("expected stop_reason=tool_use, got %v", body["stop_reason"])
	}
}

func TestOpenAIFunctionCallBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := openaiResponse(map[string]any{
			"content": nil,
			"tool_calls": []any{
				map[string]any{
					"id":   "call_1",
					"type": "function",
					"function": map[string]any{
						"name":      "run_command",
						"arguments": `{"command":"rm -rf /"}`,
					},
				},
			},
		}, "tool_calls")
		w.Write(body)
	}))
	defer upstream.Close()

	srv, port := newTestInterceptor(t, upstream.URL)
	cancel := startTestInterceptor(t, srv)
	defer cancel()

	client := interceptClient(port)
	resp, err := client.Post(interceptURL(port, "/v1/chat/completions"), "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)

	choices := body["choices"].([]any)
	choice := choices[0].(map[string]any)
	msg := choice["message"].(map[string]any)

	if msg["tool_calls"] != nil {
		t.Error("expected tool_calls to be nil")
	}
	content, _ := msg["content"].(string)
	if !strings.Contains(content, "[BLOCKED by chainwatch]") {
		t.Errorf("expected block message, got %s", content)
	}
}

func TestNonToolResponsePassthrough(t *testing.T) {
	expectedBody := `{"content":[{"type":"text","text":"Hello world"}],"stop_reason":"end_turn"}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(expectedBody))
	}))
	defer upstream.Close()

	srv, port := newTestInterceptor(t, upstream.URL)
	cancel := startTestInterceptor(t, srv)
	defer cancel()

	client := interceptClient(port)
	resp, err := client.Post(interceptURL(port, "/v1/messages"), "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	// Should pass through unchanged (no tool calls to intercept)
	var parsed map[string]any
	json.Unmarshal(body, &parsed)
	content := parsed["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("expected 1 content block, got %d", len(content))
	}
	if content[0].(map[string]any)["type"] != "text" {
		t.Error("expected text block to pass through")
	}
}

// --- Streaming tests ---

func TestStreamingAnthropicBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)

		events := []string{
			`event: message_start` + "\n" + `data: {"type":"message_start","message":{"id":"msg_1","role":"assistant"}}` + "\n\n",
			`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"run_command"}}` + "\n\n",
			`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"rm -rf /\"}"}}` + "\n\n",
			`event: content_block_stop` + "\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n",
			`event: message_stop` + "\n" + `data: {"type":"message_stop"}` + "\n\n",
		}
		for _, ev := range events {
			fmt.Fprint(w, ev)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	srv, port := newTestInterceptor(t, upstream.URL)
	cancel := startTestInterceptor(t, srv)
	defer cancel()

	client := interceptClient(port)
	resp, err := client.Post(interceptURL(port, "/v1/messages"), "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	output := string(body)

	// Should contain blocked text, not tool_use
	if !strings.Contains(output, "[BLOCKED by chainwatch]") {
		t.Errorf("expected block message in streaming output, got:\n%s", output)
	}
	if strings.Contains(output, "\"type\":\"tool_use\"") {
		// The replacement should use "text" type, not "tool_use"
		// But content_block_start with tool_use may appear in initial buffer
	}
}

func TestStreamingTextPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)

		events := []string{
			`event: message_start` + "\n" + `data: {"type":"message_start","message":{"id":"msg_1"}}` + "\n\n",
			`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n",
			`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}` + "\n\n",
			`event: content_block_stop` + "\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n",
			`event: message_stop` + "\n" + `data: {"type":"message_stop"}` + "\n\n",
		}
		for _, ev := range events {
			fmt.Fprint(w, ev)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	srv, port := newTestInterceptor(t, upstream.URL)
	cancel := startTestInterceptor(t, srv)
	defer cancel()

	client := interceptClient(port)
	resp, err := client.Post(interceptURL(port, "/v1/messages"), "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	output := string(body)

	// Text should pass through unchanged
	if !strings.Contains(output, "Hello") {
		t.Errorf("expected text to pass through, got:\n%s", output)
	}
	if strings.Contains(output, "[BLOCKED") {
		t.Error("text-only stream should not contain block messages")
	}
}

// --- Infrastructure tests ---

func TestRequestHeadersForwarded(t *testing.T) {
	var receivedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}]}`))
	}))
	defer upstream.Close()

	srv, port := newTestInterceptor(t, upstream.URL)
	cancel := startTestInterceptor(t, srv)
	defer cancel()

	client := interceptClient(port)
	req, _ := http.NewRequest("POST", interceptURL(port, "/v1/messages"), strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer sk-test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if receivedAuth != "Bearer sk-test-key" {
		t.Errorf("expected auth header forwarded, got %q", receivedAuth)
	}
}

func TestTraceRecordsInterceptedCalls(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := anthropicResponse([]any{
			map[string]any{"type": "tool_use", "id": "t1", "name": "run_command", "input": map[string]any{"command": "rm -rf /"}},
		}, "tool_use")
		w.Write(body)
	}))
	defer upstream.Close()

	srv, port := newTestInterceptor(t, upstream.URL)
	cancel := startTestInterceptor(t, srv)
	defer cancel()

	client := interceptClient(port)
	resp, err := client.Post(interceptURL(port, "/v1/messages"), "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	summary := srv.TraceSummary()
	events, ok := summary["events"]
	if !ok || events == nil {
		t.Fatal("expected trace events")
	}
}

// --- Helpers ---

func makeResult(decision, reason, policyID string) model.PolicyResult {
	return model.PolicyResult{
		Decision: model.Decision(decision),
		Reason:   reason,
		PolicyID: policyID,
	}
}
