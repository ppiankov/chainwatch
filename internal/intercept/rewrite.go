package intercept

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ppiankov/chainwatch/internal/model"
)

// EvalResult pairs a ToolCall with its policy evaluation outcome.
type EvalResult struct {
	Call   ToolCall
	Result model.PolicyResult
}

// RewriteResponse applies evaluation results to the response body.
// For each blocked tool call, replaces it with a text explanation.
// Returns the modified JSON bytes and whether any changes were made.
func RewriteResponse(body map[string]any, results []EvalResult, format LLMFormat) ([]byte, bool) {
	var changed bool
	switch format {
	case FormatAnthropic:
		changed = rewriteAnthropic(body, results)
	case FormatOpenAI:
		changed = rewriteOpenAI(body, results)
	}

	if !changed {
		out, _ := json.Marshal(body)
		return out, false
	}

	out, _ := json.Marshal(body)
	return out, true
}

// rewriteAnthropic replaces blocked tool_use content blocks with text blocks.
func rewriteAnthropic(body map[string]any, results []EvalResult) bool {
	content, ok := body["content"].([]any)
	if !ok {
		return false
	}

	changed := false
	allBlocked := true

	for _, er := range results {
		if er.Result.Decision == model.Allow || er.Result.Decision == model.AllowWithRedaction {
			allBlocked = false
			continue
		}

		// Replace tool_use block with text block
		if er.Call.Index < len(content) {
			content[er.Call.Index] = map[string]any{
				"type": "text",
				"text": blockMessage(er.Call, er.Result),
			}
			changed = true
		}
	}

	if changed {
		body["content"] = content
		// Update stop_reason if ALL tool calls were blocked
		if allBlocked {
			if sr, ok := body["stop_reason"].(string); ok && sr == "tool_use" {
				body["stop_reason"] = "end_turn"
			}
		}
	}

	return changed
}

// rewriteOpenAI removes blocked tool_call entries from choices[0].message.tool_calls.
func rewriteOpenAI(body map[string]any, results []EvalResult) bool {
	choices, ok := body["choices"].([]any)
	if !ok || len(choices) == 0 {
		return false
	}
	choice, ok := choices[0].(map[string]any)
	if !ok {
		return false
	}
	message, ok := choice["message"].(map[string]any)
	if !ok {
		return false
	}
	toolCalls, ok := message["tool_calls"].([]any)
	if !ok {
		return false
	}

	// Collect blocked indices and messages
	blockedIndices := make(map[int]bool)
	var blockMessages []string
	for _, er := range results {
		if er.Result.Decision != model.Allow && er.Result.Decision != model.AllowWithRedaction {
			blockedIndices[er.Call.Index] = true
			blockMessages = append(blockMessages, blockMessage(er.Call, er.Result))
		}
	}

	if len(blockedIndices) == 0 {
		return false
	}

	// Filter out blocked tool calls
	var remaining []any
	for i, tc := range toolCalls {
		if !blockedIndices[i] {
			remaining = append(remaining, tc)
		}
	}

	if len(remaining) == 0 {
		// All tool calls blocked — remove tool_calls, set content to block messages
		message["tool_calls"] = nil
		message["content"] = strings.Join(blockMessages, "\n")
		if fr, ok := choice["finish_reason"].(string); ok && fr == "tool_calls" {
			choice["finish_reason"] = "stop"
		}
	} else {
		// Some remaining — keep them, append block messages to content
		message["tool_calls"] = remaining
		existing, _ := message["content"].(string)
		if existing != "" {
			existing += "\n"
		}
		message["content"] = existing + strings.Join(blockMessages, "\n")
	}

	choices[0] = choice
	body["choices"] = choices
	return true
}

// blockMessage formats the human-readable block explanation.
func blockMessage(tc ToolCall, result model.PolicyResult) string {
	msg := fmt.Sprintf("[BLOCKED by chainwatch] Tool '%s' denied: %s", tc.Name, result.Reason)
	if result.PolicyID != "" {
		msg += fmt.Sprintf(" (policy_id=%s)", result.PolicyID)
	}
	if result.ApprovalKey != "" {
		msg += fmt.Sprintf(" (approval_key=%s)", result.ApprovalKey)
	}
	return msg
}

// RewriteOpenAISSE generates an SSE chunk that replaces a blocked tool call
// with a content text message in OpenAI streaming format.
func RewriteOpenAISSE(tc ToolCall, result model.PolicyResult) string {
	msg := blockMessage(tc, result)

	chunk := map[string]any{
		"id":      "chatcmpl-chainwatch-block",
		"object":  "chat.completion.chunk",
		"created": 0,
		"choices": []any{
			map[string]any{
				"index": 0,
				"delta": map[string]any{
					"content": msg,
				},
				"finish_reason": nil,
			},
		},
	}

	data, _ := json.Marshal(chunk)
	return "data: " + string(data) + "\n"
}

// RewriteOpenAISSEFinish generates the finish_reason chunk when all tool calls
// are blocked and need to be replaced with a stop.
func RewriteOpenAISSEFinish() string {
	chunk := map[string]any{
		"id":      "chatcmpl-chainwatch-block",
		"object":  "chat.completion.chunk",
		"created": 0,
		"choices": []any{
			map[string]any{
				"index":         0,
				"delta":         map[string]any{},
				"finish_reason": "stop",
			},
		},
	}

	data, _ := json.Marshal(chunk)
	return "data: " + string(data) + "\n"
}

// RewriteAnthropicSSE generates SSE events that replace a blocked tool_use block
// with a text content block in streaming format.
func RewriteAnthropicSSE(index int, tc ToolCall, result model.PolicyResult) []string {
	msg := blockMessage(tc, result)

	startData, _ := json.Marshal(map[string]any{
		"type":  "content_block_start",
		"index": index,
		"content_block": map[string]any{
			"type": "text",
			"text": "",
		},
	})

	deltaData, _ := json.Marshal(map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{
			"type": "text_delta",
			"text": msg,
		},
	})

	stopData, _ := json.Marshal(map[string]any{
		"type":  "content_block_stop",
		"index": index,
	})

	return []string{
		"event: content_block_start\ndata: " + string(startData) + "\n",
		"event: content_block_delta\ndata: " + string(deltaData) + "\n",
		"event: content_block_stop\ndata: " + string(stopData) + "\n",
	}
}
