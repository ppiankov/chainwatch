package intercept

import (
	"encoding/json"
	"strings"
)

// LLMFormat identifies which LLM API format a response uses.
type LLMFormat int

const (
	FormatUnknown   LLMFormat = 0
	FormatAnthropic LLMFormat = 1
	FormatOpenAI    LLMFormat = 2
)

// ToolCall is a normalized representation of a tool invocation
// extracted from either Anthropic or OpenAI response format.
type ToolCall struct {
	ID         string         // "toolu_123" or "call_123"
	Name       string         // tool name: "run_command", "file_write", etc.
	Arguments  map[string]any // parsed arguments
	Index      int            // position in the content/tool_calls array
	Format     LLMFormat
	ParseError string // set if argument JSON could not be parsed
}

// DetectFormat examines a parsed JSON response body and determines
// whether it uses Anthropic or OpenAI format.
func DetectFormat(body map[string]any) LLMFormat {
	// Anthropic: has "content" array with objects having "type" field
	if content, ok := body["content"]; ok {
		if arr, ok := content.([]any); ok && len(arr) > 0 {
			if first, ok := arr[0].(map[string]any); ok {
				if _, hasType := first["type"]; hasType {
					return FormatAnthropic
				}
			}
		}
	}

	// OpenAI: has "choices" array with objects having "message" field
	if choices, ok := body["choices"]; ok {
		if arr, ok := choices.([]any); ok && len(arr) > 0 {
			if first, ok := arr[0].(map[string]any); ok {
				if _, hasMsg := first["message"]; hasMsg {
					return FormatOpenAI
				}
			}
		}
	}

	return FormatUnknown
}

// DetectStreamingFormat determines format from the HTTP request path/headers.
func DetectStreamingFormat(path string, headers map[string][]string) LLMFormat {
	if strings.Contains(path, "/v1/messages") {
		return FormatAnthropic
	}
	if strings.Contains(path, "/v1/chat/completions") {
		return FormatOpenAI
	}
	if _, ok := headers["Anthropic-Version"]; ok {
		return FormatAnthropic
	}
	return FormatUnknown
}

// ExtractToolCalls extracts all tool calls from a parsed response body.
// Returns nil if the response contains no tool calls.
func ExtractToolCalls(body map[string]any) ([]ToolCall, LLMFormat) {
	format := DetectFormat(body)
	switch format {
	case FormatAnthropic:
		calls := extractAnthropic(body)
		return calls, format
	case FormatOpenAI:
		calls := extractOpenAI(body)
		return calls, format
	default:
		return nil, FormatUnknown
	}
}

// extractAnthropic extracts tool_use blocks from Anthropic response format.
// Anthropic content: [{"type": "tool_use", "id": "...", "name": "...", "input": {...}}]
func extractAnthropic(body map[string]any) []ToolCall {
	content, ok := body["content"].([]any)
	if !ok {
		return nil
	}

	var calls []ToolCall
	for i, item := range content {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		blockType, _ := block["type"].(string)
		if blockType != "tool_use" {
			continue
		}

		tc := ToolCall{
			Index:  i,
			Format: FormatAnthropic,
		}
		if id, ok := block["id"].(string); ok {
			tc.ID = id
		}
		if name, ok := block["name"].(string); ok {
			tc.Name = name
		}
		if input, ok := block["input"].(map[string]any); ok {
			tc.Arguments = input
		}
		calls = append(calls, tc)
	}
	return calls
}

// extractOpenAI extracts function_call blocks from OpenAI response format.
// OpenAI: choices[0].message.tool_calls[].function.{name, arguments}
func extractOpenAI(body map[string]any) []ToolCall {
	choices, ok := body["choices"].([]any)
	if !ok || len(choices) == 0 {
		return nil
	}
	choice, ok := choices[0].(map[string]any)
	if !ok {
		return nil
	}
	message, ok := choice["message"].(map[string]any)
	if !ok {
		return nil
	}
	toolCalls, ok := message["tool_calls"].([]any)
	if !ok {
		return nil
	}

	var calls []ToolCall
	for i, item := range toolCalls {
		tc, ok := item.(map[string]any)
		if !ok {
			continue
		}

		call := ToolCall{
			Index:  i,
			Format: FormatOpenAI,
		}
		if id, ok := tc["id"].(string); ok {
			call.ID = id
		}
		if fn, ok := tc["function"].(map[string]any); ok {
			if name, ok := fn["name"].(string); ok {
				call.Name = name
			}
			if argsStr, ok := fn["arguments"].(string); ok {
				var args map[string]any
				if err := json.Unmarshal([]byte(argsStr), &args); err == nil {
					call.Arguments = args
				}
			}
		}
		calls = append(calls, call)
	}
	return calls
}

// maxArgSize limits the accumulated argument JSON to prevent OOM from malicious streams.
const maxArgSize = 1 << 20 // 1MB

// StreamBuffer accumulates streaming tool_use chunks until a complete
// tool call can be evaluated.
type StreamBuffer struct {
	calls  map[int]*streamingToolCall
	Format LLMFormat
}

type streamingToolCall struct {
	ID        string
	Name      string
	ArgJSON   strings.Builder
	Index     int
	Events    []string // buffered raw SSE lines
	Truncated bool     // set if ArgJSON exceeded maxArgSize
}

// NewStreamBuffer creates a StreamBuffer for the detected format.
func NewStreamBuffer(format LLMFormat) *StreamBuffer {
	return &StreamBuffer{
		calls:  make(map[int]*streamingToolCall),
		Format: format,
	}
}

// IsBuffering returns true if any tool call is being buffered.
func (sb *StreamBuffer) IsBuffering(index int) bool {
	_, ok := sb.calls[index]
	return ok
}

// StartToolUse begins buffering a new tool_use block.
func (sb *StreamBuffer) StartToolUse(index int, id, name string, rawEvent string) {
	sb.calls[index] = &streamingToolCall{
		ID:     id,
		Name:   name,
		Index:  index,
		Events: []string{rawEvent},
	}
}

// AppendDelta adds an input_json_delta chunk to the buffer.
// Fragments beyond maxArgSize are discarded to prevent OOM.
func (sb *StreamBuffer) AppendDelta(index int, jsonFragment string, rawEvent string) {
	if tc, ok := sb.calls[index]; ok {
		if !tc.Truncated && tc.ArgJSON.Len()+len(jsonFragment) <= maxArgSize {
			tc.ArgJSON.WriteString(jsonFragment)
		} else {
			tc.Truncated = true
		}
		tc.Events = append(tc.Events, rawEvent)
	}
}

// Complete finalizes a tool_use block and returns the assembled ToolCall.
func (sb *StreamBuffer) Complete(index int, rawEvent string) (ToolCall, []string, bool) {
	tc, ok := sb.calls[index]
	if !ok {
		return ToolCall{}, nil, false
	}

	tc.Events = append(tc.Events, rawEvent)
	events := tc.Events

	var args map[string]any
	var parseError string
	if tc.Truncated {
		parseError = "tool arguments truncated: exceeded 1MB limit"
	} else if argStr := tc.ArgJSON.String(); argStr != "" {
		if err := json.Unmarshal([]byte(argStr), &args); err != nil {
			parseError = "malformed tool arguments: " + err.Error()
		}
	}

	call := ToolCall{
		ID:         tc.ID,
		Name:       tc.Name,
		Arguments:  args,
		Index:      tc.Index,
		Format:     sb.Format,
		ParseError: parseError,
	}

	delete(sb.calls, index)
	return call, events, true
}
