package intercept

import (
	"encoding/json"
	"testing"
)

func FuzzExtractToolCalls(f *testing.F) {
	// Anthropic format
	f.Add([]byte(`{"content":[{"type":"tool_use","id":"toolu_1","name":"run_command","input":{"command":"ls"}}]}`))

	// OpenAI format
	f.Add([]byte(`{"choices":[{"message":{"tool_calls":[{"id":"call_1","function":{"name":"run_command","arguments":"{\"command\":\"ls\"}"}}]}}]}`))

	// No tool calls
	f.Add([]byte(`{"content":[{"type":"text","text":"Hello"}]}`))

	// Empty JSON
	f.Add([]byte(`{}`))

	// Garbage
	f.Add([]byte(`not json at all`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var body map[string]any
		if err := json.Unmarshal(data, &body); err != nil {
			return // skip non-JSON inputs for ExtractToolCalls
		}
		// Must not panic
		ExtractToolCalls(body)
	})
}

func FuzzStreamBufferDelta(f *testing.F) {
	f.Add("toolu_1", "run_command", `{"command":"ls"}`)
	f.Add("toolu_2", "file_write", `{"path":"/tmp/test","content":"hello"}`)
	f.Add("", "", "")
	f.Add("x", "y", `{{{not json`)

	f.Fuzz(func(t *testing.T, id, name, argJSON string) {
		sb := NewStreamBuffer(FormatAnthropic)
		sb.StartToolUse(0, id, name, "event:start")

		// Feed the argument JSON in chunks
		for i := 0; i < len(argJSON); i += 10 {
			end := i + 10
			if end > len(argJSON) {
				end = len(argJSON)
			}
			sb.AppendDelta(0, argJSON[i:end], "event:delta")
		}

		// Must not panic
		call, _, ok := sb.Complete(0, "event:complete")
		if ok && call.ParseError == "" && call.Arguments != nil {
			// Valid parse — arguments should be a map
			_ = call.Arguments
		}
	})
}
