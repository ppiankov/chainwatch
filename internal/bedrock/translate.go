package bedrock

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	anthropicVersion    = "bedrock-2023-05-31"
	defaultMaxTokens    = 1024
	assistantRole       = "assistant"
	chatCompletionID    = "chatcmpl-bedrock"
	chatCompletionType  = "chat.completion"
	finishReasonLength  = "length"
	finishReasonStop    = "stop"
	stopReasonMaxTokens = "max_tokens"
	systemRole          = "system"
	userRole            = "user"
)

type chatCompletionRequest struct {
	Messages    []Message `json:"messages"`
	Model       string    `json:"model"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature *float64  `json:"temperature,omitempty"`
}

type chatCompletionResponse struct {
	ID      string                 `json:"id"`
	Object  string                 `json:"object"`
	Model   string                 `json:"model"`
	Choices []chatCompletionChoice `json:"choices"`
	Usage   *chatCompletionUsage   `json:"usage,omitempty"`
}

type chatCompletionChoice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

type chatCompletionUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type anthropicMessagesRequest struct {
	AnthropicVersion string             `json:"anthropic_version"`
	Messages         []anthropicMessage `json:"messages"`
	MaxTokens        int                `json:"max_tokens"`
	System           string             `json:"system,omitempty"`
	Temperature      *float64           `json:"temperature,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicMessagesResponse struct {
	Content    []anthropicContentBlock `json:"content"`
	StopReason string                  `json:"stop_reason,omitempty"`
	Usage      anthropicUsage          `json:"usage"`
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

func translateRequest(req chatCompletionRequest) ([]byte, error) {
	if len(req.Messages) == 0 {
		return nil, fmt.Errorf("chat completion request requires at least one message")
	}

	body := anthropicMessagesRequest{
		AnthropicVersion: anthropicVersion,
		MaxTokens:        req.MaxTokens,
		Temperature:      req.Temperature,
	}
	if body.MaxTokens <= 0 {
		body.MaxTokens = defaultMaxTokens
	}

	var systemParts []string
	for i, msg := range req.Messages {
		role := strings.TrimSpace(msg.Role)
		if role == "" {
			return nil, fmt.Errorf("messages[%d].role is required", i)
		}

		switch role {
		case systemRole:
			systemParts = append(systemParts, msg.Content)
		case userRole, assistantRole:
			body.Messages = append(body.Messages, anthropicMessage{
				Role:    role,
				Content: msg.Content,
			})
		default:
			return nil, fmt.Errorf("messages[%d].role %q is not supported", i, msg.Role)
		}
	}

	if len(body.Messages) == 0 {
		return nil, fmt.Errorf("chat completion request requires at least one non-system message")
	}
	if len(systemParts) > 0 {
		body.System = strings.Join(systemParts, "\n\n")
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal anthropic request: %w", err)
	}

	return payload, nil
}

func translateResponse(body []byte) (*chatCompletionResponse, error) {
	var parsed anthropicMessagesResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode bedrock response: %w", err)
	}

	var text strings.Builder
	for _, block := range parsed.Content {
		if block.Type != "text" {
			continue
		}

		text.WriteString(block.Text)
	}

	return &chatCompletionResponse{
		ID:     chatCompletionID,
		Object: chatCompletionType,
		Choices: []chatCompletionChoice{
			{
				Index: 0,
				Message: Message{
					Role:    assistantRole,
					Content: text.String(),
				},
				FinishReason: finishReasonFromStopReason(parsed.StopReason),
			},
		},
		Usage: &chatCompletionUsage{
			PromptTokens:     parsed.Usage.InputTokens,
			CompletionTokens: parsed.Usage.OutputTokens,
			TotalTokens:      parsed.Usage.InputTokens + parsed.Usage.OutputTokens,
		},
	}, nil
}

func finishReasonFromStopReason(stopReason string) string {
	if stopReason == stopReasonMaxTokens {
		return finishReasonLength
	}

	return finishReasonStop
}
