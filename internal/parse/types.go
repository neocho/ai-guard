// Package parse normalizes provider-specific chat-completion API payloads
// (Anthropic Messages, OpenAI chat/completions) into a common shape used
// by the UI, scanners, and policy engine. Parsers in this package operate
// on already-decompressed body bytes; capture-side decompression is the
// proxy's responsibility.
package parse

import "encoding/json"

// Provider identifies which API a Request or Response was parsed from.
const (
	ProviderAnthropic = "anthropic"
	ProviderOpenAI    = "openai"
)

// Request is a normalized chat-completion request.
type Request struct {
	Provider  string          `json:"provider"`
	Model     string          `json:"model"`
	System    string          `json:"system"`
	Messages  []Message       `json:"messages"`
	Tools     []ToolDef       `json:"tools"`
	MaxTokens int             `json:"max_tokens"`
	Stream    bool            `json:"stream"`
	Raw       json.RawMessage `json:"-"` // internal; not serialized for API
}

// Response is a normalized chat-completion response.
type Response struct {
	Provider   string          `json:"provider"`
	ID         string          `json:"id"`
	Model      string          `json:"model"`
	Content    []Block         `json:"content"`
	StopReason string          `json:"stop_reason"`
	Usage      Usage           `json:"usage"`
	Streaming  bool            `json:"streaming"`
	Raw        json.RawMessage `json:"-"` // internal; not serialized for API
}

// Message is one user/assistant/system turn.
type Message struct {
	Role    string  `json:"role"`
	Content []Block `json:"content"`
}

// Block is one piece of message content. Exactly one of Text / ToolUse /
// ToolResult is populated based on Type.
type Block struct {
	Type       string      `json:"type"`
	Text       string      `json:"text,omitempty"`
	ToolUse    *ToolUse    `json:"tool_use,omitempty"`
	ToolResult *ToolResult `json:"tool_result,omitempty"`
}

// ToolUse is a request from the model to invoke a tool.
type ToolUse struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// ToolResult is the output of a tool call sent back to the model.
type ToolResult struct {
	ToolUseID string `json:"tool_use_id"`
	Content   string `json:"content"`
	IsError   bool   `json:"is_error,omitempty"`
}

// ToolDef is a tool the agent advertises to the model.
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// Usage reports token counts. Some fields may be 0 when not returned by
// the provider (especially mid-stream).
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}
