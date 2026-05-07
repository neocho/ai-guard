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
	Provider  string
	Model     string
	System    string // Anthropic top-level system; OpenAI flattens system messages here
	Messages  []Message
	Tools     []ToolDef
	MaxTokens int
	Stream    bool
	Raw       json.RawMessage // original body, preserved for debugging
}

// Response is a normalized chat-completion response.
type Response struct {
	Provider   string
	ID         string
	Model      string
	Content    []Block
	StopReason string
	Usage      Usage
	Streaming  bool            // true if parsed from an SSE event stream
	Raw        json.RawMessage // original body when non-streaming; nil for SSE
}

// Message is one user/assistant/system turn.
type Message struct {
	Role    string // "user" | "assistant" | "system"
	Content []Block
}

// Block is one piece of message content. Exactly one of Text / ToolUse /
// ToolResult is populated based on Type.
type Block struct {
	Type       string // "text" | "tool_use" | "tool_result"
	Text       string
	ToolUse    *ToolUse
	ToolResult *ToolResult
}

// ToolUse is a request from the model to invoke a tool.
type ToolUse struct {
	ID    string
	Name  string
	Input json.RawMessage // tool-specific JSON object
}

// ToolResult is the output of a tool call sent back to the model.
type ToolResult struct {
	ToolUseID string
	Content   string // flattened (Anthropic allows array of content blocks)
	IsError   bool
}

// ToolDef is a tool the agent advertises to the model.
type ToolDef struct {
	Name        string
	Description string
	InputSchema json.RawMessage
}

// Usage reports token counts. Some fields may be 0 when not returned by
// the provider (especially mid-stream).
type Usage struct {
	InputTokens  int
	OutputTokens int
}
