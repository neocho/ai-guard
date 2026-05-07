package parse

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// OpenAIRequest parses an OpenAI Chat Completions API request body (the
// JSON posted to /v1/chat/completions). System messages are flattened
// into Request.System (mirroring Anthropic's top-level system field) so
// downstream consumers see one shape regardless of provider.
func OpenAIRequest(body []byte) (*Request, error) {
	var raw struct {
		Model               string          `json:"model"`
		Messages            []openaiMessage `json:"messages"`
		Tools               []openaiToolDef `json:"tools"`
		MaxTokens           int             `json:"max_tokens"`
		MaxCompletionTokens int             `json:"max_completion_tokens"`
		Stream              bool            `json:"stream"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	system, messages := splitOpenAISystem(raw.Messages)
	maxTokens := raw.MaxTokens
	if maxTokens == 0 {
		maxTokens = raw.MaxCompletionTokens // some reasoning-class models use this field name instead
	}

	return &Request{
		Provider:  ProviderOpenAI,
		Model:     raw.Model,
		System:    system,
		Messages:  messages,
		Tools:     parseOpenAITools(raw.Tools),
		MaxTokens: maxTokens,
		Stream:    raw.Stream,
		Raw:       body,
	}, nil
}

// OpenAIResponse parses an OpenAI Chat Completions response body. It
// auto-detects between non-streaming JSON (starts with `{`) and SSE
// streams (`data: {...}` lines, terminated by `data: [DONE]`).
func OpenAIResponse(body []byte) (*Response, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("empty body")
	}
	if trimmed[0] == '{' {
		return parseOpenAINonStreaming(body)
	}
	return parseOpenAISSE(body)
}

// --- internal types matching OpenAI's wire shape ---

type openaiMessage struct {
	Role       string           `json:"role"`
	Content    json.RawMessage  `json:"content"`      // string | null | [{type,text|image_url}]
	ToolCalls  []openaiToolCall `json:"tool_calls"`   // assistant messages
	ToolCallID string           `json:"tool_call_id"` // role="tool" messages
}

type openaiToolCall struct {
	Index    int    `json:"index"` // populated in streaming deltas; ignored in non-streaming
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"` // JSON-as-string; in streaming it's a fragment
	} `json:"function"`
}

type openaiToolDef struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

// splitOpenAISystem pulls out role="system" messages and concatenates their
// text into a single string (preserving order, double-newline separated),
// returning the remaining messages translated into our normalized form.
func splitOpenAISystem(in []openaiMessage) (string, []Message) {
	var sysParts []string
	var rest []Message
	for _, m := range in {
		if m.Role == "system" {
			if t := openaiContentText(m.Content); t != "" {
				sysParts = append(sysParts, t)
			}
			continue
		}
		rest = append(rest, openaiMessageToNormalized(m))
	}
	return strings.Join(sysParts, "\n\n"), rest
}

// openaiMessageToNormalized maps one OpenAI message to our Message shape.
// Notably, role="tool" messages (tool results) become user messages with a
// tool_result block, matching Anthropic's representation.
func openaiMessageToNormalized(m openaiMessage) Message {
	if m.Role == "tool" {
		return Message{
			Role: "user",
			Content: []Block{{
				Type: "tool_result",
				ToolResult: &ToolResult{
					ToolUseID: m.ToolCallID,
					Content:   openaiContentText(m.Content),
				},
			}},
		}
	}

	var content []Block
	if t := openaiContentText(m.Content); t != "" {
		content = append(content, Block{Type: "text", Text: t})
	}
	for _, tc := range m.ToolCalls {
		content = append(content, Block{
			Type: "tool_use",
			ToolUse: &ToolUse{
				ID:    tc.ID,
				Name:  tc.Function.Name,
				Input: json.RawMessage(tc.Function.Arguments),
			},
		})
	}
	return Message{Role: m.Role, Content: content}
}

// openaiContentText extracts the text portion of an OpenAI content field.
// Handles the three valid shapes: string, null, and an array of typed
// parts. Image and other non-text parts are intentionally dropped.
func openaiContentText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// String form (most common).
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Array of content parts.
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var b strings.Builder
		first := true
		for _, p := range parts {
			if p.Type != "text" {
				continue
			}
			if !first {
				b.WriteString("\n\n")
			}
			b.WriteString(p.Text)
			first = false
		}
		return b.String()
	}
	return ""
}

func parseOpenAITools(in []openaiToolDef) []ToolDef {
	out := make([]ToolDef, 0, len(in))
	for _, t := range in {
		out = append(out, ToolDef{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			InputSchema: t.Function.Parameters,
		})
	}
	return out
}

// --- response parsing (non-streaming) ---

func parseOpenAINonStreaming(body []byte) (*Response, error) {
	var raw struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Index        int           `json:"index"`
			Message      openaiMessage `json:"message"`
			FinishReason string        `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	resp := &Response{
		Provider:  ProviderOpenAI,
		ID:        raw.ID,
		Model:     raw.Model,
		Streaming: false,
		Raw:       body,
		Usage: Usage{
			InputTokens:  raw.Usage.PromptTokens,
			OutputTokens: raw.Usage.CompletionTokens,
		},
	}
	if len(raw.Choices) > 0 {
		first := raw.Choices[0]
		resp.Content = openaiMessageToNormalized(first.Message).Content
		resp.StopReason = first.FinishReason
	}
	return resp, nil
}

// --- response parsing (SSE / streaming) ---
//
// OpenAI's SSE wire format: each line is either blank, `data: <json>`, or
// `data: [DONE]`. There are no `event:` lines like Anthropic. Each JSON
// payload has `choices[i].delta` with content / tool_calls deltas. Tool
// calls are identified by `index` across deltas — the first delta for an
// index typically carries id+name+empty-args, later deltas carry argument
// fragments to concatenate.

func parseOpenAISSE(body []byte) (*Response, error) {
	resp := &Response{Provider: ProviderOpenAI, Streaming: true}

	type tcAccum struct {
		ID   string
		Name string
		Args strings.Builder
	}
	toolCalls := make(map[int]*tcAccum)
	var textBuilder strings.Builder

	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" || data == "" {
			continue
		}

		var ev struct {
			ID      string `json:"id"`
			Model   string `json:"model"`
			Choices []struct {
				Delta struct {
					Content   string           `json:"content"`
					ToolCalls []openaiToolCall `json:"tool_calls"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			continue
		}

		if resp.ID == "" && ev.ID != "" {
			resp.ID = ev.ID
		}
		if resp.Model == "" && ev.Model != "" {
			resp.Model = ev.Model
		}

		for _, ch := range ev.Choices {
			if ch.Delta.Content != "" {
				textBuilder.WriteString(ch.Delta.Content)
			}
			for _, tc := range ch.Delta.ToolCalls {
				acc, ok := toolCalls[tc.Index]
				if !ok {
					acc = &tcAccum{}
					toolCalls[tc.Index] = acc
				}
				if tc.ID != "" {
					acc.ID = tc.ID
				}
				if tc.Function.Name != "" {
					acc.Name = tc.Function.Name
				}
				acc.Args.WriteString(tc.Function.Arguments)
			}
			if ch.FinishReason != "" {
				resp.StopReason = ch.FinishReason
			}
		}
		if ev.Usage != nil {
			resp.Usage.InputTokens = ev.Usage.PromptTokens
			resp.Usage.OutputTokens = ev.Usage.CompletionTokens
		}
	}
	if err := scanner.Err(); err != nil {
		return resp, err
	}

	if textBuilder.Len() > 0 {
		resp.Content = append(resp.Content, Block{Type: "text", Text: textBuilder.String()})
	}
	indices := make([]int, 0, len(toolCalls))
	for i := range toolCalls {
		indices = append(indices, i)
	}
	sort.Ints(indices)
	for _, i := range indices {
		acc := toolCalls[i]
		resp.Content = append(resp.Content, Block{
			Type: "tool_use",
			ToolUse: &ToolUse{
				ID:    acc.ID,
				Name:  acc.Name,
				Input: json.RawMessage(acc.Args.String()),
			},
		})
	}
	return resp, nil
}
