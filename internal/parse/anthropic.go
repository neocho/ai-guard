package parse

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// AnthropicRequest parses an Anthropic Messages API request body (the JSON
// posted to /v1/messages).
func AnthropicRequest(body []byte) (*Request, error) {
	var raw struct {
		Model     string             `json:"model"`
		System    json.RawMessage    `json:"system"`
		Messages  []anthropicMessage `json:"messages"`
		Tools     []anthropicToolDef `json:"tools"`
		MaxTokens int                `json:"max_tokens"`
		Stream    bool               `json:"stream"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	return &Request{
		Provider:  ProviderAnthropic,
		Model:     raw.Model,
		System:    parseAnthropicSystem(raw.System),
		Messages:  parseAnthropicMessages(raw.Messages),
		Tools:     parseAnthropicTools(raw.Tools),
		MaxTokens: raw.MaxTokens,
		Stream:    raw.Stream,
		Raw:       body,
	}, nil
}

// AnthropicResponse parses an Anthropic Messages API response body. It
// auto-detects between non-streaming JSON (starts with `{`) and SSE event
// streams (`event: ... \n data: ... \n\n` lines).
func AnthropicResponse(body []byte) (*Response, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("empty body")
	}
	if trimmed[0] == '{' {
		return parseAnthropicNonStreaming(body)
	}
	return parseAnthropicSSE(body)
}

// --- internal types matching Anthropic's wire shape ---

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"` // string OR []block
}

type anthropicToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// --- system / messages / content / tools parsing ---

func parseAnthropicSystem(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// String form.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Array of {type:"text", text:"..."} form.
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err == nil {
		var b strings.Builder
		for i, blk := range blocks {
			if i > 0 {
				b.WriteString("\n\n")
			}
			b.WriteString(blk.Text)
		}
		return b.String()
	}
	return ""
}

func parseAnthropicMessages(in []anthropicMessage) []Message {
	out := make([]Message, 0, len(in))
	for _, m := range in {
		out = append(out, Message{
			Role:    m.Role,
			Content: parseAnthropicContent(m.Content),
		})
	}
	return out
}

func parseAnthropicContent(raw json.RawMessage) []Block {
	if len(raw) == 0 {
		return nil
	}
	// String form: single text block.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []Block{{Type: "text", Text: s}}
	}
	// Array of blocks.
	var rawBlocks []json.RawMessage
	if err := json.Unmarshal(raw, &rawBlocks); err != nil {
		return nil
	}
	out := make([]Block, 0, len(rawBlocks))
	for _, b := range rawBlocks {
		if blk := parseAnthropicBlock(b); blk != nil {
			out = append(out, *blk)
		}
	}
	return out
}

func parseAnthropicBlock(raw json.RawMessage) *Block {
	var typed struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &typed); err != nil {
		return nil
	}
	switch typed.Type {
	case "text":
		var t struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(raw, &t)
		return &Block{Type: "text", Text: t.Text}
	case "tool_use":
		var t struct {
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		}
		_ = json.Unmarshal(raw, &t)
		return &Block{Type: "tool_use", ToolUse: &ToolUse{
			ID:    t.ID,
			Name:  t.Name,
			Input: t.Input,
		}}
	case "tool_result":
		var t struct {
			ToolUseID string          `json:"tool_use_id"`
			Content   json.RawMessage `json:"content"`
			IsError   bool            `json:"is_error"`
		}
		_ = json.Unmarshal(raw, &t)
		return &Block{Type: "tool_result", ToolResult: &ToolResult{
			ToolUseID: t.ToolUseID,
			Content:   flattenAnthropicContent(t.Content),
			IsError:   t.IsError,
		}}
	}
	return nil
}

func flattenAnthropicContent(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err == nil {
		var b strings.Builder
		for i, blk := range blocks {
			if i > 0 {
				b.WriteString("\n\n")
			}
			b.WriteString(blk.Text)
		}
		return b.String()
	}
	return ""
}

func parseAnthropicTools(in []anthropicToolDef) []ToolDef {
	out := make([]ToolDef, 0, len(in))
	for _, t := range in {
		out = append(out, ToolDef{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	return out
}

// --- response parsing (non-streaming) ---

func parseAnthropicNonStreaming(body []byte) (*Response, error) {
	var raw struct {
		ID         string            `json:"id"`
		Model      string            `json:"model"`
		Content    []json.RawMessage `json:"content"`
		StopReason string            `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	var content []Block
	for _, b := range raw.Content {
		if blk := parseAnthropicBlock(b); blk != nil {
			content = append(content, *blk)
		}
	}
	return &Response{
		Provider:   ProviderAnthropic,
		ID:         raw.ID,
		Model:      raw.Model,
		Content:    content,
		StopReason: raw.StopReason,
		Usage: Usage{
			InputTokens:  raw.Usage.InputTokens,
			OutputTokens: raw.Usage.OutputTokens,
		},
		Streaming: false,
		Raw:       body,
	}, nil
}

// --- response parsing (SSE / streaming) ---
//
// Anthropic streams a sequence of named events:
//
//   event: message_start
//   data: {"type":"message_start","message":{...}}
//
//   event: content_block_start
//   data: {"type":"content_block_start","index":0,"content_block":{...}}
//
//   event: content_block_delta
//   data: {"type":"content_block_delta","index":0,"delta":{...}}
//
//   event: message_delta
//   data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{...}}
//
// We accumulate deltas into per-index Block builders and assemble the
// final response when the stream ends. Any unknown events are ignored.

func parseAnthropicSSE(body []byte) (*Response, error) {
	resp := &Response{Provider: ProviderAnthropic, Streaming: true}
	blocks := make(map[int]*Block)
	toolJSON := make(map[int]*strings.Builder) // accumulating partial_json per index

	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var currentEvent string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			handleAnthropicSSEEvent(currentEvent, []byte(data), resp, blocks, toolJSON)
		}
	}
	if err := scanner.Err(); err != nil {
		return resp, err
	}

	// Finalize any tool_use blocks: their input arrived as accumulated
	// partial_json fragments; coalesce into the Input field.
	for idx, sb := range toolJSON {
		if blk, ok := blocks[idx]; ok && blk.ToolUse != nil {
			blk.ToolUse.Input = json.RawMessage(sb.String())
		}
	}

	indices := make([]int, 0, len(blocks))
	for i := range blocks {
		indices = append(indices, i)
	}
	sort.Ints(indices)
	for _, i := range indices {
		resp.Content = append(resp.Content, *blocks[i])
	}
	return resp, nil
}

func handleAnthropicSSEEvent(event string, data []byte, resp *Response, blocks map[int]*Block, toolJSON map[int]*strings.Builder) {
	switch event {
	case "message_start":
		var m struct {
			Message struct {
				ID    string `json:"id"`
				Model string `json:"model"`
				Usage struct {
					InputTokens int `json:"input_tokens"`
				} `json:"usage"`
			} `json:"message"`
		}
		if err := json.Unmarshal(data, &m); err == nil {
			resp.ID = m.Message.ID
			resp.Model = m.Message.Model
			resp.Usage.InputTokens = m.Message.Usage.InputTokens
		}
	case "content_block_start":
		var e struct {
			Index        int             `json:"index"`
			ContentBlock json.RawMessage `json:"content_block"`
		}
		if err := json.Unmarshal(data, &e); err == nil {
			if blk := parseAnthropicBlock(e.ContentBlock); blk != nil {
				blocks[e.Index] = blk
				if blk.Type == "tool_use" {
					toolJSON[e.Index] = &strings.Builder{}
				}
			}
		}
	case "content_block_delta":
		var e struct {
			Index int `json:"index"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
		}
		if err := json.Unmarshal(data, &e); err == nil {
			blk, ok := blocks[e.Index]
			if !ok {
				return
			}
			switch e.Delta.Type {
			case "text_delta":
				blk.Text += e.Delta.Text
			case "input_json_delta":
				if sb, ok := toolJSON[e.Index]; ok {
					sb.WriteString(e.Delta.PartialJSON)
				}
			}
		}
	case "message_delta":
		var e struct {
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
			Usage struct {
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(data, &e); err == nil {
			if e.Delta.StopReason != "" {
				resp.StopReason = e.Delta.StopReason
			}
			if e.Usage.OutputTokens > 0 {
				resp.Usage.OutputTokens = e.Usage.OutputTokens
			}
		}
	}
}
