package parse

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// OpenAIResponsesRequest parses an OpenAI /v1/responses request body. The
// Responses API is OpenAI's newer agentic API (used by Codex, etc.) and
// has a different wire shape from /v1/chat/completions:
//
//   - Top-level "instructions" string instead of a system message
//   - "input" can be a string or an array of typed items mixing
//     message-style entries and standalone function_call /
//     function_call_output items
//   - Tool calls are NOT nested inside assistant messages — they're
//     siblings in the input array
//
// We normalize all of that into the same Request shape we use for
// Anthropic and chat/completions: System + Messages with text /
// tool_use / tool_result blocks.
func OpenAIResponsesRequest(body []byte) (*Request, error) {
	var raw struct {
		Model            string             `json:"model"`
		Instructions     string             `json:"instructions"`
		Input            json.RawMessage    `json:"input"` // string OR []item
		Tools            []oaiResponsesTool `json:"tools"`
		MaxOutputTokens  int                `json:"max_output_tokens"`
		MaxTokens        int                `json:"max_tokens"`
		Stream           bool               `json:"stream"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	maxTokens := raw.MaxOutputTokens
	if maxTokens == 0 {
		maxTokens = raw.MaxTokens
	}

	return &Request{
		Provider:  ProviderOpenAI,
		Model:     raw.Model,
		System:    raw.Instructions,
		Messages:  parseOAIResponsesInput(raw.Input),
		Tools:     parseOAIResponsesTools(raw.Tools),
		MaxTokens: maxTokens,
		Stream:    raw.Stream,
		Raw:       body,
	}, nil
}

// OpenAIResponsesResponse parses an OpenAI /v1/responses response body.
// Auto-detects between non-streaming JSON (starts with `{`) and SSE
// event streams (`event: response.created` etc.).
func OpenAIResponsesResponse(body []byte) (*Response, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("empty body")
	}
	if trimmed[0] == '{' {
		return parseOAIResponsesNonStreaming(body)
	}
	return parseOAIResponsesSSE(body)
}

// --- Internal types matching the Responses API wire shape. ---

type oaiResponsesTool struct {
	Type        string          `json:"type"` // "function" | "web_search" | "computer_use" | etc.
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// oaiResponseObject mirrors the `response` object that appears both as the
// non-streaming body and inside streaming response.created/.completed events.
type oaiResponseObject struct {
	ID                 string                 `json:"id"`
	Object             string                 `json:"object"`
	Model              string                 `json:"model"`
	Status             string                 `json:"status"`
	IncompleteDetails  json.RawMessage        `json:"incomplete_details"`
	Output             []oaiResponsesOutItem  `json:"output"`
	Usage              oaiResponsesUsage      `json:"usage"`
}

type oaiResponsesOutItem struct {
	Type      string                  `json:"type"`     // "message" | "function_call" | "reasoning" | ...
	Role      string                  `json:"role"`     // for message items
	Content   []oaiResponsesContent   `json:"content"`  // for message items
	ID        string                  `json:"id"`
	CallID    string                  `json:"call_id"`  // for function_call items
	Name      string                  `json:"name"`     // for function_call items
	Arguments string                  `json:"arguments"`// for function_call items
}

type oaiResponsesContent struct {
	Type string `json:"type"` // "output_text" | "input_text" | "refusal" | ...
	Text string `json:"text"`
}

type oaiResponsesUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// --- Request input parsing ---

func parseOAIResponsesInput(raw json.RawMessage) []Message {
	if len(raw) == 0 {
		return nil
	}
	// Form 1: a bare string -> single user message.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []Message{{Role: "user", Content: []Block{{Type: "text", Text: s}}}}
	}
	// Form 2: array of items.
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	var out []Message
	for _, item := range items {
		if msgs := parseOAIResponsesInputItem(item); len(msgs) > 0 {
			out = append(out, msgs...)
		}
	}
	return out
}

func parseOAIResponsesInputItem(raw json.RawMessage) []Message {
	var typed struct {
		Type    string          `json:"type"`
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
		// function_call_output:
		CallID string          `json:"call_id"`
		Output json.RawMessage `json:"output"`
		// function_call:
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
		ID        string `json:"id"`
	}
	if err := json.Unmarshal(raw, &typed); err != nil {
		return nil
	}

	switch typed.Type {
	case "function_call":
		// Standalone function_call → assistant message with single tool_use block.
		id := typed.CallID
		if id == "" {
			id = typed.ID
		}
		return []Message{{
			Role: "assistant",
			Content: []Block{{
				Type: "tool_use",
				ToolUse: &ToolUse{
					ID:    id,
					Name:  typed.Name,
					Input: json.RawMessage(typed.Arguments),
				},
			}},
		}}
	case "function_call_output":
		// Standalone function_call_output → user message with tool_result block.
		return []Message{{
			Role: "user",
			Content: []Block{{
				Type: "tool_result",
				ToolResult: &ToolResult{
					ToolUseID: typed.CallID,
					Content:   stringOrJSONString(typed.Output),
				},
			}},
		}}
	case "reasoning":
		// Reasoning items aren't user-visible content; skip.
		return nil
	}

	// Default: treat as a message with role + content. Role-less items
	// without one of the recognized types above are ignored.
	if typed.Role == "" {
		return nil
	}
	return []Message{{
		Role:    typed.Role,
		Content: parseOAIResponsesMessageContent(typed.Content),
	}}
}

// parseOAIResponsesMessageContent handles the "content" field of a
// message-typed input/output item. Form is a string OR array of typed parts.
func parseOAIResponsesMessageContent(raw json.RawMessage) []Block {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []Block{{Type: "text", Text: s}}
	}
	var parts []oaiResponsesContent
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil
	}
	var out []Block
	for _, p := range parts {
		switch p.Type {
		case "input_text", "output_text", "text":
			out = append(out, Block{Type: "text", Text: p.Text})
		}
	}
	return out
}

// stringOrJSONString returns the underlying string value if raw is a JSON
// string; otherwise returns raw rendered as JSON. Used for tool outputs
// which may be string-encoded or arbitrary JSON.
func stringOrJSONString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

func parseOAIResponsesTools(in []oaiResponsesTool) []ToolDef {
	out := make([]ToolDef, 0, len(in))
	for _, t := range in {
		// Built-in tools (web_search, computer_use, etc.) lack a `name`
		// field in OpenAI's wire format — only `type`. Fall back to type
		// so callers always have a non-empty display name.
		name := t.Name
		if name == "" {
			name = t.Type
		}
		desc := t.Description
		if t.Type != "" && t.Type != "function" {
			if desc == "" {
				desc = "(builtin)"
			}
		}
		out = append(out, ToolDef{
			Name:        name,
			Description: desc,
			InputSchema: t.Parameters,
		})
	}
	return out
}

// --- Response parsing (non-streaming) ---

func parseOAIResponsesNonStreaming(body []byte) (*Response, error) {
	var obj oaiResponseObject
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, err
	}
	resp := mapOAIResponseObject(&obj)
	resp.Raw = body
	return resp, nil
}

func mapOAIResponseObject(obj *oaiResponseObject) *Response {
	resp := &Response{
		Provider: ProviderOpenAI,
		ID:       obj.ID,
		Model:    obj.Model,
		Usage: Usage{
			InputTokens:  obj.Usage.InputTokens,
			OutputTokens: obj.Usage.OutputTokens,
		},
		StopReason: obj.Status,
	}

	for _, item := range obj.Output {
		switch item.Type {
		case "message":
			for _, c := range item.Content {
				switch c.Type {
				case "output_text", "text":
					resp.Content = append(resp.Content, Block{Type: "text", Text: c.Text})
				}
			}
		case "function_call":
			id := item.CallID
			if id == "" {
				id = item.ID
			}
			resp.Content = append(resp.Content, Block{
				Type: "tool_use",
				ToolUse: &ToolUse{
					ID:    id,
					Name:  item.Name,
					Input: json.RawMessage(item.Arguments),
				},
			})
		}
	}
	return resp
}

// --- Response parsing (SSE / streaming) ---
//
// The Responses API streams named events:
//
//   event: response.created
//   data: {"type":"response.created","response":{...partial...}}
//
//   event: response.output_text.delta
//   data: {"type":"...","item_id":"...","delta":"hello"}
//
//   event: response.completed
//   data: {"type":"response.completed","response":{...full final state...}}
//
// The completed event carries the entire final response object, so the
// fast path is "find the last response.completed and parse its .response
// like a non-streaming body." If the stream cuts off before completion,
// fall back to reconstructing from deltas.

func parseOAIResponsesSSE(body []byte) (*Response, error) {
	resp := &Response{Provider: ProviderOpenAI, Streaming: true}

	// Delta accumulators per output_item id.
	textByID := make(map[string]*strings.Builder)
	argsByID := make(map[string]*strings.Builder)
	itemMeta := make(map[string]*oaiResponsesOutItem)
	var itemOrder []string

	var finalObj *oaiResponseObject

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
			if data == "" {
				continue
			}
			handleResponsesSSEEvent(currentEvent, []byte(data),
				resp, &finalObj, textByID, argsByID, itemMeta, &itemOrder)
		}
	}
	if err := scanner.Err(); err != nil {
		return resp, err
	}

	// Fast path: completed event carries the full final response.
	if finalObj != nil {
		out := mapOAIResponseObject(finalObj)
		out.Streaming = true
		return out, nil
	}

	// Fallback: stitch from deltas. Preserve item order as observed.
	for _, id := range itemOrder {
		meta := itemMeta[id]
		if meta == nil {
			continue
		}
		switch meta.Type {
		case "message":
			if sb, ok := textByID[id]; ok && sb.Len() > 0 {
				resp.Content = append(resp.Content, Block{Type: "text", Text: sb.String()})
			}
		case "function_call":
			args := meta.Arguments
			if sb, ok := argsByID[id]; ok && sb.Len() > 0 {
				args = sb.String()
			}
			callID := meta.CallID
			if callID == "" {
				callID = meta.ID
			}
			resp.Content = append(resp.Content, Block{
				Type: "tool_use",
				ToolUse: &ToolUse{
					ID:    callID,
					Name:  meta.Name,
					Input: json.RawMessage(args),
				},
			})
		}
	}
	return resp, nil
}

func handleResponsesSSEEvent(
	event string, data []byte,
	resp *Response, finalObj **oaiResponseObject,
	textByID, argsByID map[string]*strings.Builder,
	itemMeta map[string]*oaiResponsesOutItem,
	itemOrder *[]string,
) {
	switch event {
	case "response.created":
		var e struct {
			Response oaiResponseObject `json:"response"`
		}
		if err := json.Unmarshal(data, &e); err == nil {
			if resp.ID == "" {
				resp.ID = e.Response.ID
			}
			if resp.Model == "" {
				resp.Model = e.Response.Model
			}
		}
	case "response.completed":
		var e struct {
			Response oaiResponseObject `json:"response"`
		}
		if err := json.Unmarshal(data, &e); err == nil {
			obj := e.Response
			*finalObj = &obj
		}
	case "response.output_item.added":
		var e struct {
			OutputIndex int                 `json:"output_index"`
			Item        oaiResponsesOutItem `json:"item"`
		}
		if err := json.Unmarshal(data, &e); err == nil {
			if e.Item.ID == "" {
				return
			}
			itemMeta[e.Item.ID] = &e.Item
			*itemOrder = append(*itemOrder, e.Item.ID)
		}
	case "response.output_text.delta":
		var e struct {
			ItemID string `json:"item_id"`
			Delta  string `json:"delta"`
		}
		if err := json.Unmarshal(data, &e); err == nil && e.ItemID != "" {
			sb, ok := textByID[e.ItemID]
			if !ok {
				sb = &strings.Builder{}
				textByID[e.ItemID] = sb
			}
			sb.WriteString(e.Delta)
		}
	case "response.function_call_arguments.delta":
		var e struct {
			ItemID string `json:"item_id"`
			Delta  string `json:"delta"`
		}
		if err := json.Unmarshal(data, &e); err == nil && e.ItemID != "" {
			sb, ok := argsByID[e.ItemID]
			if !ok {
				sb = &strings.Builder{}
				argsByID[e.ItemID] = sb
			}
			sb.WriteString(e.Delta)
		}
	}
}
