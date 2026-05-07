package parse_test

import (
	"strings"
	"testing"

	"github.com/neocho/ai-guard/internal/parse"
)

func TestOpenAIRequest_Basic(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4o",
		"max_tokens": 1024,
		"messages": [
			{"role": "system", "content": "you are helpful"},
			{"role": "user", "content": "hello"},
			{"role": "assistant", "content": "hi there"}
		]
	}`)
	req, err := parse.OpenAIRequest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if req.Provider != parse.ProviderOpenAI {
		t.Errorf("Provider = %q, want openai", req.Provider)
	}
	if req.Model != "gpt-4o" {
		t.Errorf("Model = %q", req.Model)
	}
	if req.System != "you are helpful" {
		t.Errorf("System should flatten from system message, got %q", req.System)
	}
	if len(req.Messages) != 2 {
		t.Fatalf("Messages count = %d, want 2 (system stripped)", len(req.Messages))
	}
	if req.Messages[0].Role != "user" || req.Messages[0].Content[0].Text != "hello" {
		t.Errorf("first non-system msg wrong: %+v", req.Messages[0])
	}
	if req.MaxTokens != 1024 {
		t.Errorf("MaxTokens = %d", req.MaxTokens)
	}
}

func TestOpenAIRequest_MaxCompletionTokensFallback(t *testing.T) {
	body := []byte(`{
		"model": "o1-mini",
		"max_completion_tokens": 4096,
		"messages": [{"role": "user", "content": "hi"}]
	}`)
	req, err := parse.OpenAIRequest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if req.MaxTokens != 4096 {
		t.Errorf("MaxTokens should fall back to max_completion_tokens, got %d", req.MaxTokens)
	}
}

func TestOpenAIRequest_MultipleSystemMessages(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4o",
		"messages": [
			{"role": "system", "content": "first directive"},
			{"role": "user", "content": "ok"},
			{"role": "system", "content": "second directive"}
		]
	}`)
	req, err := parse.OpenAIRequest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.Contains(req.System, "first directive") || !strings.Contains(req.System, "second directive") {
		t.Errorf("System should contain both, got %q", req.System)
	}
	if len(req.Messages) != 1 {
		t.Errorf("non-system messages = %d, want 1", len(req.Messages))
	}
}

func TestOpenAIRequest_ToolCallsAndResults(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4o",
		"messages": [
			{"role": "user", "content": "list files"},
			{"role": "assistant", "content": null, "tool_calls": [
				{"id": "call_1", "type": "function", "function": {"name": "Bash", "arguments": "{\"command\":\"ls\"}"}}
			]},
			{"role": "tool", "tool_call_id": "call_1", "content": "file1\nfile2"}
		]
	}`)
	req, err := parse.OpenAIRequest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(req.Messages) != 3 {
		t.Fatalf("messages = %d, want 3", len(req.Messages))
	}
	a := req.Messages[1]
	if a.Role != "assistant" {
		t.Errorf("second message role = %q", a.Role)
	}
	if len(a.Content) != 1 || a.Content[0].Type != "tool_use" {
		t.Fatalf("expected single tool_use block on assistant, got %+v", a.Content)
	}
	tu := a.Content[0].ToolUse
	if tu.Name != "Bash" {
		t.Errorf("tool name = %q", tu.Name)
	}
	if string(tu.Input) != `{"command":"ls"}` {
		t.Errorf("tool input = %q", string(tu.Input))
	}
	tr := req.Messages[2]
	if tr.Role != "user" {
		t.Errorf("tool message should normalize to user role, got %q", tr.Role)
	}
	if len(tr.Content) != 1 || tr.Content[0].Type != "tool_result" {
		t.Fatalf("expected tool_result block, got %+v", tr.Content)
	}
	if tr.Content[0].ToolResult.ToolUseID != "call_1" {
		t.Errorf("tool_result tool_use_id = %q", tr.Content[0].ToolResult.ToolUseID)
	}
	if tr.Content[0].ToolResult.Content != "file1\nfile2" {
		t.Errorf("tool_result content = %q", tr.Content[0].ToolResult.Content)
	}
}

func TestOpenAIRequest_ToolDefs(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4o",
		"messages": [],
		"tools": [
			{"type": "function", "function": {"name": "Bash", "description": "run shell", "parameters": {"type":"object"}}},
			{"type": "function", "function": {"name": "Read", "description": "read file", "parameters": {"type":"object"}}}
		]
	}`)
	req, err := parse.OpenAIRequest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(req.Tools) != 2 {
		t.Fatalf("tools = %d, want 2", len(req.Tools))
	}
	if req.Tools[0].Name != "Bash" || req.Tools[1].Name != "Read" {
		t.Errorf("tool names wrong: %+v", req.Tools)
	}
}

func TestOpenAIResponse_NonStreaming(t *testing.T) {
	body := []byte(`{
		"id": "chatcmpl-abc",
		"object": "chat.completion",
		"model": "gpt-4o",
		"choices": [{
			"index": 0,
			"message": {
				"role": "assistant",
				"content": "the answer is 42",
				"tool_calls": [
					{"id": "call_1", "type": "function", "function": {"name": "Bash", "arguments": "{\"command\":\"echo 42\"}"}}
				]
			},
			"finish_reason": "tool_calls"
		}],
		"usage": {"prompt_tokens": 100, "completion_tokens": 12}
	}`)
	resp, err := parse.OpenAIResponse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Streaming {
		t.Errorf("expected non-streaming")
	}
	if resp.ID != "chatcmpl-abc" {
		t.Errorf("ID = %q", resp.ID)
	}
	if resp.StopReason != "tool_calls" {
		t.Errorf("StopReason = %q", resp.StopReason)
	}
	if resp.Usage.InputTokens != 100 || resp.Usage.OutputTokens != 12 {
		t.Errorf("Usage = %+v", resp.Usage)
	}
	if len(resp.Content) != 2 {
		t.Fatalf("Content blocks = %d, want 2 (text + tool_use)", len(resp.Content))
	}
	if resp.Content[0].Type != "text" || resp.Content[0].Text != "the answer is 42" {
		t.Errorf("first block = %+v", resp.Content[0])
	}
	if resp.Content[1].Type != "tool_use" || resp.Content[1].ToolUse.Name != "Bash" {
		t.Errorf("second block = %+v", resp.Content[1])
	}
}

func TestOpenAIResponse_SSE(t *testing.T) {
	// Synthetic SSE stream: text deltas + a tool_call assembled across
	// multiple argument fragments + finish_reason + [DONE].
	body := []byte(`data: {"id":"chatcmpl-x","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant"}}]}

data: {"id":"chatcmpl-x","choices":[{"index":0,"delta":{"content":"Hello"}}]}

data: {"id":"chatcmpl-x","choices":[{"index":0,"delta":{"content":" world"}}]}

data: {"id":"chatcmpl-x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"Bash","arguments":""}}]}}]}

data: {"id":"chatcmpl-x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"command\":"}}]}}]}

data: {"id":"chatcmpl-x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"echo hi\"}"}}]}}]}

data: {"id":"chatcmpl-x","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":50,"completion_tokens":8}}

data: [DONE]
`)
	resp, err := parse.OpenAIResponse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !resp.Streaming {
		t.Errorf("expected streaming")
	}
	if resp.ID != "chatcmpl-x" {
		t.Errorf("ID = %q", resp.ID)
	}
	if resp.Model != "gpt-4o" {
		t.Errorf("Model = %q", resp.Model)
	}
	if resp.StopReason != "tool_calls" {
		t.Errorf("StopReason = %q", resp.StopReason)
	}
	if resp.Usage.InputTokens != 50 || resp.Usage.OutputTokens != 8 {
		t.Errorf("Usage = %+v", resp.Usage)
	}
	if len(resp.Content) != 2 {
		t.Fatalf("Content blocks = %d, want 2", len(resp.Content))
	}
	if resp.Content[0].Type != "text" || resp.Content[0].Text != "Hello world" {
		t.Errorf("text block = %+v", resp.Content[0])
	}
	if resp.Content[1].Type != "tool_use" || resp.Content[1].ToolUse == nil {
		t.Fatalf("expected tool_use block, got %+v", resp.Content[1])
	}
	tu := resp.Content[1].ToolUse
	if tu.Name != "Bash" {
		t.Errorf("ToolUse.Name = %q", tu.Name)
	}
	if string(tu.Input) != `{"command":"echo hi"}` {
		t.Errorf("ToolUse.Input reassembled = %q", string(tu.Input))
	}
}
