package parse_test

import (
	"strings"
	"testing"

	"github.com/neocho/ai-guard/internal/parse"
)

func TestAnthropicRequest_Basic(t *testing.T) {
	body := []byte(`{
		"model": "claude-test",
		"max_tokens": 1024,
		"system": "you are a helpful assistant",
		"messages": [
			{"role": "user", "content": "hello"},
			{"role": "assistant", "content": "hi there"}
		]
	}`)
	req, err := parse.AnthropicRequest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if req.Provider != parse.ProviderAnthropic {
		t.Errorf("Provider = %q, want anthropic", req.Provider)
	}
	if req.Model != "claude-test" {
		t.Errorf("Model = %q, want claude-test", req.Model)
	}
	if req.MaxTokens != 1024 {
		t.Errorf("MaxTokens = %d, want 1024", req.MaxTokens)
	}
	if req.System != "you are a helpful assistant" {
		t.Errorf("System = %q", req.System)
	}
	if len(req.Messages) != 2 {
		t.Fatalf("Messages count = %d, want 2", len(req.Messages))
	}
	if req.Messages[0].Role != "user" || req.Messages[0].Content[0].Text != "hello" {
		t.Errorf("first message wrong: %+v", req.Messages[0])
	}
}

func TestAnthropicRequest_SystemAsBlocks(t *testing.T) {
	body := []byte(`{
		"model": "claude-test",
		"system": [
			{"type": "text", "text": "part one"},
			{"type": "text", "text": "part two"}
		],
		"messages": []
	}`)
	req, err := parse.AnthropicRequest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.Contains(req.System, "part one") || !strings.Contains(req.System, "part two") {
		t.Errorf("System should contain both parts, got %q", req.System)
	}
}

func TestAnthropicRequest_ToolUseAndResult(t *testing.T) {
	body := []byte(`{
		"model": "claude-test",
		"messages": [
			{"role": "user", "content": "list files"},
			{"role": "assistant", "content": [
				{"type": "text", "text": "I will list files."},
				{"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "ls"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "toolu_1", "content": "file1\nfile2"}
			]}
		]
	}`)
	req, err := parse.AnthropicRequest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(req.Messages) != 3 {
		t.Fatalf("messages count = %d, want 3", len(req.Messages))
	}
	a := req.Messages[1]
	if len(a.Content) != 2 {
		t.Fatalf("assistant content blocks = %d, want 2", len(a.Content))
	}
	if a.Content[1].Type != "tool_use" || a.Content[1].ToolUse == nil {
		t.Fatalf("expected tool_use block, got %+v", a.Content[1])
	}
	if a.Content[1].ToolUse.Name != "Bash" {
		t.Errorf("ToolUse.Name = %q, want Bash", a.Content[1].ToolUse.Name)
	}
	tr := req.Messages[2].Content[0]
	if tr.Type != "tool_result" || tr.ToolResult == nil {
		t.Fatalf("expected tool_result block, got %+v", tr)
	}
	if tr.ToolResult.Content != "file1\nfile2" {
		t.Errorf("tool_result content = %q", tr.ToolResult.Content)
	}
	if tr.ToolResult.ToolUseID != "toolu_1" {
		t.Errorf("tool_result tool_use_id = %q", tr.ToolResult.ToolUseID)
	}
}

func TestAnthropicRequest_ToolDefs(t *testing.T) {
	body := []byte(`{
		"model": "claude-test",
		"messages": [],
		"tools": [
			{"name": "Bash", "description": "run a shell command", "input_schema": {"type":"object"}},
			{"name": "Read", "description": "read a file", "input_schema": {"type":"object"}}
		]
	}`)
	req, err := parse.AnthropicRequest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(req.Tools) != 2 {
		t.Fatalf("tools count = %d, want 2", len(req.Tools))
	}
	if req.Tools[0].Name != "Bash" || req.Tools[1].Name != "Read" {
		t.Errorf("tool names wrong: %+v", req.Tools)
	}
}

func TestAnthropicResponse_NonStreaming(t *testing.T) {
	body := []byte(`{
		"id": "msg_test",
		"model": "claude-test",
		"content": [
			{"type": "text", "text": "the answer is 42"}
		],
		"stop_reason": "end_turn",
		"usage": {"input_tokens": 100, "output_tokens": 12}
	}`)
	resp, err := parse.AnthropicResponse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Streaming {
		t.Errorf("expected non-streaming")
	}
	if resp.ID != "msg_test" {
		t.Errorf("ID = %q", resp.ID)
	}
	if resp.StopReason != "end_turn" {
		t.Errorf("StopReason = %q", resp.StopReason)
	}
	if resp.Usage.InputTokens != 100 || resp.Usage.OutputTokens != 12 {
		t.Errorf("Usage = %+v", resp.Usage)
	}
	if len(resp.Content) != 1 || resp.Content[0].Text != "the answer is 42" {
		t.Errorf("Content = %+v", resp.Content)
	}
}

func TestAnthropicResponse_SSE(t *testing.T) {
	// A trimmed-down SSE stream covering: message_start, two content blocks
	// (text + tool_use), text/JSON deltas, and message_delta with stop info.
	body := []byte(`event: message_start
data: {"type":"message_start","message":{"id":"msg_xyz","model":"claude-test","usage":{"input_tokens":42}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" world"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"Bash","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":"}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"ls\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":1}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":7}}

event: message_stop
data: {"type":"message_stop"}
`)
	resp, err := parse.AnthropicResponse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !resp.Streaming {
		t.Errorf("expected streaming = true")
	}
	if resp.ID != "msg_xyz" {
		t.Errorf("ID = %q", resp.ID)
	}
	if resp.Model != "claude-test" {
		t.Errorf("Model = %q", resp.Model)
	}
	if resp.StopReason != "tool_use" {
		t.Errorf("StopReason = %q, want tool_use", resp.StopReason)
	}
	if resp.Usage.InputTokens != 42 || resp.Usage.OutputTokens != 7 {
		t.Errorf("Usage = %+v", resp.Usage)
	}
	if len(resp.Content) != 2 {
		t.Fatalf("Content count = %d, want 2", len(resp.Content))
	}
	if resp.Content[0].Type != "text" || resp.Content[0].Text != "Hello world" {
		t.Errorf("first block = %+v", resp.Content[0])
	}
	if resp.Content[1].Type != "tool_use" || resp.Content[1].ToolUse == nil {
		t.Fatalf("second block should be tool_use, got %+v", resp.Content[1])
	}
	tu := resp.Content[1].ToolUse
	if tu.Name != "Bash" {
		t.Errorf("ToolUse.Name = %q", tu.Name)
	}
	if string(tu.Input) != `{"command":"ls"}` {
		t.Errorf("ToolUse.Input reassembled = %q, want {\"command\":\"ls\"}", string(tu.Input))
	}
}
