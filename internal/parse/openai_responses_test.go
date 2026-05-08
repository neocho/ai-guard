package parse_test

import (
	"testing"

	"github.com/neocho/ai-guard/internal/parse"
)

func TestOpenAIResponsesRequest_StringInput(t *testing.T) {
	body := []byte(`{
		"model": "gpt-5.5",
		"instructions": "you are codex",
		"input": "explain this codebase",
		"max_output_tokens": 2048,
		"stream": true
	}`)
	req, err := parse.OpenAIResponsesRequest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if req.Provider != parse.ProviderOpenAI {
		t.Errorf("Provider = %q", req.Provider)
	}
	if req.Model != "gpt-5.5" {
		t.Errorf("Model = %q", req.Model)
	}
	if req.System != "you are codex" {
		t.Errorf("System = %q", req.System)
	}
	if req.MaxTokens != 2048 {
		t.Errorf("MaxTokens = %d", req.MaxTokens)
	}
	if !req.Stream {
		t.Errorf("Stream = false, want true")
	}
	if len(req.Messages) != 1 {
		t.Fatalf("Messages = %d, want 1", len(req.Messages))
	}
	if req.Messages[0].Role != "user" || req.Messages[0].Content[0].Text != "explain this codebase" {
		t.Errorf("first message = %+v", req.Messages[0])
	}
}

func TestOpenAIResponsesRequest_ArrayInputWithFunctionCalls(t *testing.T) {
	body := []byte(`{
		"model": "gpt-5.5",
		"instructions": "...",
		"input": [
			{"role": "user", "content": "list files"},
			{"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "Bash", "arguments": "{\"command\":\"ls\"}"},
			{"type": "function_call_output", "call_id": "call_1", "output": "file1\nfile2"},
			{"role": "user", "content": "summarize"}
		]
	}`)
	req, err := parse.OpenAIResponsesRequest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(req.Messages) != 4 {
		t.Fatalf("Messages = %d, want 4", len(req.Messages))
	}
	// [0] user "list files"
	if req.Messages[0].Role != "user" || req.Messages[0].Content[0].Text != "list files" {
		t.Errorf("[0] = %+v", req.Messages[0])
	}
	// [1] function_call → assistant w/ tool_use
	a := req.Messages[1]
	if a.Role != "assistant" || a.Content[0].Type != "tool_use" {
		t.Fatalf("[1] = %+v", a)
	}
	if a.Content[0].ToolUse.Name != "Bash" {
		t.Errorf("ToolUse.Name = %q", a.Content[0].ToolUse.Name)
	}
	if string(a.Content[0].ToolUse.Input) != `{"command":"ls"}` {
		t.Errorf("ToolUse.Input = %q", string(a.Content[0].ToolUse.Input))
	}
	if a.Content[0].ToolUse.ID != "call_1" {
		t.Errorf("ToolUse.ID = %q (should prefer call_id over id)", a.Content[0].ToolUse.ID)
	}
	// [2] function_call_output → user w/ tool_result
	r := req.Messages[2]
	if r.Role != "user" || r.Content[0].Type != "tool_result" {
		t.Fatalf("[2] = %+v", r)
	}
	if r.Content[0].ToolResult.ToolUseID != "call_1" {
		t.Errorf("ToolResult.ToolUseID = %q", r.Content[0].ToolResult.ToolUseID)
	}
	if r.Content[0].ToolResult.Content != "file1\nfile2" {
		t.Errorf("ToolResult.Content = %q", r.Content[0].ToolResult.Content)
	}
	// [3] user "summarize"
	if req.Messages[3].Role != "user" || req.Messages[3].Content[0].Text != "summarize" {
		t.Errorf("[3] = %+v", req.Messages[3])
	}
}

func TestOpenAIResponsesRequest_Tools(t *testing.T) {
	body := []byte(`{
		"model": "gpt-5.5",
		"input": "hi",
		"tools": [
			{"type": "function", "name": "Bash", "description": "run shell", "parameters": {"type":"object"}},
			{"type": "web_search"}
		]
	}`)
	req, err := parse.OpenAIResponsesRequest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(req.Tools) != 2 {
		t.Fatalf("Tools = %d, want 2", len(req.Tools))
	}
	if req.Tools[0].Name != "Bash" {
		t.Errorf("first tool name = %q", req.Tools[0].Name)
	}
	// Builtin tools without a `name` field fall back to using `type`
	// as the display name (e.g. web_search → "web_search"), so callers
	// always have a non-empty label.
	if req.Tools[1].Name != "web_search" {
		t.Errorf("builtin should fall back to type as name, got %q", req.Tools[1].Name)
	}
	if req.Tools[1].Description != "(builtin)" {
		t.Errorf("builtin description = %q, want (builtin)", req.Tools[1].Description)
	}
}

func TestOpenAIResponsesResponse_NonStreaming(t *testing.T) {
	body := []byte(`{
		"id": "resp_abc",
		"object": "response",
		"model": "gpt-5.5",
		"status": "completed",
		"output": [
			{"type": "message", "role": "assistant", "content": [
				{"type": "output_text", "text": "the answer is 42"}
			]},
			{"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "Bash", "arguments": "{\"command\":\"echo 42\"}"}
		],
		"usage": {"input_tokens": 100, "output_tokens": 12}
	}`)
	resp, err := parse.OpenAIResponsesResponse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Streaming {
		t.Errorf("expected non-streaming")
	}
	if resp.ID != "resp_abc" {
		t.Errorf("ID = %q", resp.ID)
	}
	if resp.StopReason != "completed" {
		t.Errorf("StopReason = %q", resp.StopReason)
	}
	if resp.Usage.InputTokens != 100 || resp.Usage.OutputTokens != 12 {
		t.Errorf("Usage = %+v", resp.Usage)
	}
	if len(resp.Content) != 2 {
		t.Fatalf("Content = %d, want 2", len(resp.Content))
	}
	if resp.Content[0].Type != "text" || resp.Content[0].Text != "the answer is 42" {
		t.Errorf("[0] = %+v", resp.Content[0])
	}
	if resp.Content[1].Type != "tool_use" || resp.Content[1].ToolUse.Name != "Bash" {
		t.Errorf("[1] = %+v", resp.Content[1])
	}
}

func TestOpenAIResponsesResponse_SSE_CompletedFastPath(t *testing.T) {
	// The fast path: response.completed event carries the full final
	// response object. We should parse that and ignore the deltas.
	body := []byte(`event: response.created
data: {"type":"response.created","response":{"id":"resp_xyz","model":"gpt-5.5","status":"in_progress","output":[]}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_1","delta":"Hello"}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_1","delta":" world"}

event: response.completed
data: {"type":"response.completed","response":{"id":"resp_xyz","model":"gpt-5.5","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hello world"}]}],"usage":{"input_tokens":10,"output_tokens":2}}}
`)
	resp, err := parse.OpenAIResponsesResponse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !resp.Streaming {
		t.Errorf("expected streaming = true")
	}
	if resp.ID != "resp_xyz" {
		t.Errorf("ID = %q", resp.ID)
	}
	if resp.StopReason != "completed" {
		t.Errorf("StopReason = %q", resp.StopReason)
	}
	if resp.Usage.OutputTokens != 2 {
		t.Errorf("Usage.OutputTokens = %d", resp.Usage.OutputTokens)
	}
	if len(resp.Content) != 1 || resp.Content[0].Text != "Hello world" {
		t.Errorf("Content = %+v", resp.Content)
	}
}

func TestOpenAIResponsesResponse_SSE_DeltaFallback(t *testing.T) {
	// No response.completed event — we should reconstruct from deltas.
	body := []byte(`event: response.created
data: {"type":"response.created","response":{"id":"resp_partial","model":"gpt-5.5"}}

event: response.output_item.added
data: {"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","id":"msg_1","content":[]}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_1","delta":"streamed"}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_1","delta":" text"}

event: response.output_item.added
data: {"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"Bash","arguments":""}}

event: response.function_call_arguments.delta
data: {"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"command\":"}

event: response.function_call_arguments.delta
data: {"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"\"ls\"}"}
`)
	resp, err := parse.OpenAIResponsesResponse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.ID != "resp_partial" {
		t.Errorf("ID = %q", resp.ID)
	}
	if len(resp.Content) != 2 {
		t.Fatalf("Content = %d, want 2", len(resp.Content))
	}
	if resp.Content[0].Type != "text" || resp.Content[0].Text != "streamed text" {
		t.Errorf("[0] = %+v", resp.Content[0])
	}
	if resp.Content[1].Type != "tool_use" {
		t.Fatalf("[1] = %+v", resp.Content[1])
	}
	tu := resp.Content[1].ToolUse
	if tu.Name != "Bash" {
		t.Errorf("ToolUse.Name = %q", tu.Name)
	}
	if string(tu.Input) != `{"command":"ls"}` {
		t.Errorf("ToolUse.Input = %q", string(tu.Input))
	}
	if tu.ID != "call_1" {
		t.Errorf("ToolUse.ID = %q (should prefer call_id)", tu.ID)
	}
}
