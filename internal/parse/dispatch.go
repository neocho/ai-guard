package parse

import (
	"encoding/json"
	"net"
)

// Dispatch picks the right provider parser based on host + path. Returns
// nil for either side when the capture isn't from a recognized API or
// when parsing fails — callers fall back to surfacing raw bodies.
func Dispatch(host, path string, reqBody, respBody []byte) (*Request, *Response) {
	h := stripPort(host)
	switch {
	case h == "api.anthropic.com" && path == "/v1/messages":
		var req *Request
		var resp *Response
		if len(reqBody) > 0 {
			if r, err := AnthropicRequest(reqBody); err == nil {
				req = r
			}
		}
		if len(respBody) > 0 {
			if r, err := AnthropicResponse(respBody); err == nil {
				resp = r
			}
		}
		return req, resp
	case h == "api.openai.com" && path == "/v1/chat/completions":
		var req *Request
		var resp *Response
		if len(reqBody) > 0 {
			if r, err := OpenAIRequest(reqBody); err == nil {
				req = r
			}
		}
		if len(respBody) > 0 {
			if r, err := OpenAIResponse(respBody); err == nil {
				resp = r
			}
		}
		return req, resp
	case h == "api.openai.com" && path == "/v1/responses":
		var req *Request
		var resp *Response
		if len(reqBody) > 0 {
			if r, err := OpenAIResponsesRequest(reqBody); err == nil {
				req = r
			}
		}
		if len(respBody) > 0 {
			if r, err := OpenAIResponsesResponse(respBody); err == nil {
				resp = r
			}
		}
		return req, resp
	}
	return nil, nil
}

// NormalizeRequest replaces nil slices with empty ones so JSON encoding
// emits `[]` instead of `null`. Strict-typed clients (Swift Codable,
// strongly-typed TypeScript, etc.) reject `null` for non-optional array
// fields; emitting empty arrays sidesteps that whole class of bug.
func NormalizeRequest(r *Request) {
	if r == nil {
		return
	}
	if r.Messages == nil {
		r.Messages = []Message{}
	}
	if r.Tools == nil {
		r.Tools = []ToolDef{}
	}
	for i := range r.Messages {
		if r.Messages[i].Content == nil {
			r.Messages[i].Content = []Block{}
		}
		for j := range r.Messages[i].Content {
			NormalizeBlock(&r.Messages[i].Content[j])
		}
	}
	for i := range r.Tools {
		if r.Tools[i].InputSchema == nil {
			r.Tools[i].InputSchema = json.RawMessage("null")
		}
	}
}

// NormalizeResponse is the response-side equivalent of NormalizeRequest.
func NormalizeResponse(r *Response) {
	if r == nil {
		return
	}
	if r.Content == nil {
		r.Content = []Block{}
	}
	for i := range r.Content {
		NormalizeBlock(&r.Content[i])
	}
}

// NormalizeBlock fixes per-block nullable fields.
func NormalizeBlock(b *Block) {
	if b == nil {
		return
	}
	if b.ToolUse != nil && b.ToolUse.Input == nil {
		b.ToolUse.Input = json.RawMessage("null")
	}
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
