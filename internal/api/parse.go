package api

import (
	"encoding/json"
	"net"

	"github.com/neocho/ai-guard/internal/parse"
)

// normalizeRequest replaces nil slices with empty ones so JSON encoding
// emits `[]` instead of `null`. Strict-typed clients (Swift Codable,
// strongly-typed TypeScript, etc.) reject `null` for non-optional array
// fields; emitting empty arrays sidesteps that whole class of bug.
func normalizeRequest(r *parse.Request) {
	if r == nil {
		return
	}
	if r.Messages == nil {
		r.Messages = []parse.Message{}
	}
	if r.Tools == nil {
		r.Tools = []parse.ToolDef{}
	}
	for i := range r.Messages {
		if r.Messages[i].Content == nil {
			r.Messages[i].Content = []parse.Block{}
		}
		for j := range r.Messages[i].Content {
			normalizeBlock(&r.Messages[i].Content[j])
		}
	}
	for i := range r.Tools {
		if r.Tools[i].InputSchema == nil {
			r.Tools[i].InputSchema = json.RawMessage("null")
		}
	}
}

func normalizeResponse(r *parse.Response) {
	if r == nil {
		return
	}
	if r.Content == nil {
		r.Content = []parse.Block{}
	}
	for i := range r.Content {
		normalizeBlock(&r.Content[i])
	}
}

func normalizeBlock(b *parse.Block) {
	if b == nil {
		return
	}
	if b.ToolUse != nil && b.ToolUse.Input == nil {
		b.ToolUse.Input = json.RawMessage("null")
	}
}

// dispatchParse calls the right provider parser based on host + path. When
// the capture isn't from a recognized API, both returns are nil and we fall
// back to surfacing only raw bodies in the API response. Errors during
// parsing don't fail the request — the parsed fields just stay nil.
func dispatchParse(host, path string, reqBody, respBody []byte) (*parse.Request, *parse.Response) {
	h := stripPort(host)
	switch {
	case h == "api.anthropic.com" && path == "/v1/messages":
		var req *parse.Request
		var resp *parse.Response
		if len(reqBody) > 0 {
			if r, err := parse.AnthropicRequest(reqBody); err == nil {
				req = r
			}
		}
		if len(respBody) > 0 {
			if r, err := parse.AnthropicResponse(respBody); err == nil {
				resp = r
			}
		}
		return req, resp
	case h == "api.openai.com" && path == "/v1/chat/completions":
		var req *parse.Request
		var resp *parse.Response
		if len(reqBody) > 0 {
			if r, err := parse.OpenAIRequest(reqBody); err == nil {
				req = r
			}
		}
		if len(respBody) > 0 {
			if r, err := parse.OpenAIResponse(respBody); err == nil {
				resp = r
			}
		}
		return req, resp
	case h == "api.openai.com" && path == "/v1/responses":
		var req *parse.Request
		var resp *parse.Response
		if len(reqBody) > 0 {
			if r, err := parse.OpenAIResponsesRequest(reqBody); err == nil {
				req = r
			}
		}
		if len(respBody) > 0 {
			if r, err := parse.OpenAIResponsesResponse(respBody); err == nil {
				resp = r
			}
		}
		return req, resp
	}
	return nil, nil
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
