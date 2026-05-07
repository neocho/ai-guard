package api

import (
	"net"

	"github.com/neocho/ai-guard/internal/parse"
)

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
