package scanner

import "net"

// Endpoint identifies a (host, path) pair that's worth scanning.
type Endpoint struct {
	Host string `json:"host"`
	Path string `json:"path"`
}

// scannableEndpoints is the single source of truth for which endpoints
// the scanner runs over. Adding here is the deliberate "yes, this
// carries user content" gate. Everything else (telemetry, oauth,
// mcp registry, datadog logs) gets captured but never scanned.
var scannableEndpoints = []Endpoint{
	{Host: "api.anthropic.com", Path: "/v1/messages"},
	{Host: "api.openai.com", Path: "/v1/chat/completions"},
	{Host: "api.openai.com", Path: "/v1/responses"},
}

// IsScannable returns true when (host, path) is in the allowlist.
func IsScannable(host, path string) bool {
	h := stripPort(host)
	for _, e := range scannableEndpoints {
		if e.Host == h && e.Path == path {
			return true
		}
	}
	return false
}

// ScannableEndpoints returns the (host, path) allowlist. Used by the
// API so UIs can show "we scan these endpoints" without duplicating the
// list.
func ScannableEndpoints() []Endpoint {
	out := make([]Endpoint, len(scannableEndpoints))
	copy(out, scannableEndpoints)
	return out
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
