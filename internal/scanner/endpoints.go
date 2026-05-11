package scanner

import "net"

// IsScannable returns true when (host, path) is a known AI-prompt
// endpoint worth scanning. Anything else (telemetry, oauth, mcp
// registry, datadog logs) gets captured but never scanned — those bodies
// regularly carry the same email or session id dozens of times and
// produce useless finding-noise that drowns out the real signal.
//
// Expand the allowlist when a new provider/endpoint surfaces. Adding
// here is the deliberate "yes, this carries user content" gate.
func IsScannable(host, path string) bool {
	h := stripPort(host)
	switch {
	case h == "api.anthropic.com" && path == "/v1/messages":
		return true
	case h == "api.openai.com" && (path == "/v1/chat/completions" || path == "/v1/responses"):
		return true
	}
	return false
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
