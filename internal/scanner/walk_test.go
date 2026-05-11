package scanner_test

import (
	"testing"

	"github.com/neocho/ai-guard/internal/scanner"
)

func TestScanJSON_TagsPaths(t *testing.T) {
	body := []byte(`{
		"model": "claude-haiku-4-5",
		"system": "you are a helpful assistant",
		"messages": [
			{"role": "user", "content": "my key is sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"}
		],
		"metadata": {
			"contact": "alice@example.com"
		}
	}`)
	s := scanner.Default()
	fs := s.ScanJSON(body, scanner.DirectionOutbound, "req")

	wantSources := map[string]string{
		"openai_key": "req.messages[0].content",
		"email":      "req.metadata.contact",
	}
	for rule, wantSrc := range wantSources {
		found := false
		for _, f := range fs {
			if f.Rule == rule && f.Source == wantSrc {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected rule %q with source %q; got findings: %+v", rule, wantSrc, fs)
		}
	}
}

func TestScanJSON_EmptyOrInvalid(t *testing.T) {
	s := scanner.Default()
	if fs := s.ScanJSON(nil, scanner.DirectionOutbound, "req"); fs != nil {
		t.Errorf("nil input: want nil, got %v", fs)
	}
	if fs := s.ScanJSON([]byte("not json"), scanner.DirectionOutbound, "req"); fs != nil {
		t.Errorf("garbage input: want nil, got %v", fs)
	}
}

func TestIsScannable(t *testing.T) {
	cases := []struct {
		host string
		path string
		want bool
	}{
		{"api.anthropic.com:443", "/v1/messages", true},
		{"api.anthropic.com", "/v1/messages", true},
		{"api.openai.com:443", "/v1/chat/completions", true},
		{"api.openai.com:443", "/v1/responses", true},
		{"api.anthropic.com:443", "/api/event_logging/v2/batch", false},
		{"api.anthropic.com:443", "/mcp-registry/v0/servers", false},
		{"http-intake.logs.us5.datadoghq.com:443", "/api/v2/logs", false},
		{"api.anthropic.com:443", "/v1/messages?foo=bar", false}, // exact match — query gets stripped by net/http
	}
	for _, c := range cases {
		got := scanner.IsScannable(c.host, c.path)
		if got != c.want {
			t.Errorf("IsScannable(%q, %q) = %v, want %v", c.host, c.path, got, c.want)
		}
	}
}
