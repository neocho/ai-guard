package scanner_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/neocho/ai-guard/internal/scanner"
)

func TestDefault_PositiveSamples(t *testing.T) {
	cases := []struct {
		name string
		body string
		rule string
	}{
		// Synthetic samples — not real credentials.
		{"openai_key", "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH", "openai_key"},
		{"anthropic_key", "x-api-key: sk-ant-api03-" + strings.Repeat("a", 95), "anthropic_key"},
		{"pem_private", "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----", "private_key_pem"},
		{"pem_rsa", "-----BEGIN RSA PRIVATE KEY-----", "private_key_pem"},
		{"jwt", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.ABcd-EfgHIjkLmnoPQrsTuvWxYz", "jwt"},
		{"email", "Contact: alice.smith@example.com please.", "email"},
	}
	s := scanner.Default()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := s.Scan([]byte(tc.body), scanner.DirectionOutbound, "test")
			if len(fs) == 0 {
				t.Fatalf("expected at least one finding for %q, got 0", tc.body)
			}
			ok := false
			for _, f := range fs {
				if f.Rule == tc.rule {
					ok = true
					break
				}
			}
			if !ok {
				t.Fatalf("expected rule %q to match, got rules: %v", tc.rule, ruleIDs(fs))
			}
		})
	}
}

func TestDefault_NegativeSamples(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"plain_prose", "the quick brown fox jumps over the lazy dog"},
		{"empty", ""},
		{"sk_too_short", "sk-aaaa"},                       // openai needs {32,}
		{"jwt_two_chunks", "eyJabc.eyJdef"},               // jwt needs three sections
	}
	s := scanner.Default()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if fs := s.Scan([]byte(tc.body), scanner.DirectionOutbound, ""); len(fs) > 0 {
				t.Fatalf("expected 0 findings, got %v", ruleIDs(fs))
			}
		})
	}
}

func TestRedact(t *testing.T) {
	s := scanner.Default()
	body := []byte("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH")
	fs := s.Scan(body, scanner.DirectionOutbound, "")
	if len(fs) == 0 {
		t.Fatalf("want at least 1 finding, got 0")
	}
	if fs[0].Match == string(body) {
		t.Fatalf("match must be redacted, got the raw secret")
	}
	if !strings.Contains(fs[0].Match, "*") {
		t.Fatalf("redacted match should contain '*', got %q", fs[0].Match)
	}
	if !strings.HasPrefix(fs[0].Match, "sk-p") {
		t.Fatalf("redacted match should keep prefix, got %q", fs[0].Match)
	}
}

func TestScan_DirectionFiltering(t *testing.T) {
	body := []byte("a@b.co")
	s := scanner.Default()
	if fs := s.Scan(body, scanner.DirectionOutbound, ""); len(fs) != 1 {
		t.Fatalf("outbound: want 1, got %d", len(fs))
	}
	// Built-in rules are all outbound — no built-ins fire on inbound scans.
	if fs := s.Scan(body, scanner.DirectionInbound, ""); len(fs) != 0 {
		t.Fatalf("inbound (no built-ins): want 0, got %d", len(fs))
	}
}

func TestScan_BothDirection(t *testing.T) {
	// A rule with direction=both fires on either side.
	rule := scanner.Rule{
		ID:        "test_both",
		Pattern:   regexpMust(`SECRET-[A-Z]{6}`),
		Severity:  scanner.SeverityHigh,
		Direction: scanner.DirectionBoth,
	}
	s := scanner.New([]scanner.Rule{rule})
	body := []byte("hello SECRET-ABCDEF world")
	if fs := s.Scan(body, scanner.DirectionOutbound, ""); len(fs) != 1 {
		t.Fatalf("outbound: want 1, got %d", len(fs))
	}
	if fs := s.Scan(body, scanner.DirectionInbound, ""); len(fs) != 1 {
		t.Fatalf("inbound: want 1, got %d", len(fs))
	}
}

func TestScan_DeterministicOrder(t *testing.T) {
	body := []byte("first a@b.co second c@d.co")
	s := scanner.Default()
	a := s.Scan(body, scanner.DirectionOutbound, "")
	b := s.Scan(body, scanner.DirectionOutbound, "")
	if len(a) != len(b) {
		t.Fatalf("scan length differs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("finding %d differs across runs", i)
		}
	}
}

func ruleIDs(fs []scanner.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Rule
	}
	return out
}

func regexpMust(s string) *regexp.Regexp {
	return regexp.MustCompile(s)
}
