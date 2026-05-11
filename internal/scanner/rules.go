package scanner

import "regexp"

// DefaultRules returns the built-in v0 rule set.
//
// All built-ins are outbound — they catch secrets/PII leaving the user's
// machine. Scope is intentionally tight: only patterns whose format we
// can verify against vendor docs or RFCs end up here. Looser-format
// rules (AWS, GitHub, Stripe, Google, Slack, US SSN) were considered
// but pulled out — they're easy to write but easy to false-positive,
// and false positives at the detection layer corrupt the policy engine
// downstream. Users can add them back via ~/.aig/rules.yaml.
//
// No built-in inbound rules in v0; users opt in via rules.yaml because
// inbound false positives (every "rm -rf node_modules" lighting up)
// create alert fatigue, and the right patterns depend on the user's
// environment.
func DefaultRules() []Rule {
	return []Rule{
		// Anthropic API key. sk-ant-api01- / sk-ant-admin01- + long tail.
		{
			ID:          "anthropic_key",
			Description: "Anthropic API key",
			Pattern:     regexp.MustCompile(`\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}\b`),
			Severity:    SeverityHigh,
			Direction:   DirectionOutbound,
		},
		// OpenAI API key. sk-, sk-proj-, sk-svcacct- variants.
		{
			ID:          "openai_key",
			Description: "OpenAI API key",
			Pattern:     regexp.MustCompile(`\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b`),
			Severity:    SeverityHigh,
			Direction:   DirectionOutbound,
		},
		// PEM private-key headers (RFC 7468). Covers RSA/EC/OPENSSH/PGP/generic.
		{
			ID:          "private_key_pem",
			Description: "PEM-encoded private key header",
			Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`),
			Severity:    SeverityHigh,
			Direction:   DirectionOutbound,
		},
		// JWT — three base64url chunks separated by dots, header starts with "ey".
		// Medium severity: non-secret JWTs (id tokens, public claims) are common.
		{
			ID:          "jwt",
			Description: "JSON Web Token (eyJ...eyJ...sig)",
			Pattern:     regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`),
			Severity:    SeverityMedium,
			Direction:   DirectionOutbound,
		},
		// Email — RFC-5322-lite. PII signal, not a secret.
		{
			ID:          "email",
			Description: "Email address",
			Pattern:     regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
			Severity:    SeverityLow,
			Direction:   DirectionOutbound,
		},
	}
}
