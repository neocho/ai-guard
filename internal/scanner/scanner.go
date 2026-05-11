// Package scanner detects secrets, PII, and other policy-relevant patterns
// in captured request/response content.
//
// The scanner is a pure function: bytes (or reassembled strings) in,
// findings out. It does not block, log, or store — those are the proxy's
// and policy engine's jobs (T-011, T-012). Splitting concerns this way
// means the scanner stays small and trivially testable.
//
// v0 is regex-only with high-confidence built-in rules + an optional
// user YAML at ~/.aig/rules.yaml. Entropy / keyword / validator passes
// belong in a follow-up once we have real captures to tune against.
package scanner

import (
	"regexp"
)

// Direction is which side of the proxy a finding came from.
type Direction string

const (
	DirectionOutbound Direction = "outbound" // request body — agent → service
	DirectionInbound  Direction = "inbound"  // response body — service → agent
	DirectionBoth     Direction = "both"     // rule applies to both sides
)

// Severity is how confident we are this is a real leak/risk. Used by the
// policy engine to decide allow/warn/block.
type Severity string

const (
	SeverityHigh   Severity = "high"   // tight rule, near-zero false positives
	SeverityMedium Severity = "medium" // looser rule, occasional false positives
	SeverityLow    Severity = "low"    // PII/hint, rarely a leak by itself
)

// Action is what the proxy does when a finding from this rule fires.
//   - allow:  record the finding, no notification, forward upstream
//   - warn:   record + fire Mac notification, forward upstream
//   - block:  return 403 to the agent, do not forward
type Action string

const (
	ActionAllow Action = "allow"
	ActionWarn  Action = "warn"
	ActionBlock Action = "block"
)

// DefaultAction is what a rule gets when its `action` field is omitted.
// Warn is the safe middle ground — finding fires a notification but
// requests still go through. Users opt up to block per-rule.
const DefaultAction Action = ActionWarn

// Decision is the proxy's derived verdict for one capture, picked by
// taking the strictest action across all findings (block > warn > allow).
type Decision string

const (
	DecisionAllowed Decision = "allowed"
	DecisionWarned  Decision = "warned"
	DecisionBlocked Decision = "blocked"
)

// DeriveDecision picks the strictest action across findings.
//   - Any block → blocked
//   - Else any warn → warned
//   - Else any allow → allowed
//   - Empty findings → allowed (nothing fired)
func DeriveDecision(findings []Finding) Decision {
	hasWarn, hasAllow := false, false
	for _, f := range findings {
		switch f.Action {
		case ActionBlock:
			return DecisionBlocked
		case ActionWarn:
			hasWarn = true
		case ActionAllow:
			hasAllow = true
		}
	}
	if hasWarn {
		return DecisionWarned
	}
	if hasAllow {
		return DecisionAllowed
	}
	return DecisionAllowed
}

// FirstBlockingRule returns the rule id of the first finding with
// Action=block, used to compose the 403 body when the proxy refuses to
// forward. Empty string if none.
func FirstBlockingRule(findings []Finding) string {
	for _, f := range findings {
		if f.Action == ActionBlock {
			return f.Rule
		}
	}
	return ""
}

// Finding is one match a Rule produced.
type Finding struct {
	Rule      string    `json:"rule"`      // stable rule id, e.g. "aws_access_key"
	Match     string    `json:"match"`     // redacted (first 4 + stars + last 2)
	Offset    int       `json:"offset"`    // byte offset in the scanned input
	Length    int       `json:"length"`    // length of the match in bytes
	Severity  Severity  `json:"severity"`
	Direction Direction `json:"direction"` // which side fired
	Action    Action    `json:"action"`    // copied from the rule for downstream policy
	// Source describes where in the capture the match came from, e.g.
	// "req_body", "resp.text[0]", "resp.tool_use[1].command". Empty for raw scans.
	Source string `json:"source,omitempty"`
}

// Rule is one regex check with metadata.
type Rule struct {
	ID          string
	Description string
	Pattern     *regexp.Regexp
	Severity    Severity
	Direction   Direction
	Action      Action
	// Validate optionally filters regex matches. RE2 has no lookarounds,
	// so rules like "SSN with valid area number" do that filtering here.
	Validate func(match []byte) bool
}

// Scanner runs a set of Rules against bodies/strings.
type Scanner struct {
	outbound []Rule
	inbound  []Rule
}

// New builds a scanner. Rules are partitioned by Direction at construction
// time so Scan calls don't pay the filter cost per request.
func New(rules []Rule) *Scanner {
	s := &Scanner{}
	for _, r := range rules {
		switch r.Direction {
		case DirectionOutbound:
			s.outbound = append(s.outbound, r)
		case DirectionInbound:
			s.inbound = append(s.inbound, r)
		case DirectionBoth:
			s.outbound = append(s.outbound, r)
			s.inbound = append(s.inbound, r)
		}
	}
	return s
}

// Default returns a scanner loaded with built-in rules only.
func Default() *Scanner {
	return New(DefaultRules())
}

// Scan runs all rules matching dir against b and returns the findings.
// source is attached to each Finding so callers can later say "from
// req_body" vs "from resp.tool_use[1].command".
func (s *Scanner) Scan(b []byte, dir Direction, source string) []Finding {
	if len(b) == 0 {
		return nil
	}
	var rules []Rule
	switch dir {
	case DirectionOutbound:
		rules = s.outbound
	case DirectionInbound:
		rules = s.inbound
	default:
		return nil
	}
	var out []Finding
	for _, r := range rules {
		for _, idx := range r.Pattern.FindAllIndex(b, -1) {
			start, end := idx[0], idx[1]
			if r.Validate != nil && !r.Validate(b[start:end]) {
				continue
			}
			out = append(out, Finding{
				Rule:      r.ID,
				Match:     redact(b[start:end]),
				Offset:    start,
				Length:    end - start,
				Severity:  r.Severity,
				Direction: dir,
				Action:    r.Action,
				Source:    source,
			})
		}
	}
	return out
}

// redact keeps the first 4 + last 2 chars of the matched string and
// stars the middle. Stored findings should not be a copy of the secret.
func redact(b []byte) string {
	const head, tail = 4, 2
	s := string(b)
	if len(s) <= head+tail {
		return s
	}
	stars := len(s) - head - tail
	if stars > 8 {
		stars = 8
	}
	out := make([]byte, 0, head+stars+tail)
	out = append(out, s[:head]...)
	for i := 0; i < stars; i++ {
		out = append(out, '*')
	}
	out = append(out, s[len(s)-tail:]...)
	return string(out)
}
