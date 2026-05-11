package scanner_test

import (
	"testing"

	"github.com/neocho/ai-guard/internal/scanner"
)

func TestDeriveDecision(t *testing.T) {
	cases := []struct {
		name     string
		findings []scanner.Finding
		want     scanner.Decision
	}{
		{
			"empty findings → allowed",
			nil,
			scanner.DecisionAllowed,
		},
		{
			"all allow → allowed",
			[]scanner.Finding{
				{Action: scanner.ActionAllow},
				{Action: scanner.ActionAllow},
			},
			scanner.DecisionAllowed,
		},
		{
			"single warn → warned",
			[]scanner.Finding{{Action: scanner.ActionWarn}},
			scanner.DecisionWarned,
		},
		{
			"warn beats allow",
			[]scanner.Finding{
				{Action: scanner.ActionAllow},
				{Action: scanner.ActionWarn},
				{Action: scanner.ActionAllow},
			},
			scanner.DecisionWarned,
		},
		{
			"block beats everything",
			[]scanner.Finding{
				{Action: scanner.ActionAllow},
				{Action: scanner.ActionWarn},
				{Action: scanner.ActionBlock},
				{Action: scanner.ActionWarn},
			},
			scanner.DecisionBlocked,
		},
		{
			"single block → blocked",
			[]scanner.Finding{{Action: scanner.ActionBlock}},
			scanner.DecisionBlocked,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanner.DeriveDecision(tc.findings)
			if got != tc.want {
				t.Errorf("DeriveDecision = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFirstBlockingRule(t *testing.T) {
	cases := []struct {
		name     string
		findings []scanner.Finding
		want     string
	}{
		{"empty", nil, ""},
		{"no blocks", []scanner.Finding{{Rule: "a", Action: scanner.ActionWarn}}, ""},
		{
			"single block",
			[]scanner.Finding{{Rule: "first", Action: scanner.ActionBlock}},
			"first",
		},
		{
			"returns first not last block",
			[]scanner.Finding{
				{Rule: "warn1", Action: scanner.ActionWarn},
				{Rule: "block_a", Action: scanner.ActionBlock},
				{Rule: "block_b", Action: scanner.ActionBlock},
			},
			"block_a",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanner.FirstBlockingRule(tc.findings)
			if got != tc.want {
				t.Errorf("FirstBlockingRule = %q, want %q", got, tc.want)
			}
		})
	}
}
