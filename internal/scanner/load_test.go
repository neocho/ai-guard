package scanner_test

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neocho/ai-guard/internal/scanner"
)

func TestLoadConfig_FileMissing(t *testing.T) {
	rules, err := scanner.LoadConfig(filepath.Join(t.TempDir(), "nope.yaml"), nil)
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("missing file should yield zero rules (bootstrap is the caller's job); got %d", len(rules))
	}
}

func TestLoadConfig_LoadsUserRules(t *testing.T) {
	yaml := `
rules:
  - id: mycorp_token
    description: "Internal token"
    pattern: 'mycorp_[A-Z]{10}'
    severity: high
    direction: outbound
`
	path := writeTemp(t, yaml)
	rules, err := scanner.LoadConfig(path, nil)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "mycorp_token" {
		t.Fatalf("expected exactly one rule 'mycorp_token', got %+v", rules)
	}
}

func TestLoadConfig_PerRuleEnabledFalseSkipsRule(t *testing.T) {
	yaml := `
rules:
  - id: keep_me
    pattern: 'A'
    severity: high
    direction: outbound
  - id: silenced
    pattern: 'B'
    severity: high
    direction: outbound
    enabled: false
`
	path := writeTemp(t, yaml)
	rules, err := scanner.LoadConfig(path, nil)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	for _, r := range rules {
		if r.ID == "silenced" {
			t.Fatalf("rule with enabled:false should have been skipped")
		}
	}
	if len(rules) != 1 || rules[0].ID != "keep_me" {
		t.Fatalf("expected only 'keep_me' to load, got %+v", rules)
	}
}

func TestToggleRule_FlipsEnabled(t *testing.T) {
	path := writeTemp(t, `rules:
  - id: x
    pattern: 'A'
    severity: high
    direction: outbound
`)
	// First toggle: enabled (default) → false.
	now, err := scanner.ToggleRule(path, "x")
	if err != nil {
		t.Fatalf("ToggleRule: %v", err)
	}
	if now {
		t.Error("first toggle should leave rule disabled")
	}
	// Loading should now skip 'x'.
	rules, _ := scanner.LoadConfig(path, nil)
	if len(rules) != 0 {
		t.Errorf("disabled rule should not load, got %d", len(rules))
	}
	// Second toggle: false → enabled (field removed).
	now, err = scanner.ToggleRule(path, "x")
	if err != nil {
		t.Fatalf("ToggleRule 2: %v", err)
	}
	if !now {
		t.Error("second toggle should re-enable")
	}
	rules, _ = scanner.LoadConfig(path, nil)
	if len(rules) != 1 {
		t.Errorf("re-enabled rule should load, got %d", len(rules))
	}
}

func TestLoadConfig_ActionDefaultsToWarn(t *testing.T) {
	// Rule has no action field — should default to warn.
	path := writeTemp(t, `rules:
  - id: x
    pattern: 'A'
    severity: high
    direction: outbound
`)
	rules, err := scanner.LoadConfig(path, nil)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
	if rules[0].Action != scanner.ActionWarn {
		t.Errorf("default action = %q, want %q", rules[0].Action, scanner.ActionWarn)
	}
}

func TestLoadConfig_ActionInvalidErrors(t *testing.T) {
	path := writeTemp(t, `rules:
  - id: x
    pattern: 'A'
    severity: high
    direction: outbound
    action: nope
`)
	_, err := scanner.LoadConfig(path, nil)
	if err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}
	if !strings.Contains(err.Error(), "invalid action") {
		t.Errorf("error should mention invalid action, got %q", err.Error())
	}
}

func TestLoadConfig_ActionCarriedThrough(t *testing.T) {
	path := writeTemp(t, `rules:
  - id: a_block
    pattern: 'A'
    severity: high
    direction: outbound
    action: block
  - id: b_allow
    pattern: 'B'
    severity: low
    direction: outbound
    action: allow
`)
	rules, err := scanner.LoadConfig(path, nil)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	byID := map[string]scanner.Action{}
	for _, r := range rules {
		byID[r.ID] = r.Action
	}
	if byID["a_block"] != scanner.ActionBlock {
		t.Errorf("a_block action = %q, want %q", byID["a_block"], scanner.ActionBlock)
	}
	if byID["b_allow"] != scanner.ActionAllow {
		t.Errorf("b_allow action = %q, want %q", byID["b_allow"], scanner.ActionAllow)
	}
}

func TestSetRuleAction_RoundTrip(t *testing.T) {
	path := writeTemp(t, `rules:
  - id: x
    pattern: 'A'
    severity: high
    direction: outbound
    action: warn
`)
	if err := scanner.SetRuleAction(path, "x", "block"); err != nil {
		t.Fatalf("SetRuleAction: %v", err)
	}
	rules, _ := scanner.LoadConfig(path, nil)
	if len(rules) != 1 || rules[0].Action != scanner.ActionBlock {
		t.Fatalf("after SetRuleAction(block): got %+v", rules)
	}
	// Back to default by passing empty string.
	if err := scanner.SetRuleAction(path, "x", ""); err != nil {
		t.Fatalf("SetRuleAction empty: %v", err)
	}
	rules, _ = scanner.LoadConfig(path, nil)
	if rules[0].Action != scanner.ActionWarn {
		t.Errorf("after SetRuleAction(\"\"): action = %q, want default warn", rules[0].Action)
	}
}

func TestSetRuleAction_InvalidAction(t *testing.T) {
	path := writeTemp(t, `rules:
  - id: x
    pattern: 'A'
    severity: high
    direction: outbound
`)
	err := scanner.SetRuleAction(path, "x", "destroy")
	if err == nil {
		t.Fatal("expected invalid-action error")
	}
	if !strings.Contains(err.Error(), "invalid action") {
		t.Errorf("error should mention invalid action, got %q", err.Error())
	}
}

func TestSetRuleAction_MissingRule(t *testing.T) {
	path := writeTemp(t, `rules:
  - id: x
    pattern: 'A'
    severity: high
    direction: outbound
`)
	err := scanner.SetRuleAction(path, "ghost", "block")
	if err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestDeleteRule_RemovesFromFile(t *testing.T) {
	path := writeTemp(t, `rules:
  - id: keep
    pattern: 'A'
    severity: high
    direction: outbound
  - id: drop
    pattern: 'B'
    severity: high
    direction: outbound
`)
	if err := scanner.DeleteRule(path, "drop"); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	rules, _ := scanner.LoadConfig(path, nil)
	if len(rules) != 1 || rules[0].ID != "keep" {
		t.Errorf("expected only 'keep' to remain, got %+v", rules)
	}
	if err := scanner.DeleteRule(path, "nonexistent"); err == nil {
		t.Error("deleting unknown id should error")
	}
}

func TestLoadConfig_HardFailMissingFields(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			"missing_id",
			`rules:
  - pattern: 'foo'
    severity: high
    direction: outbound`,
			"missing required field 'id'",
		},
		{
			"missing_pattern",
			`rules:
  - id: foo
    severity: high
    direction: outbound`,
			"missing required field 'pattern'",
		},
		{
			"missing_severity",
			`rules:
  - id: foo
    pattern: 'x'
    direction: outbound`,
			"missing required field 'severity'",
		},
		{
			"missing_direction",
			`rules:
  - id: foo
    pattern: 'x'
    severity: high`,
			"missing required field 'direction'",
		},
		{
			"invalid_severity",
			`rules:
  - id: foo
    pattern: 'x'
    severity: critical
    direction: outbound`,
			"invalid severity",
		},
		{
			"invalid_direction",
			`rules:
  - id: foo
    pattern: 'x'
    severity: high
    direction: sideways`,
			"invalid direction",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, tc.yaml)
			_, err := scanner.LoadConfig(path, nil)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error message %q should contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestLoadConfig_SoftFailBadRegex(t *testing.T) {
	yaml := `
rules:
  - id: bad_regex
    pattern: '[unclosed'
    severity: high
    direction: outbound
  - id: good_regex
    pattern: 'foo'
    severity: high
    direction: outbound
`
	path := writeTemp(t, yaml)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	rules, err := scanner.LoadConfig(path, logger)
	if err != nil {
		t.Fatalf("bad regex should soft-fail, got error: %v", err)
	}
	hasBad := false
	hasGood := false
	for _, r := range rules {
		if r.ID == "bad_regex" {
			hasBad = true
		}
		if r.ID == "good_regex" {
			hasGood = true
		}
	}
	if hasBad {
		t.Error("bad_regex should have been skipped")
	}
	if !hasGood {
		t.Error("good_regex should still be loaded after bad sibling")
	}
	if !strings.Contains(buf.String(), "invalid regex") {
		t.Errorf("expected warn log about invalid regex, got: %s", buf.String())
	}
}

func TestLoadConfig_BadYAML(t *testing.T) {
	path := writeTemp(t, "this is: not: valid: yaml:::")
	_, err := scanner.LoadConfig(path, nil)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
