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
	if len(rules) == 0 {
		t.Fatal("expected built-in rules even when file missing")
	}
}

func TestLoadConfig_AppendsUserRules(t *testing.T) {
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
	hasUser := false
	hasBuiltIn := false
	for _, r := range rules {
		if r.ID == "mycorp_token" {
			hasUser = true
		}
		if r.ID == "anthropic_key" {
			hasBuiltIn = true
		}
	}
	if !hasUser {
		t.Error("user rule not loaded")
	}
	if !hasBuiltIn {
		t.Error("built-in rule missing — user rules should append, not replace")
	}
}

func TestLoadConfig_DisabledRemovesBuiltIn(t *testing.T) {
	yaml := `
disabled: [email, jwt]
rules: []
`
	path := writeTemp(t, yaml)
	rules, err := scanner.LoadConfig(path, nil)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	for _, r := range rules {
		if r.ID == "email" || r.ID == "jwt" {
			t.Fatalf("rule %q should have been disabled", r.ID)
		}
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
