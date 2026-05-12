package scanner

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// ConfigFile is the on-disk shape of ~/.aig/rules.yaml. Exported so the
// toggle/delete helpers can round-trip it without leaking internal types.
type ConfigFile struct {
	Rules []ConfigRule `yaml:"rules"`
}

// ConfigRule is one entry in the rules.yaml file. Description, Enabled,
// and Action are optional; the others are required.
type ConfigRule struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description,omitempty"`
	Pattern     string `yaml:"pattern"`
	Severity    string `yaml:"severity"`
	Direction   string `yaml:"direction"`
	// Enabled is a pointer so the absence of the field means "true" and
	// only an explicit `enabled: false` disables the rule. yaml.v3
	// preserves this on marshal: omitted when nil, present when set.
	Enabled *bool `yaml:"enabled,omitempty"`
	// Action defaults to DefaultAction ("warn") when omitted. Validated
	// at load time — invalid values hard-fail.
	Action string `yaml:"action,omitempty"`
}

// LoadConfig reads rules.yaml and returns the compiled rules. There is
// no merge with code-side defaults — whatever is in the YAML is what runs.
// First-run bootstrap (cmd/aig/scanner.go) is responsible for seeding the
// file with starter rules.
//
// Hard-fails on:
//   - YAML syntax errors
//   - missing required fields (id, pattern, severity, direction)
//   - unknown severity / direction enum values
//
// Soft-fails (logs warning, skips rule, keeps going) on:
//   - regex compile errors — bad regex shouldn't kill the proxy
//
// Rules with `enabled: false` are silently skipped (they're still
// preserved in the YAML for re-enable in the UI). Missing file returns
// an empty rule set, not an error.
func LoadConfig(path string, logger *slog.Logger) ([]Rule, error) {
	if logger == nil {
		logger = slog.Default()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg ConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var rules []Rule
	for i, cr := range cfg.Rules {
		if cr.Enabled != nil && !*cr.Enabled {
			continue
		}
		if cr.ID == "" {
			return nil, fmt.Errorf("%s: rule #%d missing required field 'id'", path, i+1)
		}
		if cr.Pattern == "" {
			return nil, fmt.Errorf("%s: rule '%s' missing required field 'pattern'", path, cr.ID)
		}
		sev, err := parseSeverity(cr.Severity)
		if err != nil {
			return nil, fmt.Errorf("%s: rule '%s': %w", path, cr.ID, err)
		}
		dir, err := parseDirection(cr.Direction)
		if err != nil {
			return nil, fmt.Errorf("%s: rule '%s': %w", path, cr.ID, err)
		}
		act, err := parseAction(cr.Action)
		if err != nil {
			return nil, fmt.Errorf("%s: rule '%s': %w", path, cr.ID, err)
		}
		re, err := regexp.Compile(cr.Pattern)
		if err != nil {
			logger.Warn("scanner: invalid regex, skipping rule",
				"path", path, "rule", cr.ID, "err", err)
			continue
		}
		rules = append(rules, Rule{
			ID:          cr.ID,
			Description: cr.Description,
			Pattern:     re,
			Severity:    sev,
			Direction:   dir,
			Action:      act,
		})
	}
	return rules, nil
}

// LoadConfigRaw reads rules.yaml and returns the raw ConfigFile
// (including disabled rules). Used by the toggle/delete helpers and the
// /api/rules endpoint, which need to see every rule regardless of
// enabled state.
func LoadConfigRaw(path string) (*ConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ConfigFile{}, nil
		}
		return nil, err
	}
	var cfg ConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveConfig writes the config back to path. Atomicity-light: writes
// directly, no temp + rename — this file is tiny and edits are rare.
func SaveConfig(path string, cfg *ConfigFile) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ToggleRule flips the enabled state of one rule in the YAML. Absent or
// `enabled: true` becomes `enabled: false`; `enabled: false` becomes
// removed (back to default true). Returns the new enabled state.
func ToggleRule(path, id string) (bool, error) {
	cfg, err := LoadConfigRaw(path)
	if err != nil {
		return false, err
	}
	for i, r := range cfg.Rules {
		if r.ID != id {
			continue
		}
		nowEnabled := r.Enabled == nil || *r.Enabled
		if nowEnabled {
			f := false
			cfg.Rules[i].Enabled = &f
			return false, SaveConfig(path, cfg)
		}
		cfg.Rules[i].Enabled = nil
		return true, SaveConfig(path, cfg)
	}
	return false, fmt.Errorf("rule %q not found", id)
}

// SetRuleAction updates a rule's action in the YAML. action must be
// one of "allow", "warn", "block". An empty action means "use the
// default" — we remove the field rather than store the empty value, so
// the file stays clean.
func SetRuleAction(path, id, action string) error {
	if action != "" {
		if _, err := parseAction(action); err != nil {
			return err
		}
	}
	cfg, err := LoadConfigRaw(path)
	if err != nil {
		return err
	}
	for i, r := range cfg.Rules {
		if r.ID != id {
			continue
		}
		cfg.Rules[i].Action = action
		return SaveConfig(path, cfg)
	}
	return fmt.Errorf("rule %q not found", id)
}

// DeleteRule removes a rule from the YAML by id.
func DeleteRule(path, id string) error {
	cfg, err := LoadConfigRaw(path)
	if err != nil {
		return err
	}
	for i, r := range cfg.Rules {
		if r.ID == id {
			cfg.Rules = append(cfg.Rules[:i], cfg.Rules[i+1:]...)
			return SaveConfig(path, cfg)
		}
	}
	return fmt.Errorf("rule %q not found", id)
}

func parseSeverity(s string) (Severity, error) {
	switch Severity(s) {
	case SeverityHigh, SeverityMedium, SeverityLow:
		return Severity(s), nil
	case "":
		return "", fmt.Errorf("missing required field 'severity' (high|medium|low)")
	default:
		return "", fmt.Errorf("invalid severity %q (must be high|medium|low)", s)
	}
}

func parseDirection(s string) (Direction, error) {
	switch Direction(s) {
	case DirectionOutbound, DirectionInbound, DirectionBoth:
		return Direction(s), nil
	case "":
		return "", fmt.Errorf("missing required field 'direction' (outbound|inbound|both)")
	default:
		return "", fmt.Errorf("invalid direction %q (must be outbound|inbound|both)", s)
	}
}

func parseAction(s string) (Action, error) {
	switch Action(s) {
	case ActionAllow, ActionWarn, ActionBlock:
		return Action(s), nil
	case "":
		return DefaultAction, nil
	default:
		return "", fmt.Errorf("invalid action %q (must be allow|warn|block)", s)
	}
}

// StarterConfig is the YAML body written to ~/.aig/rules.yaml on first
// run (or when migrating from an earlier empty-rules version). No
// comments — the file is machine-managed by the UI's toggle/delete
// actions, which rewrite it on every change.
//
// Per-rule action defaults aim at "block what's almost certainly a
// real secret, warn on probable-but-noisy patterns, silently record
// emails." Users can flip any of these in the Mac UI.
const StarterConfig = `rules:
  - id: anthropic_key
    description: Anthropic API key
    pattern: 'sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}'
    severity: high
    direction: outbound
    action: block
  - id: openai_key
    description: OpenAI API key (sk-proj- / sk-svcacct-)
    pattern: 'sk-(?:proj|svcacct)-[A-Za-z0-9_-]{32,}'
    severity: high
    direction: outbound
    action: block
  - id: private_key_pem
    description: PEM-encoded private key header
    pattern: '-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----'
    severity: high
    direction: outbound
    action: block
  - id: jwt
    description: JSON Web Token (eyJ...eyJ...sig)
    pattern: 'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'
    severity: medium
    direction: outbound
    action: warn
  - id: email
    description: Email address
    pattern: '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'
    severity: low
    direction: outbound
    action: allow
  - id: rm_rf_root
    description: rm -rf targeting / or ~
    pattern: '\brm\s+-rf?\s+(?:/|~)(\s|$)'
    severity: high
    direction: inbound
    action: warn
  - id: sql_drop
    description: Destructive SQL DROP statement
    pattern: '(?i)\bDROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|TRIGGER|PROCEDURE|FUNCTION)\b'
    severity: high
    direction: inbound
    action: warn
`
