package scanner

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// configFile is the on-disk shape of ~/.aig/rules.yaml. Optional fields
// use pointers/zero values; required ones (id, pattern, severity,
// direction) hard-fail at validation.
type configFile struct {
	Disabled []string     `yaml:"disabled"`
	Rules    []configRule `yaml:"rules"`
}

type configRule struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Pattern     string `yaml:"pattern"`
	Severity    string `yaml:"severity"`
	Direction   string `yaml:"direction"`
}

// LoadConfig reads ~/.aig/rules.yaml (or the path supplied) and returns
// the merged rule set: built-ins minus disabled, plus user rules. Returns
// the built-ins alone if the file doesn't exist.
//
// Hard-fails on:
//   - YAML syntax errors
//   - missing required fields (id, pattern, severity, direction)
//   - unknown severity / direction enum values
//
// Soft-fails (logs warning, skips rule, keeps going) on:
//   - regex compile errors — bad regex shouldn't kill the proxy
//
// logger may be nil (uses slog.Default).
func LoadConfig(path string, logger *slog.Logger) ([]Rule, error) {
	if logger == nil {
		logger = slog.Default()
	}

	rules := DefaultRules()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return rules, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg configFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	if len(cfg.Disabled) > 0 {
		disabled := make(map[string]struct{}, len(cfg.Disabled))
		for _, id := range cfg.Disabled {
			disabled[id] = struct{}{}
		}
		filtered := rules[:0]
		for _, r := range rules {
			if _, off := disabled[r.ID]; off {
				continue
			}
			filtered = append(filtered, r)
		}
		rules = filtered
	}

	for i, cr := range cfg.Rules {
		// Required fields — hard-fail with a precise pointer to which rule.
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

		// Soft-fail: invalid regex skips this rule but doesn't kill the proxy.
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
		})
	}

	return rules, nil
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

// ExampleConfig is the bootstrap rules.yaml written when none exists. Has
// built-ins commented and a couple of opt-in inbound Tier-1 rules ready
// to uncomment.
const ExampleConfig = `# ai-guard rules — augments the built-in rule set.
# Built-in rules are loaded automatically. List their IDs under "disabled"
# below to silence them.
#
# Built-in IDs:
#   anthropic_key, openai_key, private_key_pem, jwt, email

disabled: []

rules:
  # --- INBOUND examples (uncomment to opt in) -------------------------
  # Detect AI suggesting destructive shell commands. These are noisy by
  # default — context matters (rm -rf node_modules is fine). Uncomment
  # the patterns that match your workflow.
  #
  # - id: rm_rf_root
  #   description: "rm -rf targeting / or ~"
  #   pattern: 'rm\s+-rf\s+(?:/|~)(?:\s|$)'
  #   severity: high
  #   direction: inbound
  #
  # - id: curl_pipe_shell
  #   description: "curl/wget piped into a shell"
  #   pattern: '(?:curl|wget)[^|]+\|\s*(?:bash|sh|zsh)'
  #   severity: high
  #   direction: inbound
  #
  # - id: dd_to_disk
  #   description: "dd writing to a raw disk device"
  #   pattern: 'dd\s+[^;]*of=/dev/[hsv]d[a-z]'
  #   severity: high
  #   direction: inbound

  # --- OUTBOUND custom rules -----------------------------------------
  # Add your org's internal token formats here. Example:
  #
  # - id: mycorp_internal_token
  #   description: "Internal MyCorp service tokens"
  #   pattern: 'mycorp_[A-Za-z0-9]{32}'
  #   severity: high
  #   direction: outbound
`
