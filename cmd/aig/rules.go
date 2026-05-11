package main

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/neocho/ai-guard/internal/paths"
	"github.com/neocho/ai-guard/internal/scanner"
)

func cmdRules(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "aig rules: missing subcommand")
		fmt.Fprintln(os.Stderr, "usage: aig rules <list>")
		return 2
	}
	switch args[0] {
	case "list":
		return cmdRulesList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "aig rules: unknown subcommand %q\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: aig rules <list>")
		return 2
	}
}

// cmdRulesList prints every rule in rules.yaml (including disabled ones)
// in tabular form. The ENABLED column is "yes" or "no" so you can spot
// silenced rules without grepping the YAML.
func cmdRulesList(_ []string) int {
	rulesPath, err := paths.RulesFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: %v\n", err)
		return 1
	}

	cfg, err := scanner.LoadConfigRaw(rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig rules list: %v\n", err)
		return 1
	}

	rules := cfg.Rules
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSEV\tDIR\tACTION\tENABLED\tDESCRIPTION")
	for _, r := range rules {
		enabled := "yes"
		if r.Enabled != nil && !*r.Enabled {
			enabled = "no"
		}
		action := r.Action
		if action == "" {
			action = string(scanner.DefaultAction)
		}
		desc := r.Description
		if desc == "" {
			desc = "—"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.Direction, action, enabled, desc)
	}
	_ = w.Flush()

	if _, err := os.Stat(rulesPath); err == nil {
		fmt.Fprintf(os.Stdout, "\n%d rules in %s\n", len(rules), rulesPath)
	} else {
		fmt.Fprintf(os.Stdout, "\nno config at %s (run `aig run <cmd>` once to bootstrap)\n", rulesPath)
	}
	return 0
}
