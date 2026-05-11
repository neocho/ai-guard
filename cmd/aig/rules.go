package main

import (
	"fmt"
	"log/slog"
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

// cmdRulesList prints the merged rule set (built-ins + user) in tabular
// form. Source column says where each rule came from.
func cmdRulesList(_ []string) int {
	rulesPath, err := paths.RulesFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: %v\n", err)
		return 1
	}

	// Silent logger — bad-regex warnings are noise for `rules list`.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	rules, err := scanner.LoadConfig(rulesPath, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig rules list: %v\n", err)
		return 1
	}

	builtIns := map[string]bool{}
	for _, r := range scanner.DefaultRules() {
		builtIns[r.ID] = true
	}

	// Stable order: built-in alphabetical, then user alphabetical.
	sort.Slice(rules, func(i, j int) bool {
		bi, bj := builtIns[rules[i].ID], builtIns[rules[j].ID]
		if bi != bj {
			return bi
		}
		return rules[i].ID < rules[j].ID
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSEV\tDIR\tSOURCE\tDESCRIPTION")
	for _, r := range rules {
		src := "user"
		if builtIns[r.ID] {
			src = "built-in"
		}
		desc := r.Description
		if desc == "" {
			desc = "—"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.Direction, src, desc)
	}
	_ = w.Flush()

	if _, err := os.Stat(rulesPath); err == nil {
		fmt.Fprintf(os.Stdout, "\n%d rules loaded (config: %s)\n", len(rules), rulesPath)
	} else {
		fmt.Fprintf(os.Stdout, "\n%d rules loaded (no user config at %s)\n", len(rules), rulesPath)
	}
	return 0
}
