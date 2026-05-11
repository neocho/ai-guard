package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/neocho/ai-guard/internal/paths"
	"github.com/neocho/ai-guard/internal/scanner"
)

// loadScanner builds the scanner used by `aig run`. It loads rules from
// ~/.aig/rules.yaml, seeding the starter rules on first run or when the
// file exists but has no rules (a one-time migration from the earlier
// empty-bootstrap format).
//
// There are no code-side defaults at runtime: whatever's in the YAML
// runs. Users own the rules; deleting / toggling in the Mac UI rewrites
// the file.
func loadScanner(logger *slog.Logger) (*scanner.Scanner, error) {
	rulesPath, err := paths.RulesFile()
	if err != nil {
		return nil, fmt.Errorf("resolve rules path: %w", err)
	}
	seedIfMissingOrEmpty(rulesPath, logger)
	rules, err := scanner.LoadConfig(rulesPath, logger)
	if err != nil {
		return nil, err
	}
	return scanner.New(rules), nil
}

// seedIfMissingOrEmpty writes the starter rules into the YAML when the
// file doesn't exist, OR when it exists but has zero rules (legacy
// migration). Otherwise leaves the file untouched.
func seedIfMissingOrEmpty(path string, logger *slog.Logger) {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(path, []byte(scanner.StarterConfig), 0o644); err != nil {
			logger.Warn("scanner: could not write starter rules.yaml", "err", err)
		}
		return
	}
	cfg, err := scanner.LoadConfigRaw(path)
	if err != nil {
		// Malformed file — leave alone; LoadConfig will surface the parse error.
		return
	}
	if len(cfg.Rules) == 0 {
		if err := os.WriteFile(path, []byte(scanner.StarterConfig), 0o644); err != nil {
			logger.Warn("scanner: could not migrate rules.yaml", "err", err)
		} else {
			logger.Info("scanner: seeded starter rules into existing empty rules.yaml")
		}
	}
}
