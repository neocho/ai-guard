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

// loadScanner builds the scanner used by `aig run`. It loads built-in
// rules + ~/.aig/rules.yaml (if present), and bootstraps an example
// config the first time aig runs.
//
// Returns a typed error so the caller can print a clear "fix your config"
// message before exiting.
func loadScanner(logger *slog.Logger) (*scanner.Scanner, error) {
	rulesPath, err := paths.RulesFile()
	if err != nil {
		return nil, fmt.Errorf("resolve rules path: %w", err)
	}

	// Bootstrap example file once. Don't overwrite existing configs.
	if _, err := os.Stat(rulesPath); errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(rulesPath, []byte(scanner.ExampleConfig), 0o644); err != nil {
			logger.Warn("scanner: could not write example rules.yaml", "err", err)
		}
	}

	rules, err := scanner.LoadConfig(rulesPath, logger)
	if err != nil {
		return nil, err
	}
	return scanner.New(rules), nil
}
