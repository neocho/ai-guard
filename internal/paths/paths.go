// Package paths centralizes resolution of aig's local state directory and
// the well-known files inside it. Anything that touches ~/.aig should go
// through here so the layout is defined in exactly one place.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

// Dir returns the absolute path to aig's state directory (~/.aig).
// It does not create the directory — use Ensure for that.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".aig"), nil
}

// Ensure returns Dir() and creates the directory (with parents) if missing.
func Ensure() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", d, err)
	}
	return d, nil
}

// LogFile returns the absolute path to ~/.aig/aig.log. The file is not opened.
func LogFile() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "aig.log"), nil
}

// CAFile returns the absolute path to ~/.aig/ca.pem (the public CA cert).
func CAFile() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "ca.pem"), nil
}

// CAKeyFile returns the absolute path to ~/.aig/ca-key.pem (the CA's private
// key). The caller is responsible for restricting this file to mode 0600.
func CAKeyFile() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "ca-key.pem"), nil
}
