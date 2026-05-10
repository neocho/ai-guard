package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/neocho/ai-guard/internal/ca"
	"github.com/neocho/ai-guard/internal/paths"
)

// caCommonName is the CommonName ca.LoadOrGenerate sets on the root cert.
// We grep for this in keychain entries when checking install / uninstall
// status, so it must stay in lockstep with internal/ca.go.
const caCommonName = "aig local CA"

// loginKeychainPath returns the path to the user's login keychain.
// Installing here avoids needing an admin password — only the user's
// keychain password (Touch ID-able) is required.
func loginKeychainPath() string {
	return filepath.Join(os.Getenv("HOME"), "Library", "Keychains", "login.keychain-db")
}

// cmdInstallCert installs the local CA into the user's login keychain
// and marks it trusted for SSL via `security add-trusted-cert`. It
// generates the CA on demand if not present.
func cmdInstallCert(args []string) int {
	caInst, certPath, err := loadOrGenerateCA()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: %v\n", err)
		return 1
	}

	fp := sha256.Sum256(caInst.Cert.Raw)
	fmt.Fprintf(os.Stderr, "aig: CA fingerprint sha256:%s\n", hex.EncodeToString(fp[:]))
	fmt.Fprintln(os.Stderr, "aig: installing into login keychain (you'll see a Touch ID / password prompt)")

	cmd := exec.Command("security", "add-trusted-cert",
		"-r", "trustRoot",
		"-p", "ssl",
		"-k", loginKeychainPath(),
		certPath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "aig: install failed: %v\n", err)
		return 1
	}

	fmt.Fprintln(os.Stderr, "aig: ✓ installed and trusted for SSL")
	fmt.Fprintln(os.Stderr, "aig: Chromium-based apps (Cursor, Codex Desktop, browsers) will trust certs aig mints when wrapped via `aig run`")
	return 0
}

// cmdUninstallCert removes the CA from the login keychain. The trust
// setting is associated with the cert and goes away alongside it.
func cmdUninstallCert(args []string) int {
	cmd := exec.Command("security", "delete-certificate",
		"-c", caCommonName,
		loginKeychainPath(),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		// security exits 44 ("specified item not found") when the cert isn't
		// present — that's fine for an uninstall, treat as success.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 44 {
			fmt.Fprintln(os.Stderr, "aig: no aig CA found in login keychain (already uninstalled?)")
			return 0
		}
		fmt.Fprintf(os.Stderr, "aig: uninstall failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "aig: ✓ removed from login keychain")
	return 0
}

// cmdCertStatus reports CA file presence + fingerprint, keychain install
// state, and trust state. Exit 0 if installed and trusted, 1 otherwise —
// useful for scripting (`aig cert-status && aig run cursor`).
func cmdCertStatus(args []string) int {
	caCertPath, err := paths.CAFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: %v\n", err)
		return 1
	}

	if _, err := os.Stat(caCertPath); err != nil {
		fmt.Println("CA file:    not present (run `aig install-cert` to generate and install)")
		return 1
	}

	caKeyPath, _ := paths.CAKeyFile()
	caInst, err := ca.LoadOrGenerate(caCertPath, caKeyPath)
	if err != nil {
		fmt.Printf("CA file:    error loading: %v\n", err)
		return 1
	}
	fp := sha256.Sum256(caInst.Cert.Raw)
	fmt.Printf("CA file:    %s\n", caCertPath)
	fmt.Printf("Fingerprint: sha256:%s\n", hex.EncodeToString(fp[:]))

	findCmd := exec.Command("security", "find-certificate", "-c", caCommonName, loginKeychainPath())
	if err := findCmd.Run(); err != nil {
		fmt.Println("Keychain:   not installed in login keychain")
		fmt.Println("Trust:      n/a")
		fmt.Println("→ run `aig install-cert` to install")
		return 1
	}
	fmt.Println("Keychain:   ✓ installed in login keychain")

	dumpCmd := exec.Command("security", "dump-trust-settings")
	out, _ := dumpCmd.CombinedOutput()
	if strings.Contains(string(out), caCommonName) {
		fmt.Println("Trust:      ✓ trusted for SSL (user trust settings)")
		return 0
	}
	fmt.Println("Trust:      ⚠ installed but no user trust setting (run `aig install-cert` to set)")
	return 1
}

// loadOrGenerateCA ensures ~/.aig/ca.pem and ~/.aig/ca-key.pem exist,
// generating a new CA on first run. Returns the loaded CA and the cert
// path so callers can pass it to `security`.
func loadOrGenerateCA() (*ca.CA, string, error) {
	if _, err := paths.Ensure(); err != nil {
		return nil, "", err
	}
	certPath, err := paths.CAFile()
	if err != nil {
		return nil, "", err
	}
	keyPath, err := paths.CAKeyFile()
	if err != nil {
		return nil, "", err
	}
	caInst, err := ca.LoadOrGenerate(certPath, keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("load CA: %w", err)
	}
	return caInst, certPath, nil
}
