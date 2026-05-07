package ca

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerate_CreatesValidCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	ca, err := LoadOrGenerate(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	if !ca.Cert.IsCA {
		t.Errorf("expected IsCA=true")
	}
	if !ca.Cert.BasicConstraintsValid {
		t.Errorf("expected BasicConstraintsValid=true")
	}
	if ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("expected KeyUsageCertSign set")
	}
	if ca.Cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Errorf("expected KeyUsageCRLSign set")
	}
	if !ca.Cert.MaxPathLenZero {
		t.Errorf("expected MaxPathLenZero=true (no intermediates allowed)")
	}
	if ca.Cert.Subject.CommonName != "aig local CA" {
		t.Errorf("CommonName = %q, want %q", ca.Cert.Subject.CommonName, "aig local CA")
	}
}

func TestLoadOrGenerate_KeyPermissions(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	if _, err := LoadOrGenerate(certPath, keyPath); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key permissions %#o, want 0600", perm)
	}
}

func TestLoadOrGenerate_ReloadsSameCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	a, err := LoadOrGenerate(certPath, keyPath)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	b, err := LoadOrGenerate(certPath, keyPath)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if a.Cert.SerialNumber.Cmp(b.Cert.SerialNumber) != 0 {
		t.Errorf("serial mismatch across loads:\n  a=%s\n  b=%s",
			a.Cert.SerialNumber, b.Cert.SerialNumber)
	}
}
