package ca

import (
	"crypto/x509"
	"path/filepath"
	"testing"
)

func newCA(t *testing.T) *CA {
	t.Helper()
	dir := t.TempDir()
	ca, err := LoadOrGenerate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem"))
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	return ca
}

func TestMinter_CertForReturnsValidLeaf(t *testing.T) {
	ca := newCA(t)
	m := NewMinter(ca)

	leaf, err := m.CertFor("api.anthropic.com")
	if err != nil {
		t.Fatalf("CertFor: %v", err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	hasSAN := false
	for _, dns := range parsed.DNSNames {
		if dns == "api.anthropic.com" {
			hasSAN = true
		}
	}
	if !hasSAN {
		t.Errorf("leaf missing api.anthropic.com SAN, got DNSNames=%v", parsed.DNSNames)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("leaf failed CA verification: %v", err)
	}
}

func TestMinter_CacheReturnsSamePointer(t *testing.T) {
	m := NewMinter(newCA(t))

	a, _ := m.CertFor("api.anthropic.com")
	b, _ := m.CertFor("api.anthropic.com")
	if a != b {
		t.Errorf("expected cached cert to be the same pointer, got different")
	}
}

func TestMinter_PortStripped(t *testing.T) {
	m := NewMinter(newCA(t))

	a, _ := m.CertFor("api.anthropic.com:443")
	b, _ := m.CertFor("api.anthropic.com")
	if a != b {
		t.Errorf("port should not affect cache key — got two different certs")
	}
}
