package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"sync"
	"time"
)

// Minter mints leaf TLS certs on demand for hosts encountered at MITM time.
// Certs are signed by the wrapped CA and cached in-memory keyed by hostname
// (without port). The cache lives for the Minter's lifetime; aig run sessions
// are short, so simple unbounded caching is fine.
type Minter struct {
	ca    *CA
	cache sync.Map // map[string]*tls.Certificate
}

// NewMinter creates a Minter backed by the given CA.
func NewMinter(ca *CA) *Minter {
	return &Minter{ca: ca}
}

// CertFor returns a leaf TLS certificate for the given host, signed by the
// CA. Subsequent calls with the same host return a shared cached cert.
//
// host may be passed as either "example.com" or "example.com:443" — the port
// is stripped before lookup so both forms hit the same cache entry.
func (m *Minter) CertFor(host string) (*tls.Certificate, error) {
	h := stripPort(host)
	if v, ok := m.cache.Load(h); ok {
		return v.(*tls.Certificate), nil
	}
	cert, err := m.mint(h)
	if err != nil {
		return nil, err
	}
	actual, _ := m.cache.LoadOrStore(h, cert)
	return actual.(*tls.Certificate), nil
}

func (m *Minter) mint(host string) (*tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-1 * time.Minute),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca.Cert, &leafKey.PublicKey, m.ca.Key)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes, m.ca.Cert.Raw},
		PrivateKey:  leafKey,
	}, nil
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
