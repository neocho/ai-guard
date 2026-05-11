package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neocho/ai-guard/internal/ca"
	"github.com/neocho/ai-guard/internal/proxy"
	"github.com/neocho/ai-guard/internal/scanner"
	"github.com/neocho/ai-guard/internal/store"
)

// TestPassthrough_TunnelsCONNECT verifies the no-MITM path:
//   - accepts a CONNECT request,
//   - replies "HTTP/1.1 200 Connection established",
//   - bridges raw bytes bidirectionally between client and upstream.
//
// This exercises the same path as before T-004 — when Options.Mint is nil
// the proxy tunnels without touching bytes.
func TestPassthrough_TunnelsCONNECT(t *testing.T) {
	upstreamAddr := startEchoServer(t)
	proxyAddr := startProxy(t, proxy.Options{}) // Mint nil → passthrough

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(client,
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		upstreamAddr, upstreamAddr,
	); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	br := bufio.NewReader(client)
	if !readStatus200(t, br) {
		return
	}

	want := []byte("hello tunnel")
	if _, err := client.Write(want); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: want %q, got %q", want, got)
	}
}

// TestMITM_DecryptsAndForwards verifies the MITM path end-to-end:
//   - Real TLS upstream (httptest h2 server) returning a known body.
//   - Our proxy in MITM mode with a freshly generated CA + minter.
//   - A capture Store wired in.
//   - HTTP client trusting our CA, configured to use our proxy.
//
// On success the client receives the upstream body unchanged, and one
// row lands in the store with method/host/path matching the request.
// Any breakage in TLS termination, h2 dispatch, ALPN mirroring, or
// upstream RoundTrip will fail one of these checks.
func TestMITM_DecryptsAndForwards(t *testing.T) {
	const wantBody = "hello from upstream"

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, wantBody)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	caInst := newCA(t)
	minter := ca.NewMinter(caInst)

	storeDir := t.TempDir()
	s, err := store.Open(filepath.Join(storeDir, "captures.db"), store.Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	proxyAddr := startProxy(t, proxy.Options{
		Mint:              minter.CertFor,
		UpstreamTLSConfig: &tls.Config{RootCAs: upstreamPool},
		Store:             s,
	})

	clientPool := x509.NewCertPool()
	clientPool.AddCert(caInst.Cert)

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:    clientPool,
				NextProtos: []string{"h2", "http/1.1"},
			},
			ForceAttemptHTTP2: true,
		},
	}

	resp, err := httpClient.Get(upstream.URL + "/some/path")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), wantBody) {
		t.Fatalf("body = %q, want it to contain %q", body, wantBody)
	}

	// Wait for the async store write to flush, then assert the capture.
	flushCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Flush(flushCtx); err != nil {
		t.Fatalf("store flush: %v", err)
	}
	captures, err := s.List(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("store list: %v", err)
	}
	if len(captures) == 0 {
		t.Fatalf("expected at least one capture, got 0")
	}
	c := captures[0]
	if c.Method != "GET" {
		t.Errorf("capture method = %q, want GET", c.Method)
	}
	if c.Path != "/some/path" {
		t.Errorf("capture path = %q, want /some/path", c.Path)
	}
	if !strings.Contains(string(c.RespBody), wantBody) {
		t.Errorf("capture resp body = %q, want it to contain %q", c.RespBody, wantBody)
	}
	if c.RespStatus != 200 {
		t.Errorf("capture resp_status = %d, want 200", c.RespStatus)
	}
}

// readStatus200 reads the HTTP status line + headers off br, returning
// true if the status is 200. On failure it calls t.Fatal.
func readStatus200(t *testing.T, br *bufio.Reader) bool {
	t.Helper()
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
		return false
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected 200 status, got %q", strings.TrimSpace(statusLine))
		return false
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header line: %v", err)
			return false
		}
		if line == "\r\n" || line == "\n" {
			return true
		}
	}
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// captureBuf collects log output into a buffer that's safe to write to from
// any goroutine (including ones still running after a test finishes). The
// buffer is dumped to t.Log on test failure for debugging.
type captureBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *captureBuf) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}
func (c *captureBuf) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func startProxy(t *testing.T, opts proxy.Options) string {
	t.Helper()
	if opts.Logger == nil {
		cap := &captureBuf{}
		opts.Logger = slog.New(slog.NewTextHandler(cap, &slog.HandlerOptions{Level: slog.LevelDebug}))
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("proxy logs:\n%s", cap.String())
			}
		})
	}
	if opts.SessionID == "" {
		opts.SessionID = "test"
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}

	p := proxy.New(opts)
	go func() { _ = p.Serve(ln) }()

	t.Cleanup(func() {
		_ = p.Close()
		_ = ln.Close()
	})
	return ln.Addr().String()
}

func newCA(t *testing.T) *ca.CA {
	t.Helper()
	dir := t.TempDir()
	c, err := ca.LoadOrGenerate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem"))
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	return c
}

// TestMITM_BlocksOnPolicyAction verifies T-011: when a scanner rule with
// action=block matches the request body, the proxy returns 403 and never
// forwards upstream. The capture row is still written, with decision=blocked.
func TestMITM_BlocksOnPolicyAction(t *testing.T) {
	var upstreamHits int
	var hitsMu sync.Mutex
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsMu.Lock()
		upstreamHits++
		hitsMu.Unlock()
		fmt.Fprint(w, "should not see this")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	caInst := newCA(t)
	minter := ca.NewMinter(caInst)

	storeDir := t.TempDir()
	s, err := store.Open(filepath.Join(storeDir, "captures.db"), store.Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	rule := scanner.Rule{
		ID:        "test_secret",
		Pattern:   regexp.MustCompile(`SECRET-[A-Z]+`),
		Severity:  scanner.SeverityHigh,
		Direction: scanner.DirectionOutbound,
		Action:    scanner.ActionBlock,
	}
	scn := scanner.New([]scanner.Rule{rule})

	proxyAddr := startProxy(t, proxy.Options{
		Mint:              minter.CertFor,
		UpstreamTLSConfig: &tls.Config{RootCAs: upstreamPool},
		Store:             s,
		Scanner:           scn,
		IsScannable:       func(host, path string) bool { return true },
	})

	clientPool := x509.NewCertPool()
	clientPool.AddCert(caInst.Cert)
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:    clientPool,
				NextProtos: []string{"h2", "http/1.1"},
			},
			ForceAttemptHTTP2: true,
		},
	}

	// Valid JSON body with a SECRET-X substring — ScanJSON walks string leaves.
	body := []byte(`{"prompt":"the answer is SECRET-ABCDEF, do not share"}`)
	resp, err := httpClient.Post(upstream.URL+"/v1/test", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	respBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBody), "blocked by rule") || !strings.Contains(string(respBody), "test_secret") {
		t.Errorf("body = %q, want it to mention blocked + rule id", respBody)
	}
	hitsMu.Lock()
	hits := upstreamHits
	hitsMu.Unlock()
	if hits != 0 {
		t.Errorf("upstream was hit %d times — block should have short-circuited", hits)
	}

	flushCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Flush(flushCtx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	captures, err := s.List(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(captures) == 0 {
		t.Fatalf("expected at least one capture, got 0")
	}
	c := captures[0]
	if c.RespStatus != http.StatusForbidden {
		t.Errorf("capture resp_status = %d, want 403", c.RespStatus)
	}
	if c.Decision != "blocked" {
		t.Errorf("capture decision = %q, want blocked", c.Decision)
	}
	if !strings.Contains(c.Findings, "test_secret") {
		t.Errorf("capture findings should mention test_secret, got %s", c.Findings)
	}
}
