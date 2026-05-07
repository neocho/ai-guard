// Package proxy provides an HTTP CONNECT proxy. It supports two modes:
//
//   - Passthrough (Options.Mint nil): bytes after CONNECT are tunneled
//     through unchanged. The proxy sees only destination + byte counts.
//
//   - MITM (Options.Mint non-nil): the proxy terminates TLS toward the
//     client using a leaf cert returned by Mint, opens a separate TLS
//     connection upstream, and bridges plaintext between them. Plaintext
//     bytes are visible inside this process — that's the window where
//     T-005 capture, T-007/8 parsing, T-010 scanners, and T-011 policy
//     will operate.
package proxy

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// Options configures a Proxy.
type Options struct {
	// SessionID tags every log line emitted by this proxy.
	SessionID string
	// Logger receives structured events. Defaults to slog.Default() if nil.
	Logger *slog.Logger
	// DialTimeout caps how long we wait for an upstream TCP connection.
	// Zero means use a sensible default (10s).
	DialTimeout time.Duration
	// Mint, if non-nil, enables MITM mode. The proxy will call Mint(host)
	// to get a leaf TLS certificate to present to the client. The host
	// argument is the SNI value (or the CONNECT host if SNI is missing),
	// already stripped of port.
	Mint func(host string) (*tls.Certificate, error)
	// UpstreamTLSConfig is an optional template for upstream TLS
	// connections (used only in MITM mode). The proxy clones it per
	// connection and overrides ServerName + NextProtos. Use this to
	// supply a custom RootCAs pool in tests, or set InsecureSkipVerify.
	// If nil, an empty config is used (system trust store).
	UpstreamTLSConfig *tls.Config
}

// Proxy is an HTTP CONNECT proxy. Construct with New, then call Serve(ln).
type Proxy struct {
	opts Options
	srv  *http.Server
}

// New returns a Proxy configured with opts. It does not start listening.
func New(opts Options) *Proxy {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 10 * time.Second
	}
	p := &Proxy{opts: opts}
	p.srv = &http.Server{Handler: http.HandlerFunc(p.handle)}
	return p
}

// Serve blocks accepting connections on ln until ln is closed or Close is
// called. It returns nil on graceful shutdown.
func (p *Proxy) Serve(ln net.Listener) error {
	err := p.srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Close shuts the proxy down. Safe to call from any goroutine.
func (p *Proxy) Close() error {
	return p.srv.Close()
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT is supported by this proxy", http.StatusMethodNotAllowed)
		return
	}
	p.handleConnect(w, r)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := r.Host

	// Dial upstream first so we can fail-502 cleanly if it's unreachable,
	// before we hijack the client conn.
	upstream, err := net.DialTimeout("tcp", host, p.opts.DialTimeout)
	if err != nil {
		http.Error(w, "upstream dial failed: "+err.Error(), http.StatusBadGateway)
		p.opts.Logger.Warn("connect upstream failed",
			"host", host, "err", err, "session_id", p.opts.SessionID)
		return
	}
	defer upstream.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	rawClient, _, err := hj.Hijack()
	if err != nil {
		p.opts.Logger.Error("hijack failed", "err", err, "session_id", p.opts.SessionID)
		return
	}
	defer rawClient.Close()

	if _, err := rawClient.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		p.opts.Logger.Warn("write 200 failed", "err", err, "session_id", p.opts.SessionID)
		return
	}

	if p.opts.Mint == nil {
		p.tunnel(rawClient, upstream, host, start)
		return
	}
	p.mitm(rawClient, upstream, host, start)
}

// tunnel implements passthrough mode: bridge raw bytes between client and
// upstream without touching them. We see destination + byte counts only.
func (p *Proxy) tunnel(client, upstream net.Conn, host string, start time.Time) {
	var up, down int64
	bridge(client, upstream, &up, &down)
	p.opts.Logger.Info("connect",
		"host", host,
		"bytes_up", atomic.LoadInt64(&up),
		"bytes_down", atomic.LoadInt64(&down),
		"duration", time.Since(start).Round(time.Millisecond).String(),
		"session_id", p.opts.SessionID,
		"mitm", false,
	)
}

// mitm implements MITM mode: terminate TLS with the client using a minted
// leaf cert, open a parallel TLS connection upstream with mirrored ALPN,
// then bridge plaintext between the two TLS conns.
func (p *Proxy) mitm(rawClient, upstream net.Conn, host string, start time.Time) {
	serverCfg := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = stripPort(host)
			}
			return p.opts.Mint(name)
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
	tlsClient := tls.Server(rawClient, serverCfg)
	if err := tlsClient.Handshake(); err != nil {
		p.opts.Logger.Warn("client TLS handshake failed",
			"host", host, "err", err, "session_id", p.opts.SessionID)
		return
	}
	defer tlsClient.Close()

	negotiated := tlsClient.ConnectionState().NegotiatedProtocol

	var upstreamCfg *tls.Config
	if p.opts.UpstreamTLSConfig != nil {
		upstreamCfg = p.opts.UpstreamTLSConfig.Clone()
	} else {
		upstreamCfg = &tls.Config{}
	}
	upstreamCfg.ServerName = stripPort(host)
	// Only constrain upstream ALPN when the client actually negotiated one.
	// If negotiated is "", the client didn't offer ALPN (or none matched);
	// passing []string{""} is invalid and we'd rather let upstream choose.
	if negotiated != "" {
		upstreamCfg.NextProtos = []string{negotiated}
	}

	tlsUpstream := tls.Client(upstream, upstreamCfg)
	if err := tlsUpstream.Handshake(); err != nil {
		p.opts.Logger.Warn("upstream TLS handshake failed",
			"host", host, "err", err, "session_id", p.opts.SessionID)
		return
	}
	defer tlsUpstream.Close()

	var up, down int64
	bridge(tlsClient, tlsUpstream, &up, &down)

	p.opts.Logger.Info("connect",
		"host", host,
		"bytes_up", atomic.LoadInt64(&up),
		"bytes_down", atomic.LoadInt64(&down),
		"duration", time.Since(start).Round(time.Millisecond).String(),
		"session_id", p.opts.SessionID,
		"alpn", negotiated,
		"mitm", true,
	)
}

// bridge copies bytes between two conns in both directions until either
// side closes. Closing either side unblocks both io.Copy calls.
func bridge(a, b net.Conn, aToB, bToA *int64) {
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(b, a)
		atomic.AddInt64(aToB, n)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(a, b)
		atomic.AddInt64(bToA, n)
		done <- struct{}{}
	}()

	<-done
	a.Close()
	b.Close()
	<-done
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
