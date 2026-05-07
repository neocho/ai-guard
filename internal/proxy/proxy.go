// Package proxy provides an HTTP CONNECT proxy. It supports two modes:
//
//   - Passthrough (Options.Mint nil): bytes after CONNECT are tunneled
//     through unchanged. The proxy sees only destination + byte counts.
//
//   - MITM (Options.Mint non-nil): the proxy terminates TLS toward the
//     client using a leaf cert returned by Mint, accepts parsed HTTP
//     requests via an embedded http.Server, makes its own outbound
//     request via http.Transport, captures both, and streams the
//     response back. Each parsed request becomes one capture row,
//     enabling downstream policy/scanning/audit (T-010+).
package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/neocho/ai-guard/internal/store"
)

// Options configures a Proxy.
type Options struct {
	// SessionID tags every log line and persisted capture.
	SessionID string
	// Logger receives structured events. Defaults to slog.Default() if nil.
	Logger *slog.Logger
	// DialTimeout caps how long we wait for an upstream TCP connection.
	// Zero means use a sensible default (10s).
	DialTimeout time.Duration
	// Mint enables MITM mode. Returns a leaf TLS certificate for the host.
	Mint func(host string) (*tls.Certificate, error)
	// UpstreamTLSConfig is an optional template for upstream TLS
	// connections (used only in MITM mode). The proxy's internal Transport
	// clones it. Use to supply a custom RootCAs pool in tests, or to set
	// InsecureSkipVerify. If nil, an empty config (system trust) is used.
	UpstreamTLSConfig *tls.Config
	// Store, if non-nil, persists each parsed request/response pair from
	// MITM mode. Captures are append-only; writes are async — see
	// internal/store. Passthrough connections are not captured (we don't
	// see their content).
	Store *store.Store
}

// Proxy is an HTTP CONNECT proxy. Construct with New, then call Serve(ln).
type Proxy struct {
	opts      Options
	srv       *http.Server
	transport *http.Transport
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

	if opts.Mint != nil {
		var tlsCfg *tls.Config
		if opts.UpstreamTLSConfig != nil {
			tlsCfg = opts.UpstreamTLSConfig.Clone()
		} else {
			tlsCfg = &tls.Config{}
		}
		p.transport = &http.Transport{
			TLSClientConfig:     tlsCfg,
			ForceAttemptHTTP2:   true,
			DialContext:         (&net.Dialer{Timeout: opts.DialTimeout}).DialContext,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		}
	}
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
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}
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

	if p.opts.Mint == nil {
		// Passthrough: pre-dial upstream so we can fail-502 cleanly before
		// hijacking the client conn.
		upstream, err := net.DialTimeout("tcp", host, p.opts.DialTimeout)
		if err != nil {
			http.Error(w, "upstream dial failed: "+err.Error(), http.StatusBadGateway)
			p.opts.Logger.Warn("passthrough upstream failed",
				"host", host, "err", err, "session_id", p.opts.SessionID)
			return
		}
		defer upstream.Close()

		rawClient, ok := hijack(w, p.opts.Logger, p.opts.SessionID)
		if !ok {
			return
		}
		defer rawClient.Close()
		if !write200(rawClient, p.opts.Logger, p.opts.SessionID) {
			return
		}

		p.tunnel(rawClient, upstream, host, start)
		return
	}

	// MITM: http.Transport will dial upstream lazily during requests.
	rawClient, ok := hijack(w, p.opts.Logger, p.opts.SessionID)
	if !ok {
		return
	}
	defer rawClient.Close()
	if !write200(rawClient, p.opts.Logger, p.opts.SessionID) {
		return
	}

	p.mitm(rawClient, host, start)
}

func hijack(w http.ResponseWriter, logger *slog.Logger, sessionID string) (net.Conn, bool) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return nil, false
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		logger.Error("hijack failed", "err", err, "session_id", sessionID)
		return nil, false
	}
	return conn, true
}

func write200(conn net.Conn, logger *slog.Logger, sessionID string) bool {
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		logger.Warn("write 200 failed", "err", err, "session_id", sessionID)
		return false
	}
	return true
}

// tunnel implements passthrough mode: bridge raw bytes between client and
// upstream without touching them.
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

// mitm implements MITM mode: terminate TLS with the client, run an
// embedded http.Server on that conn that parses each HTTP request and
// dispatches to handleHTTPRequest. The handler does the upstream call
// via p.transport and captures both directions.
func (p *Proxy) mitm(rawClient net.Conn, host string, start time.Time) {
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
	// Wrap the underlying TCP conn (not the tls.Conn) so http.Server's
	// type assertion `c.rwc.(*tls.Conn)` still succeeds and h2 dispatch
	// works. tls.Conn.Close calls the underlying conn's Close, so our
	// signal still fires when the tls layer closes.
	closed := make(chan struct{})
	wrappedTCP := &closeSignalConn{Conn: rawClient, done: closed}
	tlsConn := tls.Server(wrappedTCP, serverCfg)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.handleHTTPRequest(w, r, host)
	})

	srv := &http.Server{Handler: handler}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		p.opts.Logger.Error("h2 setup failed", "err", err, "session_id", p.opts.SessionID)
		return
	}

	listener := newBlockingOneShotListener(tlsConn, closed)
	_ = srv.Serve(listener)

	negotiated := tlsConn.ConnectionState().NegotiatedProtocol
	p.opts.Logger.Info("connect",
		"host", host,
		"alpn", negotiated,
		"duration", time.Since(start).Round(time.Millisecond).String(),
		"session_id", p.opts.SessionID,
		"mitm", true,
	)
}

// closeSignalConn wraps a net.Conn and closes the supplied channel when
// Close is called. Used to detect when the inner http.Server is done with
// the connection so the outer goroutine can return cleanly.
type closeSignalConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeSignalConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// handleHTTPRequest is the per-HTTP-request handler used inside MITM mode.
// It buffers the request body, makes the upstream call, streams the
// response back to the client, and (if a Store is configured) appends a
// Capture row covering both directions.
func (p *Proxy) handleHTTPRequest(w http.ResponseWriter, r *http.Request, connectHost string) {
	reqStart := time.Now()

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read request body: "+err.Error(), http.StatusBadGateway)
		return
	}
	_ = r.Body.Close()

	outURL := url.URL{
		Scheme:   "https",
		Host:     connectHost,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, "build upstream request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	copyHeaders(outReq.Header, r.Header)

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		p.opts.Logger.Warn("upstream roundtrip failed",
			"host", connectHost, "err", err, "session_id", p.opts.SessionID)
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		p.appendCapture(reqStart, connectHost, r, reqBody, 0, nil, nil)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	var capBuf bytes.Buffer
	teed := io.TeeReader(resp.Body, &capBuf)
	if _, err := io.Copy(w, teed); err != nil {
		p.opts.Logger.Warn("response stream to client failed",
			"err", err, "session_id", p.opts.SessionID)
	}

	p.appendCapture(reqStart, connectHost, r, reqBody, resp.StatusCode, resp.Header, capBuf.Bytes())
}

func (p *Proxy) appendCapture(start time.Time, host string, r *http.Request, reqBody []byte, status int, respHeaders http.Header, respBody []byte) {
	if p.opts.Store == nil {
		return
	}
	p.opts.Store.Append(&store.Capture{
		SessionID:   p.opts.SessionID,
		PID:         os.Getpid(),
		Timestamp:   start,
		Host:        host,
		Method:      r.Method,
		Path:        r.URL.Path,
		ReqHeaders:  encodeHeaders(r.Header),
		ReqBody:     reqBody,
		RespStatus:  status,
		RespHeaders: encodeHeaders(respHeaders),
		RespBody:    respBody,
		DurationMS:  time.Since(start).Milliseconds(),
		ALPN:        r.Proto,
	})
}

// hopByHopHeaders are not forwarded across the proxy boundary (RFC 7230 §6.1).
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		if hopByHopHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func encodeHeaders(h http.Header) string {
	if h == nil {
		return ""
	}
	b, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return string(b)
}

// bridge copies bytes between two conns in both directions until either
// side closes. Used by passthrough mode only.
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

// blockingOneShotListener returns the conn on the first Accept, then blocks
// subsequent Accepts on done. Once done is closed (by closeSignalConn), the
// next Accept returns io.EOF and http.Server.Serve unwinds. This keeps
// Serve blocked until the connection is genuinely finished, regardless of
// whether http.Server's ConnState path runs to completion (which can be
// short-circuited by TLS handshake errors).
type blockingOneShotListener struct {
	conn net.Conn
	done chan struct{}
	used atomic.Bool
}

func newBlockingOneShotListener(c net.Conn, done chan struct{}) *blockingOneShotListener {
	return &blockingOneShotListener{conn: c, done: done}
}

func (l *blockingOneShotListener) Accept() (net.Conn, error) {
	if l.used.CompareAndSwap(false, true) {
		return l.conn, nil
	}
	<-l.done
	return nil, io.EOF
}

func (l *blockingOneShotListener) Close() error {
	return l.conn.Close()
}

func (l *blockingOneShotListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
