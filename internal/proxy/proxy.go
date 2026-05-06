// Package proxy provides an HTTP CONNECT proxy that tunnels TLS traffic
// to upstream hosts. It does not yet perform TLS interception (that lands
// in T-004); for now CONNECT bytes are bridged transparently and per-tunnel
// metadata is logged.
package proxy

import (
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
	// SessionID tags every log line emitted by this proxy. The caller picks it.
	SessionID string
	// Logger receives structured events. If nil, slog.Default() is used.
	Logger *slog.Logger
	// DialTimeout caps how long we wait for an upstream TCP connection.
	// Zero means use a sensible default (10s).
	DialTimeout time.Duration
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
	client, _, err := hj.Hijack()
	if err != nil {
		p.opts.Logger.Error("hijack failed", "err", err, "session_id", p.opts.SessionID)
		return
	}
	defer client.Close()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		p.opts.Logger.Warn("write 200 failed", "err", err, "session_id", p.opts.SessionID)
		return
	}

	var bytesUp, bytesDown int64
	bridge(client, upstream, &bytesUp, &bytesDown)

	p.opts.Logger.Info("connect",
		"host", host,
		"bytes_up", atomic.LoadInt64(&bytesUp),
		"bytes_down", atomic.LoadInt64(&bytesDown),
		"duration", time.Since(start).Round(time.Millisecond).String(),
		"session_id", p.opts.SessionID,
	)
}

// bridge copies bytes between client and upstream in both directions until
// either side closes. Closing either side unblocks both io.Copy calls.
func bridge(client, upstream net.Conn, up, down *int64) {
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(upstream, client)
		atomic.AddInt64(up, n)
		done <- struct{}{}
	}()

	go func() {
		n, _ := io.Copy(client, upstream)
		atomic.AddInt64(down, n)
		done <- struct{}{}
	}()

	<-done
	client.Close()
	upstream.Close()
	<-done
}
