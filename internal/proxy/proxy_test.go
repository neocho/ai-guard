package proxy_test

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/neocho/ai-guard/internal/proxy"
)

// TestTunnelsCONNECT verifies the proxy:
//   - accepts a CONNECT request,
//   - replies "HTTP/1.1 200 Connection established",
//   - bridges bytes bidirectionally between client and upstream.
//
// We stand up a fake upstream that echoes whatever it receives, so writing
// "hello" through the tunnel should yield "hello" back.
func TestTunnelsCONNECT(t *testing.T) {
	upstreamAddr := startEchoServer(t)
	proxyAddr := startProxy(t)

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	// Send a CONNECT request asking for a tunnel to the echo server.
	if _, err := fmt.Fprintf(client,
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		upstreamAddr, upstreamAddr,
	); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	br := bufio.NewReader(client)

	// Read the status line and confirm 200.
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected 200 in status line, got %q", strings.TrimSpace(statusLine))
	}
	// Drain headers until the blank line that ends them.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header line: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Tunnel is open. Send a payload, expect it echoed back unchanged.
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

// startEchoServer returns a fake upstream that echoes whatever it receives.
// Registered with t.Cleanup so the listener closes at test end.
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

// startProxy starts our proxy on a random port with logs discarded.
// Registered with t.Cleanup so the proxy shuts down at test end.
func startProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}

	p := proxy.New(proxy.Options{
		SessionID: "test",
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	go func() { _ = p.Serve(ln) }()

	t.Cleanup(func() {
		_ = p.Close()
		_ = ln.Close()
	})
	return ln.Addr().String()
}
