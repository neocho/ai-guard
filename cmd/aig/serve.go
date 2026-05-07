package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/neocho/ai-guard/internal/api"
	"github.com/neocho/ai-guard/internal/paths"
	"github.com/neocho/ai-guard/internal/store"
)

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", "127.0.0.1:0", "address to bind (loopback only by design)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if _, err := paths.Ensure(); err != nil {
		fmt.Fprintf(os.Stderr, "aig: %v\n", err)
		return 1
	}
	dbPath, err := paths.CapturesDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: %v\n", err)
		return 1
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	captures, err := store.Open(dbPath, store.Options{Logger: logger})
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: open captures store: %v\n", err)
		return 1
	}
	defer captures.Close()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: listen %s: %v\n", *addr, err)
		return 1
	}

	apiSrv := api.New(captures, logger)
	httpSrv := &http.Server{
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "aig: serving API on http://%s\n", ln.Addr().String())
	fmt.Fprintf(os.Stderr, "aig:   GET /api/captures           list (newest first; ?before_id, ?limit)\n")
	fmt.Fprintf(os.Stderr, "aig:   GET /api/captures/{id}      detail with parsed request + response\n")
	fmt.Fprintf(os.Stderr, "aig:   GET /api/stream             SSE of new captures\n")

	serveErr := make(chan error, 1)
	go func() {
		err := httpSrv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case <-sigCh:
		fmt.Fprintln(os.Stderr, "aig: shutting down")
	case err := <-serveErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "aig: serve error: %v\n", err)
			return 1
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return 0
}
