package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"

	"github.com/neocho/ai-guard/internal/ca"
	"github.com/neocho/ai-guard/internal/paths"
	"github.com/neocho/ai-guard/internal/proxy"
	"github.com/neocho/ai-guard/internal/runner"
	"github.com/neocho/ai-guard/internal/store"
)

func cmdRun(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "aig run: missing command")
		fmt.Fprintln(os.Stderr, "usage: aig run <cmd> [args...]")
		return 2
	}

	if _, err := paths.Ensure(); err != nil {
		fmt.Fprintf(os.Stderr, "aig: %v\n", err)
		return 1
	}
	logPath, err := paths.LogFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: %v\n", err)
		return 1
	}
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: open log file %s: %v\n", logPath, err)
		return 1
	}
	defer logFile.Close()

	logger := slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo}))

	caCertPath, err := paths.CAFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: %v\n", err)
		return 1
	}
	caKeyPath, err := paths.CAKeyFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: %v\n", err)
		return 1
	}

	firstRun := false
	if _, err := os.Stat(caCertPath); errors.Is(err, fs.ErrNotExist) {
		firstRun = true
	}

	caInst, err := ca.LoadOrGenerate(caCertPath, caKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: load CA: %v\n", err)
		return 1
	}

	if firstRun {
		fp := sha256.Sum256(caInst.Cert.Raw)
		fmt.Fprintf(os.Stderr, "aig: generated local CA at %s\n", caCertPath)
		fmt.Fprintf(os.Stderr, "aig: fingerprint sha256:%s\n", hex.EncodeToString(fp[:]))
		fmt.Fprintf(os.Stderr, "aig: this CA is trusted only by processes you wrap with `aig run`\n")
	}

	minter := ca.NewMinter(caInst)

	dbPath, err := paths.CapturesDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: %v\n", err)
		return 1
	}
	captures, err := store.Open(dbPath, store.Options{Logger: logger})
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: open captures store: %v\n", err)
		return 1
	}
	defer captures.Close()

	sessionID, err := newSessionID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: session id generation failed: %v\n", err)
		return 1
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "aig: proxy listen failed: %v\n", err)
		return 1
	}
	defer ln.Close()

	proxyAddr := ln.Addr().String()
	proxyURL := fmt.Sprintf("http://%s", proxyAddr)

	fmt.Fprintf(os.Stderr, "aig: session=%s proxy=%s\n", sessionID, proxyAddr)
	fmt.Fprintf(os.Stderr, "aig: → tail -f %s to watch traffic\n", logPath)

	logger.Info("session start",
		"session_id", sessionID,
		"proxy", proxyAddr,
		"cmd", args[0],
		"mitm", true,
	)

	p := proxy.New(proxy.Options{
		SessionID: sessionID,
		Logger:    logger,
		Mint:      minter.CertFor,
		Store:     captures,
	})

	go func() {
		if err := p.Serve(ln); err != nil {
			logger.Error("proxy serve error", "err", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Only the env vars aig is adding. The runner merges with os.Environ
	// for binary targets and forwards each via `open --env` for .app
	// bundles (which need LaunchServices, not fork+exec).
	extraEnv := []string{
		"HTTPS_PROXY=" + proxyURL,
		"HTTP_PROXY=" + proxyURL,
		"https_proxy=" + proxyURL,
		"http_proxy=" + proxyURL,
		"NODE_EXTRA_CA_CERTS=" + caCertPath,
		"SSL_CERT_FILE=" + caCertPath,
		"REQUESTS_CA_BUNDLE=" + caCertPath,
		"CURL_CA_BUNDLE=" + caCertPath,
	}

	code, err := runner.Run(ctx, args, extraEnv)
	if err != nil {
		logger.Error("child run failed", "err", err)
		fmt.Fprintf(os.Stderr, "aig: child run failed: %v\n", err)
		return 1
	}

	logger.Info("session end", "session_id", sessionID, "exit_code", code)
	fmt.Fprintf(os.Stderr, "aig: session ended (exit_code=%d)\n", code)
	return code
}

func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
