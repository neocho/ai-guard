package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/neocho/ai-guard/internal/paths"
	"github.com/neocho/ai-guard/internal/proxy"
	"github.com/neocho/ai-guard/internal/runner"
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
	)

	p := proxy.New(proxy.Options{
		SessionID: sessionID,
		Logger:    logger,
	})

	go func() {
		if err := p.Serve(ln); err != nil {
			logger.Error("proxy serve error", "err", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := append(os.Environ(),
		"HTTPS_PROXY="+proxyURL,
		"HTTP_PROXY="+proxyURL,
		"https_proxy="+proxyURL,
		"http_proxy="+proxyURL,
	)

	code, err := runner.Run(ctx, args, env)
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
