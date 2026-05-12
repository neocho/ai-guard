// Package runner spawns a wrapped target (binary or .app bundle) with our
// proxy + CA env vars injected, then waits for it to exit so the calling
// session can clean up.
//
// Binary targets use the standard exec.Command path. macOS .app bundles
// can't go through fork+exec cleanly (Squirrel updaters, single-instance
// locks, LaunchServices state) — they need `open -na --env`. The runner
// detects the path shape and dispatches to the right strategy.
package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Run spawns args[0] with args[1:], injecting extraEnv on top of the
// caller's environment. Returns the wrapped target's exit code (0 for
// .app bundles since `open` doesn't propagate one back from LaunchServices).
//
// extraEnv should contain ONLY the env aig is adding (HTTPS_PROXY,
// NODE_EXTRA_CA_CERTS, etc.) — the runner merges with os.Environ for
// binary targets and forwards via `open --env` for .app bundles.
func Run(ctx context.Context, args []string, extraEnv []string) (int, error) {
	if len(args) == 0 {
		return -1, errors.New("runner.Run: empty args")
	}
	if isAppBundle(args[0]) {
		return runAppBundle(ctx, args[0], args[1:], extraEnv)
	}
	fullEnv := append(os.Environ(), extraEnv...)
	return runBinary(ctx, args, fullEnv)
}

// --- Binary target (CLI agents like Claude Code, Aider, Codex CLI) ---

func runBinary(ctx context.Context, args []string, env []string) (int, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return -1, err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	for {
		select {
		case sig := <-sigCh:
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		case err := <-done:
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return exitErr.ExitCode(), nil
			}
			if err != nil {
				return -1, err
			}
			return 0, nil
		}
	}
}

// --- macOS .app bundle target (Cursor, Codex Desktop, Claude Desktop) ---

func runAppBundle(ctx context.Context, appPath string, childArgs []string, extraEnv []string) (int, error) {
	cleanPath := strings.TrimRight(appPath, "/")
	mainBin, err := findAppMainBinary(cleanPath)
	if err != nil {
		return -1, fmt.Errorf("inspect %s: %w", cleanPath, err)
	}

	// Pull our proxy URL out of extraEnv so we can also pass it as a
	// Chromium CLI flag. Electron apps that override their own proxy
	// config at runtime (Claude Desktop calls session.setProxy() at
	// startup) ignore HTTPS_PROXY env vars but still honor the
	// `--proxy-server` CLI flag — it's read by Chromium before any app
	// code runs. Cursor / Codex Desktop already honor the env var, so
	// passing the redundant flag is harmless for them. Non-Electron
	// `.app` bundles will see an unknown arg and typically ignore it.
	var proxyURL string
	for _, e := range extraEnv {
		if strings.HasPrefix(e, "HTTPS_PROXY=") {
			proxyURL = strings.TrimPrefix(e, "HTTPS_PROXY=")
			break
		}
	}

	// Build: open -na <app> --env K=V --env K=V ... [--args --proxy-server=URL child-args...]
	openArgs := []string{"-na", cleanPath}
	for _, e := range extraEnv {
		openArgs = append(openArgs, "--env", e)
	}
	var appArgs []string
	if proxyURL != "" {
		appArgs = append(appArgs, "--proxy-server="+proxyURL)
	}
	appArgs = append(appArgs, childArgs...)
	if len(appArgs) > 0 {
		openArgs = append(openArgs, "--args")
		openArgs = append(openArgs, appArgs...)
	}

	openCmd := exec.CommandContext(ctx, "open", openArgs...)
	openCmd.Stdout = os.Stdout
	openCmd.Stderr = os.Stderr
	if err := openCmd.Run(); err != nil {
		return -1, fmt.Errorf("open -na %s: %w", cleanPath, err)
	}

	// `open` returns immediately. Find the launched main process so we
	// can stay alive until it exits.
	pid, err := findRunningPID(mainBin, 5*time.Second)
	if err != nil {
		return -1, fmt.Errorf("locate launched app: %w", err)
	}
	fmt.Fprintf(os.Stderr, "aig: launched %s (pid=%d)\n", filepath.Base(cleanPath), pid)

	return waitForPIDExit(ctx, pid)
}

// findAppMainBinary returns the main executable inside the .app bundle.
// macOS .app convention: <app>/Contents/MacOS/<binary>. There may be
// helper .app bundles nested inside Contents/Frameworks but those have
// their own Contents/MacOS — we only look at the top level.
func findAppMainBinary(appPath string) (string, error) {
	dir := filepath.Join(appPath, "Contents", "MacOS")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", fmt.Errorf("no executable in %s", dir)
}

// findRunningPID polls `pgrep -nf <fullBinaryPath>` until it finds the
// launched process or the timeout elapses. The `-n` flag returns the
// newest match — relevant if the user has the app already open and we're
// launching a second copy (which `open -na` allows).
func findRunningPID(binPath string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("pgrep", "-nf", binPath).Output()
		if err == nil {
			s := strings.TrimSpace(string(out))
			if pid, perr := strconv.Atoi(s); perr == nil && pid > 0 {
				return pid, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 0, errors.New("timed out finding launched process")
}

// waitForPIDExit polls the given PID with kill(pid, 0) until the process
// is gone, or until the parent gets SIGINT/SIGTERM (in which case we
// forward to the app and continue waiting for it to actually quit).
func waitForPIDExit(ctx context.Context, pid int) (int, error) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case sig := <-sigCh:
			// Forward to the launched app. SIGTERM usually triggers a
			// graceful quit on macOS GUI apps; SIGINT is often ignored
			// but we forward it anyway to match binary semantics.
			s, _ := sig.(syscall.Signal)
			_ = syscall.Kill(pid, s)
		case <-ticker.C:
			if err := syscall.Kill(pid, 0); err != nil {
				// Process is gone. open(1) doesn't surface the app's
				// real exit code via LaunchServices, so we report 0.
				return 0, nil
			}
		}
	}
}

// isAppBundle returns true if path looks like a macOS .app bundle directory.
func isAppBundle(path string) bool {
	return strings.HasSuffix(strings.TrimRight(path, "/"), ".app")
}
