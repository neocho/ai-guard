// Package runner spawns a child process with inherited stdio and forwards
// signals from the parent to the child. It is intentionally thin: the proxy,
// env construction, and lifecycle decisions all live in the caller.
package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// Run spawns args[0] with args[1:] using the supplied env, inheriting stdin,
// stdout, and stderr from the parent. SIGINT and SIGTERM received by the
// parent are forwarded to the child. Run returns the child's exit code.
//
// The caller owns env entirely — Run does not merge with os.Environ.
func Run(ctx context.Context, args []string, env []string) (int, error) {
	if len(args) == 0 {
		return -1, errors.New("runner.Run: empty args")
	}

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
