package main

import (
	"fmt"
	"os"
)

// Version + Commit are populated by `go build -ldflags "-X main.Version=...
// -X main.Commit=..."` in scripts/release.sh. Default values are used in
// dev builds (plain `go build` / `go run`).
var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "serve":
		os.Exit(cmdServe(os.Args[2:]))
	case "install-cert":
		os.Exit(cmdInstallCert(os.Args[2:]))
	case "uninstall-cert":
		os.Exit(cmdUninstallCert(os.Args[2:]))
	case "cert-status":
		os.Exit(cmdCertStatus(os.Args[2:]))
	case "rules":
		os.Exit(cmdRules(os.Args[2:]))
	case "-v", "--version", "version":
		fmt.Printf("aig %s (%s)\n", Version, Commit)
		os.Exit(0)
	case "-h", "--help", "help":
		usage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "aig: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, `usage: aig <command> [args...]

commands:
  run <cmd> [args...]    spawn cmd with HTTPS_PROXY pointed at an in-process proxy
  serve [--addr H:P]     serve a local JSON API on top of the captures store
  install-cert           install aig's CA into the login keychain (trusted for SSL)
  uninstall-cert         remove aig's CA from the login keychain
  cert-status            show CA file + keychain install + trust status
  rules <subcommand>     manage scanner rules (e.g. "aig rules list")
  version                show build version + commit

flags:
  -h, --help             show this help
  -v, --version          show build version`)
}
