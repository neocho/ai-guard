#!/usr/bin/env bash
# Build + package aig for distribution.
#
# Usage: ./scripts/release.sh v0.1.0
#
# Produces:
#   dist/aig-<version>-darwin-arm64.tar.gz
#   dist/aig-<version>-darwin-amd64.tar.gz
#   dist/SHA256SUMS
#
# Optionally creates a GitHub release with `gh release create`.
# This v0 ships unsigned — install via the curl install.sh path which
# avoids Gatekeeper. Re-cut signed releases once we have a Developer ID
# Application cert.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <version>   e.g. $0 v0.1.0" >&2
    exit 2
fi

VERSION="$1"
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.+-]+)?$ ]]; then
    echo "error: version must look like v0.1.0 or v0.1.0-rc1, got '$VERSION'" >&2
    exit 2
fi

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DIST="$ROOT/dist"

# Clean previous build.
rm -rf "$DIST"
mkdir -p "$DIST"

# Inject the version + commit into the binary via -ldflags so
# `aig --version` shows something useful. cmd/aig/main.go must declare:
#   var Version = "dev"  (will be overridden by linker)
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
LDFLAGS="-s -w -X main.Version=$VERSION -X main.Commit=$COMMIT"

build_arch() {
    local goarch="$1"  # arm64 or amd64
    local outdir="$DIST/build-darwin-$goarch"
    local binary="$outdir/aig"

    echo "→ building darwin/$goarch"
    mkdir -p "$outdir"
    CGO_ENABLED=0 GOOS=darwin GOARCH="$goarch" go build \
        -trimpath -ldflags "$LDFLAGS" \
        -o "$binary" ./cmd/aig

    local archive="$DIST/aig-$VERSION-darwin-$goarch.tar.gz"
    tar -czf "$archive" -C "$outdir" aig
    rm -rf "$outdir"
    echo "  packaged: $(basename "$archive") ($(du -h "$archive" | cut -f1))"
}

build_arch arm64
build_arch amd64

# Generate checksums so install.sh can verify downloads.
(
    cd "$DIST"
    shasum -a 256 ./*.tar.gz > SHA256SUMS
)

echo ""
echo "build complete:"
ls -la "$DIST"

echo ""
echo "next step:"
echo "  git tag $VERSION && git push origin $VERSION"
echo "  gh release create $VERSION dist/*.tar.gz dist/SHA256SUMS --title \"$VERSION\" --notes 'Release notes'"
