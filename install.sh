#!/usr/bin/env bash
# Install the `aig` CLI on macOS.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/neocho/ai-guard/main/install.sh | bash
#
# Or pin a specific version:
#   curl -fsSL https://raw.githubusercontent.com/neocho/ai-guard/main/install.sh | AIG_VERSION=v0.1.0 bash
#
# What this does:
#   1. detects your macOS architecture (arm64 / x86_64)
#   2. downloads the matching tarball from the latest GitHub release
#   3. verifies the SHA-256 checksum
#   4. installs the binary to /usr/local/bin/aig (falls back to ~/.local/bin
#      if /usr/local/bin isn't writable)
#
# v0 ships unsigned. macOS won't trigger Gatekeeper because curl-downloaded
# files don't get a quarantine xattr — the binary just runs.

set -euo pipefail

REPO="neocho/ai-guard"
VERSION="${AIG_VERSION:-latest}"

# --- detect platform -------------------------------------------------

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "aig: only macOS is supported right now (you're on $(uname -s))" >&2
    exit 1
fi

uname_arch="$(uname -m)"
case "$uname_arch" in
    arm64)  arch=arm64  ;;
    x86_64) arch=amd64  ;;
    *) echo "aig: unsupported arch '$uname_arch'" >&2; exit 1 ;;
esac

# --- resolve version --------------------------------------------------

if [[ "$VERSION" == "latest" ]]; then
    echo "aig: resolving latest release..."
    VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')"
    if [[ -z "$VERSION" ]]; then
        echo "aig: could not resolve latest version. Check https://github.com/$REPO/releases" >&2
        exit 1
    fi
fi

base="https://github.com/$REPO/releases/download/$VERSION"
archive_name="aig-${VERSION}-darwin-${arch}.tar.gz"
archive_url="$base/$archive_name"
checksum_url="$base/SHA256SUMS"

echo "aig: downloading $VERSION for darwin/$arch"

# --- download + verify -----------------------------------------------

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL "$archive_url" -o "$tmp/$archive_name"
curl -fsSL "$checksum_url" -o "$tmp/SHA256SUMS"

expected="$(grep -F "$archive_name" "$tmp/SHA256SUMS" | awk '{print $1}')"
actual="$(shasum -a 256 "$tmp/$archive_name" | awk '{print $1}')"
if [[ -z "$expected" ]]; then
    echo "aig: $archive_name not listed in SHA256SUMS — bad release?" >&2
    exit 1
fi
if [[ "$expected" != "$actual" ]]; then
    echo "aig: checksum mismatch!" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    exit 1
fi

# --- install ---------------------------------------------------------

tar -xzf "$tmp/$archive_name" -C "$tmp"

if [[ -w /usr/local/bin ]]; then
    install_dir="/usr/local/bin"
    mv "$tmp/aig" "$install_dir/aig"
elif sudo -n true 2>/dev/null; then
    install_dir="/usr/local/bin"
    sudo mv "$tmp/aig" "$install_dir/aig"
else
    install_dir="$HOME/.local/bin"
    mkdir -p "$install_dir"
    mv "$tmp/aig" "$install_dir/aig"
    case ":$PATH:" in
        *":$install_dir:"*) ;;
        *) echo ""
           echo "aig: installed to $install_dir/aig but it's not on your PATH."
           echo "     add this to your shell rc (~/.zshrc or ~/.bashrc):"
           echo "       export PATH=\"\$HOME/.local/bin:\$PATH\""
           ;;
    esac
fi
chmod +x "$install_dir/aig"

echo ""
echo "aig: installed → $install_dir/aig"
"$install_dir/aig" version 2>/dev/null || true
echo ""
echo "next steps:"
echo "  1. install aig's local CA into your keychain (one-time):"
echo "       aig install-cert"
echo "  2. wrap your AI agent:"
echo "       aig run claude   # or codex, cursor, etc."
