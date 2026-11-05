#!/usr/bin/env bash
# disk-cleaner-mcp — Unix (macOS/Linux) installer
# Usage:  curl -fsSL https://github.com/CThawngs/Disk-Cleaner-MCP/releases/latest/download/install.sh | bash
# Installs binary + prints MCP client configuration snippets.

set -euo pipefail

VERSION="${1:-latest}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
OWNER="CThawngs"
REPO="Disk-Cleaner-MCP"

echo "=== disk-cleaner-mcp installer (Unix) ==="

# Detect OS/arch
OS="$(uname -s)"
ARCH="$(uname -m)"
case "${OS}-${ARCH}" in
  Darwin-arm64) TARGET="aarch64-apple-darwin" ;;
  Darwin-x86_64) TARGET="x86_64-apple-darwin" ;;
  Linux-x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
  *) echo "Unsupported platform: ${OS}-${ARCH}" >&2; exit 1 ;;
esac

mkdir -p "$INSTALL_DIR"
BIN="$INSTALL_DIR/disk-cleaner-mcp"
if [ "$VERSION" = "latest" ]; then
  # /latest/download/ is a GitHub redirect that always points to the newest release
  URL="https://github.com/${OWNER}/${REPO}/releases/latest/download/disk-cleaner-mcp-${TARGET}"
else
  URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/disk-cleaner-mcp-${TARGET}"
fi
echo "Downloading $URL ..."
curl -fsSL "$URL" -o "$BIN.tmp"
# Verify SHA256 against release checksums (supply-chain integrity)
if command -v sha256sum >/dev/null 2>&1; then HASH_CMD="sha256sum"; \
elif command -v shasum >/dev/null 2>&1; then HASH_CMD="shasum -a 256"; else HASH_CMD=""; fi
if [ -z "$HASH_CMD" ]; then echo "sha256sum/shasum missing — refusing install" >&2; exit 1; fi
if [ "$VERSION" = "latest" ]; then
  SUM_URL="https://github.com/${OWNER}/${REPO}/releases/latest/download/checksums.txt"
else
  SUM_URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/checksums.txt"
fi
SUM_TMP="$(mktemp)"
trap 'rm -f "$SUM_TMP" "$BIN.tmp"' EXIT
curl -fsSL "$SUM_URL" -o "$SUM_TMP"
EXPECTED="$(grep "disk-cleaner-mcp-${TARGET}$" "$SUM_TMP" | awk '{print $1}')"
if [ -z "$EXPECTED" ]; then echo "checksums.txt missing entry for $TARGET" >&2; exit 1; fi
ACTUAL="$($HASH_CMD "$BIN.tmp" | awk '{print $1}')"
if [ "$EXPECTED" != "$ACTUAL" ]; then echo "checksum mismatch (expected $EXPECTED, got $ACTUAL)" >&2; exit 1; fi
echo "Checksum OK: $ACTUAL"
rm -f "$SUM_TMP"
trap - EXIT
mv "$BIN.tmp" "$BIN"
chmod +x "$BIN"

echo
echo "Installed: $BIN"
echo
echo "Add this MCP server to your client with:"
echo "  - Claude Desktop: claude_desktop_config.json → mcpServers.disk-cleaner-mcp.command = \"$BIN\""
echo "  - Or run: $BIN"