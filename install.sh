#!/usr/bin/env bash
# disk-cleaner-mcp — Unix (macOS/Linux) installer
# Usage:  curl -fsSL https://github.com/<OWNER>/disk-cleaner-mcp/releases/latest/download/install.sh | bash
# Installs binary + prints MCP client configuration snippets.

set -euo pipefail

VERSION="${1:-latest}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
OWNER="<OWNER>"
REPO="disk-cleaner-mcp"

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
URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/disk-cleaner-mcp-${TARGET}"
echo "Downloading $URL ..."
curl -fsSL "$URL" -o "$BIN"
chmod +x "$BIN"

echo
echo "Installed: $BIN"
echo
echo "Add this MCP server to your client with:"
echo "  - Claude Desktop: claude_desktop_config.json → mcpServers.disk-cleaner-mcp.command = \"$BIN\""
echo "  - Or run: $BIN"