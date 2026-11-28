#!/usr/bin/env bash
# disk-cleaner-mcp - Unix (macOS/Linux) installer
# Usage:
#   curl -fsSL https://github.com/CThawngs/Disk-Cleaner-MCP/releases/latest/download/install.sh | bash
#   ./install.sh [vX.Y.Z] [--version <tag>] [--install-dir <dir>] [--local-binary <path>] [--skip-binary] [--skip-client-config]
# Installs the MCP server binary atomically and additively registers it into detected MCP clients.

set -euo pipefail

VERSION="latest"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
LOCAL_BINARY=""
SKIP_BINARY=0
SKIP_CLIENT_CONFIG=0
POSITIONAL_VERSION_SET=0
OWNER="CThawngs"
REPO="Disk-Cleaner-MCP"

usage() {
  cat <<'EOF'
Usage: install.sh [VERSION] [OPTIONS]

Install disk-cleaner-mcp on macOS/Linux and additively register it in detected MCP clients.

Options:
  --version <tag>        Release tag to install (default: latest; positional vX.Y.Z also supported)
  --install-dir <dir>    Installation directory (default: $INSTALL_DIR or $HOME/.local/bin)
  --local-binary <path>  Install from an existing local binary instead of downloading
  --skip-binary          Skip binary download/copy (verify existing binary and configure clients only)
  --skip-client-config   Skip MCP client configuration updates
  -h, --help             Show this help message and exit
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --local-binary)
      if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
        echo "Error: --local-binary requires a file path" >&2
        exit 1
      fi
      LOCAL_BINARY="$2"
      shift 2
      ;;
    --local-binary=*)
      LOCAL_BINARY="${1#*=}"
      if [ -z "$LOCAL_BINARY" ]; then
        echo "Error: --local-binary requires a file path" >&2
        exit 1
      fi
      shift
      ;;
    --skip-binary)
      SKIP_BINARY=1
      shift
      ;;
    --skip-client-config)
      SKIP_CLIENT_CONFIG=1
      shift
      ;;
    --version)
      if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
        echo "Error: --version requires a release tag" >&2
        exit 1
      fi
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#*=}"
      if [ -z "$VERSION" ]; then
        echo "Error: --version requires a release tag" >&2
        exit 1
      fi
      shift
      ;;
    --install-dir)
      if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
        echo "Error: --install-dir requires a directory path" >&2
        exit 1
      fi
      INSTALL_DIR="$2"
      shift 2
      ;;
    --install-dir=*)
      INSTALL_DIR="${1#*=}"
      if [ -z "$INSTALL_DIR" ]; then
        echo "Error: --install-dir requires a directory path" >&2
        exit 1
      fi
      shift
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      if [ "$POSITIONAL_VERSION_SET" -eq 0 ]; then
        VERSION="$1"
        POSITIONAL_VERSION_SET=1
        shift
      else
        echo "Unexpected positional argument: $1" >&2
        usage >&2
        exit 1
      fi
      ;;
  esac
done

echo "=== disk-cleaner-mcp installer (Unix) ==="

OS="$(uname -s)"
ARCH="$(uname -m)"

TMP_BIN=""
SUM_TMP=""
cleanup_tmp() {
  if [ -n "${TMP_BIN:-}" ]; then
    rm -f "$TMP_BIN" || true
  fi
  if [ -n "${SUM_TMP:-}" ]; then
    rm -f "$SUM_TMP" || true
  fi
}
trap cleanup_tmp EXIT

mkdir -p "$INSTALL_DIR"
BIN="$INSTALL_DIR/disk-cleaner-mcp"

install_binary_atomically() {
  local src="$1"
  local dst="$2"
  local stage="${dst}.tmp.$$"
  TMP_BIN="$stage"
  cp "$src" "$stage"
  chmod +x "$stage"
  mv -f "$stage" "$dst"
  TMP_BIN=""
}

# 1. Install binary: --local-binary takes precedence over GitHub Release download
if [ -n "$LOCAL_BINARY" ]; then
  if [ ! -f "$LOCAL_BINARY" ]; then
    echo "Local binary not found at $LOCAL_BINARY" >&2
    exit 1
  fi
  if [ -e "$BIN" ] && [ "$LOCAL_BINARY" -ef "$BIN" ]; then
    chmod +x "$BIN"
    echo "Using existing local binary at $BIN"
  else
    install_binary_atomically "$LOCAL_BINARY" "$BIN"
    echo "Installed local binary from $LOCAL_BINARY to $BIN"
  fi
elif [ "$SKIP_BINARY" -eq 0 ]; then
  case "${OS}-${ARCH}" in
    Darwin-arm64) TARGET="aarch64-apple-darwin" ;;
    Darwin-x86_64) TARGET="x86_64-apple-darwin" ;;
    Linux-x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
    Linux-aarch64|Linux-arm64) TARGET="aarch64-unknown-linux-gnu" ;;
    *) echo "Unsupported platform: ${OS}-${ARCH}" >&2; exit 1 ;;
  esac

  if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required to download release artifacts" >&2
    exit 1
  fi

  if [ "$VERSION" = "latest" ]; then
    # /latest/download/ is a GitHub redirect that always points to the newest release
    URL="https://github.com/${OWNER}/${REPO}/releases/latest/download/disk-cleaner-mcp-${TARGET}"
    SUM_URL="https://github.com/${OWNER}/${REPO}/releases/latest/download/checksums.txt"
  else
    URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/disk-cleaner-mcp-${TARGET}"
    SUM_URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/checksums.txt"
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    HASH_CMD="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    HASH_CMD="shasum -a 256"
  else
    echo "sha256sum/shasum missing - refusing install" >&2
    exit 1
  fi

  TMP_BIN="${BIN}.tmp.$$"
  SUM_TMP="$(mktemp)"

  echo "Downloading $URL ..."
  curl -fsSL "$URL" -o "$TMP_BIN"

  # Verify SHA256 against release checksums (supply-chain integrity)
  curl -fsSL "$SUM_URL" -o "$SUM_TMP"
  EXPECTED="$(grep -E "(^|[[:space:]]|\*/)disk-cleaner-mcp-${TARGET}$" "$SUM_TMP" | awk '{print $1}' | head -n 1)"
  if [ -z "$EXPECTED" ]; then
    echo "checksums.txt missing entry for disk-cleaner-mcp-${TARGET}" >&2
    exit 1
  fi
  ACTUAL="$($HASH_CMD "$TMP_BIN" | awk '{print $1}')"
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "checksum mismatch (expected $EXPECTED, got $ACTUAL)" >&2
    exit 1
  fi
  echo "Checksum OK: $ACTUAL"

  chmod +x "$TMP_BIN"
  mv -f "$TMP_BIN" "$BIN"
  TMP_BIN=""
  rm -f "$SUM_TMP"
  SUM_TMP=""
fi

# 2. Verify binary exists
if [ ! -f "$BIN" ]; then
  echo "Binary not found at $BIN. Pass --local-binary <path>, build it locally, or check the release URL." >&2
  exit 1
fi

print_manual_snippets() {
  echo
  echo "Manual MCP client configuration (python3 not found for auto-registration):"
  echo "  - Claude Desktop / Claude Code / Cursor / Gemini CLI / Antigravity:"
  echo "      \"mcpServers\": { \"disk-cleaner-mcp\": { \"command\": \"$BIN\", \"args\": [], \"env\": {} } }"
  echo "  - OpenCode (~/.config/opencode/opencode.json):"
  echo "      \"mcp\": { \"disk-cleaner-mcp\": { \"type\": \"local\", \"command\": [\"$BIN\"], \"enabled\": true } }"
  echo "  - Codex (~/.codex/config.toml):"
  echo "      [mcp_servers.disk-cleaner-mcp]"
  echo "      command = \"$BIN\""
}

# 3. Additive UTF-8 MCP client registrations (never clobber sibling keys)
if [ "$SKIP_CLIENT_CONFIG" -eq 1 ]; then
  echo "Skipping MCP client configuration (--skip-client-config)."
elif command -v python3 >/dev/null 2>&1; then
  DCM_BIN_PATH="$BIN" DCM_OS="$OS" python3 - <<'PY'
import json
import os
import pathlib
import re
import sys

home_env = os.environ.get("HOME")
home = pathlib.Path(home_env) if home_env else pathlib.Path.home()
bin_path = os.environ["DCM_BIN_PATH"]
os_name = os.environ.get("DCM_OS", "")

def atomic_write_utf8(path, content):
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass

def register_json_client(name, path, root_key, entry, detect_dir=None):
    if detect_dir is not None:
        should_register = detect_dir.is_dir() or path.is_file()
    else:
        should_register = path.parent.is_dir()

    if not should_register:
        return

    print(f"Configuring {name} ({path})...")

    data = {}
    if path.is_file():
        raw = path.read_text(encoding="utf-8")
        if raw.strip():
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                print(f"  warning: invalid JSON in {path} ({exc}); skipping", file=sys.stderr)
                return
            if not isinstance(parsed, dict):
                print(f"  warning: expected top-level JSON object in {path}; skipping", file=sys.stderr)
                return
            data = parsed

    if root_key not in data or data[root_key] is None:
        data[root_key] = {}
    elif not isinstance(data[root_key], dict):
        print(f"  warning: '{root_key}' in {path} is not a JSON object; skipping", file=sys.stderr)
        return

    if "disk-cleaner-mcp" in data[root_key]:
        print("  already present, skipping")
        return

    data[root_key]["disk-cleaner-mcp"] = entry
    serialized = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    atomic_write_utf8(path, serialized)
    print("  OK")

def register_codex_toml(path, binary_path):
    if not path.parent.is_dir():
        return

    print(f"Configuring Codex ({path})...")
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""

    if re.search(
        r'(?m)^\s*\[mcp_servers\.(?:"disk-cleaner-mcp"|\'disk-cleaner-mcp\'|disk-cleaner-mcp)\]\s*$',
        existing,
    ):
        print("  already present, skipping")
        return

    cmd_toml = json.dumps(binary_path, ensure_ascii=False)
    block = f"[mcp_servers.disk-cleaner-mcp]\ncommand = {cmd_toml}\n"
    if not existing.strip():
        updated = block
    elif existing.endswith("\n"):
        updated = existing + "\n" + block
    else:
        updated = existing + "\n\n" + block

    atomic_write_utf8(path, updated)
    print("  OK")

standard_entry = {
    "command": bin_path,
    "args": [],
    "env": {},
}

opencode_entry = {
    "type": "local",
    "command": [bin_path],
    "enabled": True,
}

if os_name == "Darwin":
    claude_desktop_path = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
else:
    claude_desktop_path = home / ".config" / "Claude" / "claude_desktop_config.json"

json_clients = [
    ("Claude Desktop", claude_desktop_path, "mcpServers", standard_entry, None),
    ("Claude Code", home / ".claude.json", "mcpServers", standard_entry, home / ".claude"),
    ("Cursor", home / ".cursor" / "mcp.json", "mcpServers", standard_entry, None),
    ("Gemini CLI", home / ".gemini" / "settings.json", "mcpServers", standard_entry, None),
    ("Antigravity", home / ".gemini" / "antigravity" / "mcp_config.json", "mcpServers", standard_entry, None),
    ("OpenCode", home / ".config" / "opencode" / "opencode.json", "mcp", opencode_entry, None),
]

for name, cfg_path, root_key, entry, detect_dir in json_clients:
    register_json_client(name, cfg_path, root_key, entry, detect_dir)

register_codex_toml(home / ".codex" / "config.toml", bin_path)
PY
else
  print_manual_snippets
fi

echo
echo "Installed at: $BIN"
echo "Test: $BIN (expect MCP server to start, then you can use get_system_status / smart_scan / scan / analyze / delete)"
