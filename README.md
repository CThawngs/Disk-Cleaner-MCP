# disk-cleaner-mcp

A **Rust-based MCP (Model Context Protocol) server** that lets AI agents — Hermes, Claude, Cursor, OpenClaw, Codex — scan, analyze, and safely clean junk files on **Windows, macOS, and Linux**.

Built for speed (multithreaded `jwalk` + `rayon`), safety (immutable blocklist + approval tokens), and zero-cost distribution (single static binary, GitHub Actions CI).

---

## Features

- **6 MCP tools**: `get_system_status`, `scan`, `analyze`, `delete`, `list_categories`, `get_report`
- **Safety Guard** (immutable, cannot be disabled):
  - Blocks `C:\Windows`, `C:\Program Files`, `/usr`, `/boot`, `pagefile.sys`, etc.
  - Default delete = **recycle bin / trash** (recoverable)
  - Permanent delete requires `permanent=true` + `confirm_permanent=true`
  - Every delete requires an **approval token** (SHA-256 of salt + path) from the original scan — prevents stale-path attacks
- **13 junk categories**: temp, log, cache, browser_cache, node_cache, python_cache, installer, download, backup, archive, crash_dump, thumbnail, other
- **Multithreaded scan**: `jwalk` parallel directory walker + `rayon` for metadata extraction
- **Cross-platform**: Windows, macOS (Intel + ARM), Linux
- **Single binary**: no runtime dependencies, no Node.js, no Python — just one `.exe` / binary

---

## Quick Start

### Install (Windows)

```powershell
# Download the binary + register with MCP clients
powershell -ExecutionPolicy Bypass -File install.ps1
```

### Install (macOS/Linux)

```bash
curl -fsSL https://github.com/<OWNER>/disk-cleaner-mcp/releases/latest/download/install.sh | bash
```

### Build from source

```bash
cargo build --release
# Binary: target/release/disk-cleaner-mcp[.exe]
```

### Configure MCP client

Add to your MCP client config (e.g., Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "disk-cleaner-mcp": {
      "command": "C:\\Users\\<you>\\AppData\\Local\\disk-cleaner-mcp\\disk-cleaner-mcp.exe",
      "args": []
    }
  }
}
```

---

## Workflow

```
1. get_system_status  →  See disk usage, user dirs
2. scan               →  Scan a root path (e.g., Downloads), get scanId + summary
3. analyze            →  Filter entries (category, size, age), get approval tokens
4. (Review)           →  AI agent or human reviews the list
5. delete             →  Delete with approval tokens (trash by default)
```

### Example: Clean old downloads

```json
// 1. Scan
{ "method": "tools/call", "params": { "name": "scan", "arguments": { "root": "C:/Users/me/Downloads" } } }

// 2. Analyze (find installers > 100MB)
{ "method": "tools/call", "params": { "name": "analyze", "arguments": { "scanId": "<id>", "category": "installer", "minSize": 104857600 } } }

// 3. Delete (move to trash)
{ "method": "tools/call", "params": { "name": "delete", "arguments": { "scanId": "<id>", "items": [{"approvalToken":"...","path":"..."}] } } }
```

---

## Safety Architecture

```
┌──────────────────────────────────┐
│  AI Agent (LLM)                  │
│  - Suggests what to delete       │
│  - Provides approval tokens       │
└──────────┬───────────────────────┘
           │ JSON-RPC over stdio
┌──────────▼───────────────────────┐
│  Rust Engine (this server)        │
│  ┌─────────────────────────────┐ │
│  │ Safety Guard (immutable)     │ │
│  │ - Blocklist check            │ │
│  │ - Token verification         │ │
│  │ - Path normalization        │ │
│  └─────────────────────────────┘ │
│  ┌─────────────────────────────┐ │
│  │ Scan Engine                  │ │
│  │ - jwalk (parallel walk)      │ │
│  │ - rayon (metadata extract)   │ │
│  │ - Category classification    │ │
│  └─────────────────────────────┘ │
│  ┌─────────────────────────────┐ │
│  │ Delete Engine                │ │
│  │ - trash crate (default)       │ │
│  │ - permanent (opt-in)          │ │
│  └─────────────────────────────┘ │
└──────────────────────────────────┘
```

---

## Tech Stack

| Component | Crate | Purpose |
|---|---|---|
| MCP Protocol | `rmcp` 3.1 | Official Rust MCP SDK (JSON-RPC over stdio) |
| Directory Walk | `jwalk` 0.9 | Multithreaded parallel filesystem walk |
| Parallelism | `rayon` | Data-parallel metadata extraction |
| Safe Delete | `trash` 5 | Move to OS recycle bin / trash |
| Disk Info | `sysinfo` | Disk usage, platform detection |
| Hashing | `sha2` | Approval token generation |
| Schema | `schemars` | JSON Schema for MCP tool parameters |

---

## Development

```bash
# Check
cargo check

# Test (19 unit tests)
cargo test

# Lint
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt --check

# Release build
cargo build --release
```

## License

MIT