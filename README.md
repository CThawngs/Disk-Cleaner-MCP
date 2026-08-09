# Disk-Cleaner-MCP

A **Rust-based MCP (Model Context Protocol) server** that gives AI agents — Hermes, Claude, Cursor, OpenClaw, Codex — the ability to **scan, analyze, organize, and safely clean junk files** on **Windows, macOS, and Linux**.

> Built for speed (multithreaded `jwalk` + `rayon`), safety (immutable blocklist + per-scan approval tokens), and zero-cost distribution (single static binary + GitHub Actions CI).

![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)
![Rust](https://img.shields.io/badge/Rust-1.95-orange)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Features

- **7 MCP tools**:
  | Tool | Description |
  |---|---|
  | `get_system_status` | Disk usage, user directories, platform info |
  | `list_categories` | All junk categories + descriptions |
  | `scan` | Scan a root path, returns `scanId` + summary |
  | `analyze` | Filter/page entries (category, size, age, sort), returns approval tokens |
  | `organize` | **Sort files into a destination tree by category or extension** (dry-run supported, never overwrites) |
  | `delete` | Move files to trash / permanent (requires double confirmation) |
  | `get_report` | Markdown report of a scan |

- **Safety Guard** (immutable, cannot be disabled):
  - Protected paths blocked: `C:\Windows`, `C:\Program Files`, `/usr`, `/boot`, `pagefile.sys`, `$Recycle.Bin`, etc.
  - Default delete = **recycle bin / trash** (recoverable)
  - Permanent delete requires `permanent=true` + `confirm_permanent=true`
  - Every delete/organize requires an **approval token** (SHA-256 of salt + path) issued per scan — stale/mismatched tokens are rejected
  - `organize` **never overwrites**: if the destination file exists, it's skipped

- **13 junk categories**: `temp`, `log`, `cache`, `browser_cache`, `node_cache`, `python_cache`, `installer`, `download`, `backup`, `archive`, `crash_dump`, `thumbnail`, `other`

- **Multithreaded scan**: `jwalk` parallel directory walker + `rayon` metadata extraction

- **Cross-platform**: Windows, macOS (Intel + ARM), Linux — single static binary

---

## 🚀 Quick Start

### Install (Windows)

```powershell
# Downloads the binary + registers with MCP clients
powershell -ExecutionPolicy Bypass -File install.ps1
```

### Install (macOS/Linux)

```bash
curl -fsSL https://github.com/CThawngs/Disk-Cleaner-MCP/releases/latest/download/install.sh | bash
```

### Build from source

```bash
cargo build --release
# Binary: target/release/disk-cleaner-mcp[.exe]
```

### Configure MCP client

Add to your MCP client config (e.g., Claude Desktop `claude_desktop_config.json`, Cursor `.cursor/mcp.json`, or OpenClaw `mcp.json`):

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

> On macOS/Linux: `"command": "/usr/local/bin/disk-cleaner-mcp"`

---

## 🧹 Workflow

```
1. get_system_status  →  See disk usage, user dirs
2. scan               →  Scan a root path (e.g., Downloads), get scanId + summary
3. analyze            →  Filter entries (category, size, age), get approval tokens
4. organize (optional) → Sort files into category/extension subfolders (dry-run first!)
5. delete             →  Delete with approval tokens (trash by default)
```

### Example: Clean old downloads

```json
// 1. Scan
{ "method": "tools/call", "params": { "name": "scan", "arguments": { "root": "C:/Users/me/Downloads" } } }

// 2. Analyze (find installers > 100MB)
{ "method": "tools/call", "params": { "name": "analyze", "arguments": { "scanId": "<id>", "category": "installer", "minSize": 104857600 } } }

// 3. Organize downloads by extension (dry-run first!)
{ "method": "tools/call", "params": { "name": "organize", "arguments": { "scanId": "<id>", "items": [{"approvalToken":"...","path":"..."}], "destDir": "C:/Users/me/Downloads/Organized", "strategy": "extension", "dryRun": true } } }

// 4. Delete (move to trash)
{ "method": "tools/call", "params": { "name": "delete", "arguments": { "scanId": "<id>", "items": [{"approvalToken":"...","path":"..."}] } } }
```

---

## 🛡️ Safety Architecture

```
┌──────────────────────────────────┐
│  AI Agent (LLM)                  │
│  - Suggests what to delete       │
│  - Provides approval tokens      │
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
│  │ Organize Engine              │ │
│  │ - category/extension groups  │ │
│  │ - never overwrite, dry-run   │ │
│  └─────────────────────────────┘ │
│  ┌─────────────────────────────┐ │
│  │ Delete Engine                │ │
│  │ - trash crate (default)      │ │
│  │ - permanent (opt-in)         │ │
│  └─────────────────────────────┘ │
└──────────────────────────────────┘
```

---

## 📚 Tech Stack

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

## 🧪 Development

```bash
# Check
cargo check

# Test (24 unit tests)
cargo test

# Lint (zero warnings required)
cargo clippy --all-targets -- -D warnings

# Format check
cargo fmt --check

# Release build
cargo build --release

# End-to-end smoke test (stdio JSON-RPC)
python smoke_test.py target/release/disk-cleaner-mcp.exe
```

### Definition of Done

Every change must pass: `cargo fmt --check` → `cargo clippy --all-targets -- -D warnings` → `cargo build --release` → `cargo test` → smoke test E2E.

---

## 📁 Repository Layout

```
├── src/
│   ├── main.rs            # Entry point (tokio + stdio transport)
│   ├── model.rs           # JSON-serializable data models (camelCase)
│   ├── safety.rs          # Safety Guard: blocklist, tokens, path normalization
│   ├── engine.rs          # Scan/analyze/organize/delete engines
│   ├── analytics.rs       # 13 junk categories + report generator
│   ├── server.rs          # MCP tool handlers (7 tools)
│   └── sysinfo_helper.rs  # Disk info, user dirs
├── .github/workflows/ci.yml   # CI: fmt + clippy + test + build on 3 OS
├── install.ps1                # Windows installer
├── install.sh                 # macOS/Linux installer
├── smoke_test.py              # End-to-end JSON-RPC smoke test
├── demo_real.py               # Real-world cleanup demo (creates junk, cleans it)
└── survey_real.py             # Read-only junk survey (measures reclaimable space)
```

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch
3. Commit with clear messages
4. Open a PR — CI runs fmt + clippy + test on Windows/macOS/Linux

---

## 📄 License

MIT — free to use, modify, and distribute. No fees, no telemetry, no cloud dependency — **100% free forever**.