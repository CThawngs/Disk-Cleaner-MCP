# Disk-Cleaner-MCP

A **Rust-based MCP (Model Context Protocol) server** that gives AI agents — Hermes, Claude, Cursor, OpenClaw, Codex — the ability to **scan, analyze, organize, and safely clean junk files** on **Windows, macOS, and Linux**.

> Built for speed (multithreaded `jwalk` + `rayon`), safety (immutable blocklist + per-scan approval tokens), and zero-cost distribution (single static binary + GitHub Actions CI).

![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)
![Rust](https://img.shields.io/badge/Rust-1.95-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/github/v/release/CThawngs/Disk-Cleaner-MCP)
![CI](https://img.shields.io/github/actions/workflow/status/CThawngs/Disk-Cleaner-MCP/ci.yml?label=CI)

---

## ✨ Features

- **100% Pure Headless MCP Server (Zero GUI, Zero Telemetry)** — purpose-built for AI Agents & Coding Agents (`Claude Code`, `Cursor`, `Codex`, `Antigravity`, `OpenCode`, `Hermes`, `DeepSeek Harness`, `OpenMausBot`).
- **20 MCP tools**:
  | Tool | Description |
  |---|---|
  | `get_system_status` | Disk usage, user directories, platform info |
  | `get_metrics` | Aggregated disk metrics across mounted volumes (gated by `DCM_TELEMETRY`) |
  | `get_hardware_health` | **NEW (v0.6.0)** — Zero-estimation Battery + SSD SMART health + deterministic **Agent I/O Guardrails** (`ioSafetyLevel`, `avoidHeavyDiskHash`, `minimizeWriteChurn`, `diskPressureAction`) with serial/UUID redaction |
  | `smart_scan` | **NEW (v0.6.0)** — Zero-config Allowlist Smart Scan + Dev/Package caches + **AI-Stack Surgical Cleaner** (`HuggingFace *.incomplete`, `Ollama` orphan blobs, superseded `Playwright` browsers, AI IDE disposable caches with live-process Anti-Suicide lock) + `targetFreeBytes` reclaim planner |
  | `scan_browsers` | **NEW (v0.6.0)** — Per-browser & per-profile audit across 10 Chromium browsers + Firefox (`disposableCache` Green, `aiModels` Yellow incl. Gemini Nano/SODA/ScreenAI, opt-in `websiteStorage` Yellow via pure-Rust read-only LevelDB) |
  | `scan_app_leftovers` | **NEW (v0.6.0)** — Cross-platform orphaned app leftovers (`safeLeftovers` caches/logs vs `userData` profiles, `minAgeDays` default 30) |
  | `scan_startup_items` | **NEW (v0.6.0)** — Cross-platform Startup / LaunchAgents / systemd-user orphan detector with CLI secret redaction |
  | `find_large_forgotten` | **NEW (v0.6.0)** — Large & forgotten files grouped into 8 semantic kinds (`video`, `archive`, `installer`, `ml_model`, `disk_image`, `audio`, `image`, `document`, `other`) |
  | `list_categories` | All 20 junk & storage categories + descriptions |
  | `scan` | Scan a root path (`maxEntries` 100–2M, `maxDepth` 1–64 caps), returns `scanId` + summary |
  | `analyze` | Filter/page entries (category, size, age, sort), returns approval tokens |
  | `get_tree` | **TreeSize-style folder tree** — recursive size per folder ("where did the space go?") |
  | `file_types` | **TreeSize-style file-type breakdown** — size/count per extension |
  | `find_duplicates` | **SIMD `BLAKE3` duplicate finder** — size + head/tail prefilter + streaming `BLAKE3`, skips Cloud-Only placeholders (OneDrive/iCloud) & Unix hardlinks |
  | `compare_scans` | **TreeSize-style diff** — what changed between two scans (added/removed/grown, net delta) |
  | `organize` | **Sort files into a destination tree by category or extension** (dry-run supported, never overwrites) |
  | `delete` | Move files to trash / permanent (requires double confirmation). Brain judges every file first: `blocked` never, `review`/`keep` need `confirm_risk=true`, `browser_site_data` is Trash-only |
  | `get_report` | Markdown report of a scan |
  | `empty_trash` | **Permanently purge the OS Recycle Bin / Trash** (irreversible, requires `confirm=true`) — use after `delete` to reclaim space |
  | `list_trash` | List current Recycle Bin / Trash contents (newest first, `limit` 1–500) |

- **Safety Guard** (immutable, cannot be disabled):
  - Protected paths blocked: `C:\Windows`, `C:\Program Files`, `/usr`, `/boot`, `pagefile.sys`, `$Recycle.Bin`, etc.
  - Default delete = **recycle bin / trash** (recoverable)
  - Permanent delete requires `permanent=true` + `confirm_permanent=true`
  - Every delete/organize requires an **approval token** (SHA-256 of salt + path) issued per scan — stale/mismatched tokens are rejected
  - `organize` **never overwrites**: if the destination file exists, it's skipped

- **20 junk & storage categories**: `temp`, `log`, `cache`, `browser_cache`, `browser_ai_model`, `browser_site_data`, `node_cache`, `python_cache`, `dev_cache`, `ml_cache`, `app_leftover`, `startup_orphan`, `large_forgotten`, `installer`, `download`, `backup`, `archive`, `crash_dump`, `thumbnail`, `other`
- **Hard Never-Touch Guard**: Passwords/`Login Data`, `Cookies`, `History`, `Bookmarks`, `Local Storage`, `Extensions`, `key4.db`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.env*`, Keychains, and DPAPI vaults are strictly blocked at both scan and delete time.

- **Multithreaded scan**: `jwalk` parallel directory walker + `rayon` metadata extraction

- **Cross-platform**: Windows, macOS (Intel + ARM), Linux — single static binary

---

## 🚀 Quick Start

### ⬇️ Latest Release (v0.3.0)

Pre-built binaries for all platforms — no Rust toolchain needed:

| Platform | Binary | Size |
|---|---|---|
| Windows x64 | [disk-cleaner-mcp-x86_64-pc-windows-msvc.exe](https://github.com/CThawngs/Disk-Cleaner-MCP/releases/latest/download/disk-cleaner-mcp-x86_64-pc-windows-msvc.exe) | 4.1 MB |
| Linux x64 | [disk-cleaner-mcp-x86_64-unknown-linux-gnu](https://github.com/CThawngs/Disk-Cleaner-MCP/releases/latest/download/disk-cleaner-mcp-x86_64-unknown-linux-gnu) | 3.8 MB |
| macOS ARM (M-series) | [disk-cleaner-mcp-aarch64-apple-darwin](https://github.com/CThawngs/Disk-Cleaner-MCP/releases/latest/download/disk-cleaner-mcp-aarch64-apple-darwin) | 3.2 MB |

> Doubt the safety? Read [docs/WORKFLOW.md](docs/WORKFLOW.md) first. All binaries are
> built from source by GitHub Actions — no third-party, no telemetry, free 100%.

### Install (Windows)

```powershell
# Downloads the binary + registers with MCP clients
powershell -ExecutionPolicy Bypass -File install.ps1
```

### Install (macOS/Linux)

```bash
# One-liner — downloads the right binary for your arch + prints MCP config
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

> **macOS Gatekeeper**: release binaries are ad-hoc signed. If macOS still blocks the downloaded binary, allow it once: `xattr -d com.apple.quarantine disk-cleaner-mcp`.

---

## 🧹 Workflow

> Full agent-facing guide: **[docs/WORKFLOW.md](docs/WORKFLOW.md)** — tool-by-tool
> JSON examples, 13-category classification table, safety model, and recommended
> agent policy.

```
1. get_system_status  →  See disk usage, user dirs
2. scan               →  Scan a root path (e.g., Downloads), get scanId + summary
3. get_tree/file_types/find_duplicates → See WHERE and WHAT is eating space, find exact copies
4. analyze            →  Filter entries (category, size, age), get approval tokens
5. organize (optional) → Sort files into category/extension subfolders (dry-run first!)
6. delete             →  Delete with approval tokens (trash by default)
7. compare_scans      →  Verify: rescan + diff to show the net delta
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

### transports

Default: stdio. Optional HTTP (loopback-only, requires `http` feature build):
`disk-cleaner-mcp --http [PORT]` (default `8000`) serves Streamable HTTP at
`http://127.0.0.1:8000/mcp`.

### custom rules (optional)

`config_dir/disk-cleaner-mcp/config.json` (loaded once at startup; additive
only — built-in Safety Guard blocks can never be lifted):

```json
{ "protectedExtra": ["D:/important"], "keepGlobs": ["*.key"], "safeGlobs": ["*.tmp"] }
```

- `protectedExtra`: extra paths always blocked
- `keepGlobs`: glob matches forced to `keep`
- `safeGlobs`: glob matches downgraded to `safe_to_delete`

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

# Test (29 unit tests)
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
│   ├── brain.rs           # Per-file judgment: safe_to_delete / review / keep / blocked
│   ├── insights.rs        # TreeSize-grade analytics: tree, file types, duplicates, compare
  ├── server.rs          # MCP tool handlers (14 tools)
│   └── sysinfo_helper.rs  # Disk info, user dirs
├── .github/workflows/ci.yml   # CI: fmt + clippy + test + build on 3 OS
├── docs/WORKFLOW.md           # Agent-facing workflow guide (JSON examples, categories, safety)
├── install.ps1                # Windows installer
├── install.sh                 # macOS/Linux installer
├── smoke_test.py              # End-to-end JSON-RPC smoke test
├── demo_real.py               # Real-world cleanup demo (creates junk, cleans it)
└── survey_real.py             # Read-only junk survey (measures reclaimable space)
```

---

## 🤖 Works with AI Agents

Any agent that speaks **MCP** can drive this server. Full agent-facing guide:
**[docs/WORKFLOW.md](docs/WORKFLOW.md)**.

| Agent | Config file | Entry |
|---|---|---|
| **Hermes** | `~/AppData/Local/hermes/config.yaml` | `mcp_servers: disk-cleaner: {command: ...}` |
| **Claude Desktop** | `claude_desktop_config.json` | `mcpServers.disk-cleaner` |
| **Cursor** | `.cursor/mcp.json` | `mcpServers.disk-cleaner` |
| **OpenClaw** | `mcp.json` | `mcpServers.disk-cleaner` |
| **Codex / Antigravity** | MCP CLI | `codex mcp add disk-cleaner -- ...` |

**Example agent turn:** *(Hermes-style)*
```
User: "Dọn rác temp giúp tôi"
1. get_system_status → C: 5.7GB free
2. scan("C:/Users/me/AppData/Local/Temp")
3. analyze(scanId, category="temp") → 41 files, tokens attached
4. delete(scanId, items=[...]) → trashed, vào Thùng rác
5. "Đã dọn 1.2GB rác temp. Ổ C còn 6.8GB free."
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

---

## 🙏 Acknowledgements

Several `v0.6.0` cross-platform capability concepts (Allowlist Smart Scan taxonomy, 3-tier Browser Cleanup + On-Device AI Models, Orphaned App Leftovers & Startup Items, Zero-Estimation SSD SMART / Battery Health, and Read-Only LevelDB origin inspection) were inspired by [**MacSweep**](https://github.com/nihal4/macsweep) (`MIT License`, Copyright (c) 2026 S. M. Nihal Ahmed) and re-architected as a 100% pure headless cross-platform MCP server for AI Agents on Windows, macOS, and Linux. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for full license notices.
