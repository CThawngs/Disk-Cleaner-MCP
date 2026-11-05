# Disk-Cleaner-MCP — Workflow Guide

> **For AI agents** (Hermes, Claude, Cursor, OpenClaw, Codex, Antigravity) and humans.
> This document explains how to drive the 14 MCP tools safely and effectively.

---

## 1. The Core Principle

**Never skip a step.** The pipeline is deliberately split into separate tools so
that every destructive action is:

1. **Scoped** — only files the agent has actually *scanned* can be touched.
2. **Reviewed** — the agent (and optionally a human) sees the list before any action.
3. **Tokenized** — every delete/organize requires an approval token that only
   the server can produce (SHA-256 of salt + path).
4. **Reversible** — the default delete action moves files to the OS trash.

```
┌──────────┐   ┌──────────┐   ┌────────────┐   ┌───────────┐   ┌──────────┐
│  1. Scan │ → │ 2.Insight│ → │ 3. Organize│ → │ 4. Delete │ → │ 5. Report│
│ (read)   │   │ tree/dup │   │ (optional) │   │ (trash)   │   │ (read)   │
└──────────┘   └──────────┘   └────────────┘   └───────────┘   └──────────┘
```

---

## 2. Tool-by-Tool Workflow

### Step 1 — `get_system_status`
Check disk free space, temp dirs, and the platform before doing anything.

```json
{"method": "tools/call", "params": {"name": "get_system_status", "arguments": {}}}
```

### Step 2 — `scan`
Scan a root path. Returns `scanId` + summary.

```json
{"method": "tools/call", "params": {
  "name": "scan",
  "arguments": {"root": "C:/Users/me/Downloads"}
}}
```

**Response shape** (the full entry list is NOT returned — use `analyze` to page through it):
```json
{
  "summary": {
    "scanId": "scan-1789057093-1900",
    "startedAt": 1789057093,
    "durationMs": 342,
    "root": "C:/Users/me/Downloads",
    "filesScanned": 200,
    "dirsScanned": 18,
    "totalSize": 10415691776,
    "truncated": false,
    "categoryTotals": [
      {"category": "installer", "categoryLabel": "Installers", "count": 3, "size": 2147483648}
    ],
    "largestEntries": [ ...top 20 largest files... ],
    "warnings": []
  },
  "entriesCount": 218,
  "message": "Scan complete. 218 entries found. Use analyze with scanId to filter and page."
}
```

> ⚠️ `scanId` lives under `summary.scanId` — not top-level. `entriesCount` IS top-level.

### Step 3 — `analyze`
Filter the scanned entries (category, size, age, glob, extension) and receive
**approval tokens** for the filtered set.

```json
{"method": "tools/call", "params": {
  "name": "analyze",
  "arguments": {
    "scanId": "a1b2c3...",
    "category": "installer",
    "minSize": 104857600,
    "sortBy": "size",
    "sortDesc": true,
    "offset": 0,
    "limit": 100
  }
}}
```

**Response shape** (each entry carries its own token):
```json
{
  "scanId": "a1b2c3...",
  "page": [
    {
      "path": "C:/Users/me/Downloads/setup-v2.exe",
      "kind": "file",
      "size": 2147483648,
      "category": "installer",
      "categoryLabel": "Installers",
      "extension": "exe",
      "approvalToken": "9f86d081884c7d659a2feaa0c55ad015..."
    }
  ],
  "total": 3,
  "pageSize": 3
}
```

### Step 3b — TreeSize-grade insights (all read-only)

Four tools, modeled on [TreeSize](https://www.jam-software.com/treesize), give the
agent the same analytical depth the desktop app gives humans — over the entries
already cached from `scan` (no re-walk except content hashing in `find_duplicates`).

#### `get_tree` — where did the space go?

Recursive folder sizes, TreeSize "folder view":

```json
{"method": "tools/call", "params": {
  "name": "get_tree",
  "arguments": {"scanId": "a1b2c3...", "top": 10}
}}
```

```json
{
  "name": "Downloads",
  "size": 53687091200,        // this folder + ALL descendants
  "files": 4821,
  "directSize": 1048576,
  "percent": 100.0,
  "children": [
    {"name": "isos", "size": 41231686041, "percent": 76.8, "...": "..."},
    {"name": "(+14 more)", "size": 12455284728, "percent": 23.2}
  ],
  "childrenTruncated": true
}
```

> Truncated children are folded into a `(+N more)` rollup so totals stay exact.
> Drill down by scanning the biggest subfolder, then call `get_tree` again.

#### `file_types` — what type of file is eating space?

```json
{"method": "tools/call", "params": {
  "name": "file_types",
  "arguments": {"scanId": "a1b2c3...", "limit": 30}
}}
```

```json
{
  "totalFiles": 4821,
  "totalSize": 53687091200,
  "extensionCount": 87,
  "byExtension": [
    {"extension": "iso", "count": 3, "size": 38654705664},
    {"extension": "mp4", "count": 41, "size": 12884901888},
    {"extension": "log", "count": 1204, "size": 734003200}
  ]
}
```

#### `find_duplicates` — byte-identical copies (TreeSize Personal/Pro feature)

Cheap size prefilter → parallel streaming SHA-256 only over same-size files.
Files >4 GB are skipped (bounded I/O). Every returned file carries its
`approvalToken`, so deleting redundant copies flows through the normal safety path.

```json
{"method": "tools/call", "params": {
  "name": "find_duplicates",
  "arguments": {"scanId": "a1b2c3...", "minSize": 1048576, "top": 50}
}}
```

```json
{
  "groupsFound": 2,
  "totalWasted": 3221225472,
  "topGroups": [
    {
      "size": 2147483648,
      "fileCount": 2,
      "wastedSize": 2147483648,
      "files": [
        {"path": ".../backup-old.iso", "modified": 1690000000, "approvalToken": "9f86..."},
        {"path": ".../backup-old (1).iso", "modified": 1690000500, "approvalToken": "c2b5..."}
      ]
    }
  ]
}
```

> ⚠️ **Never delete all copies** — `files` is oldest-first; keep `files[0]`,
> delete the rest (they are exact byte-identical twins, verified by hash).

#### `compare_scans` — TreeSize "compare over time"

Diff two scans of the same tree (both scans must still be cached — the engine
keeps the 3 most recent):

```json
{"method": "tools/call", "params": {
  "name": "compare_scans",
  "arguments": {"scanIdA": "scan-before", "scanIdB": "scan-after", "top": 50}
}}
```

```json
{
  "totalA": 53687091200, "totalB": 51539607552,
  "netDelta": -2147483648,          // negative = space freed
  "addedCount": 3, "addedSize": 52428800,
  "removedCount": 1, "removedSize": 2200341504,
  "changedCount": 2,
  "topRemoved": [{"path": ".../old-setup.exe", "before": 2200341504, "after": 0, "delta": -2200341504}]
}
```

Use it to verify a cleanup actually freed what it claimed, or to show the user
what changed since last week.

### Step 4 (optional) — `organize`
Sort files into a categorized destination tree. **Always dry-run first.**

```json
{"method": "tools/call", "params": {
  "name": "organize",
  "arguments": {
    "scanId": "a1b2c3...",
    "items": [
      {"approvalToken": "9f86...", "path": "C:/Users/me/Downloads/img1.png"}
    ],
    "destDir": "C:/Users/me/Downloads/Organized",
    "strategy": "extension",
    "dryRun": true
  }
}}
```

Strategies:
- `category` — group by junk category (`temp/`, `installer/`, `image/`...)
- `extension` — group by file extension (`PNG/`, `PDF/`, `ZIP/`...)

Organize **never overwrites**: if the destination file already exists, the file
is skipped (reported in `skipped`). Plan output is a tree like:

```
Organized/
├── PNG/    ← 12 files
├── JPG/    ← 15 files
└── ZIP/    ← 3 files
```

### Step 5 — `delete`
Move files to trash (recoverable) — or permanently, with double confirmation.

```json
{"method": "tools/call", "params": {
  "name": "delete",
  "arguments": {
    "scanId": "a1b2c3...",
    "items": [
      {"approvalToken": "9f86...", "path": "C:/Users/me/Downloads/setup-v2.exe"}
    ],
    "permanent": false
  }
}}
```

**Permanent delete requires BOTH flags:**
```json
{"permanent": true, "confirm_permanent": true}
```

**Delete outcomes** per item: `trashed` | `permanent` | `rejected` | `error` | `not_found`.

### Step 6 — `get_report`
Get a human-readable Markdown report of the scan.

---

## 3. File Classification (13 categories)

The server classifies each scanned file by **extension + directory + name**:

| # | Category | Detected by | Safe to auto-delete? |
|---|----------|-------------|----------------------|
| 1 | `temp` | `.tmp`, `.temp`, in `%TEMP%` | ✅ yes |
| 2 | `log` | `.log`, `.etl`, `.blg` | ⚠️ review |
| 3 | `cache` | `.cache`, Cache_Data | ✅ yes |
| 4 | `browser_cache` | browser profile caches | ✅ yes |
| 5 | `node_cache` | `.npm`, node_modules caches | ✅ yes |
| 6 | `python_cache` | `__pycache__`, `.pyc` | ✅ yes |
| 7 | `installer` | `.exe`, `.msi`, `.dmg`, setup* | ⚠️ review |
| 8 | `download` | `.crdownload`, `.part`, `.download` | ✅ yes |
| 9 | `backup` | `.bak`, `.old`, `~` prefix | ⚠️ review |
| 10 | `archive` | `.zip`, `.rar`, `.7z` | ⚠️ review |
| 11 | `crash_dump` | `.dmp` | ✅ yes |
| 12 | `thumbnail` | `Thumbs.db`, `.DS_Store` | ✅ yes |
| 13 | `other` | everything else | ❌ never auto |

> **Traffic-light rule of thumb for agents:**
> - 🟢 **Green** (`temp`, `cache`, `crash_dump`, `download`, `thumbnail`) — safe to
>   propose deleting automatically, always via trash.
> - 🟡 **Yellow** (`log`, `installer`, `backup`, `archive`) — propose but flag for
>   human confirmation; never permanent.
> - 🔴 **Red** (`other`, any protected path) — never delete, never organize blindly.

---

## 4. Safety Model (non-negotiable)

### Protected paths (hard blocklist, cannot be bypassed)
Windows: `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`,
`C:\ProgramData`, `C:\System Volume Information`, `C:\Recovery`, `C:\$Recycle.Bin`,
`C:\Boot`, `C:\EFI` + `pagefile.sys`, `hiberfil.sys`, `swapfile.sys`, `ntuser.dat`.

Unix: `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/boot`, `/etc`, `/var`,
`/System`, `/Library`, `/Applications`, `/Volumes`, `/dev`, `/proc`, `/sys`,
`/opt`, `/root`, `/home`.

### Approval tokens
- Issued per-scan (salt generated at scan time).
- `token = hex(sha256(salt + ":" + path))`
- Verify is constant-time; mismatched tokens → `rejected`.
- Prevents: stale paths, guessed paths, path mutation between scan and delete.

### Reversibility
- Default delete → OS trash / recycle bin (recoverable).
- Permanent delete needs `permanent=true` **and** `confirm_permanent=true`.

---

## 5. Recommended Agent Policy

1. **Start with `get_system_status`** — know the disk before acting.
2. **Scan a narrow root** (e.g. `%TEMP%`, `Downloads`) — never the whole drive
   in one go.
3. **Look before you list** — run `get_tree` (biggest folders) and `file_types`
   (biggest types) first; drill into the hotspot instead of paging blindly.
4. **Check `find_duplicates`** before proposing deletions — exact-copy groups are
   the safest big wins (keep one, trash the rest).
5. **Analyze with filters** — pick `category=temp` etc., sort by size desc.
6. **Organize with `dryRun:true` first** — show the planned tree to the user.
7. **Delete green-category files only** — with `permanent:false`.
8. **Verify with `compare_scans`** — rescan after cleanup and show the net delta.
9. **Summarize the outcome** — bytes freed, files trashed, any errors.

### Example agent turn (Hermes-style)

```
User: "Dọn rác temp giúp tôi"

1. get_system_status → C: 5.7GB free
2. scan("C:/Users/me/AppData/Local/Temp")
3. analyze(scanId, category="temp", sort="size", order="desc")
   → 41 files, 1.2GB, tokens attached
4. delete(scanId, items=[...], permanent=false)
   → trashed=41, rejected=0, errors=6 (locked files)
5. "Đã dọn 1.2GB rác temp vào Thùng rác. 6 file đang bị app khóa
   — Windows sẽ tự dọn sau. Ổ C còn 6.8GB free."
```

---

## 6. MCP Client Registration

### Hermes Agent
```yaml
# ~/AppData/Local/hermes/config.yaml
mcp_servers:
  disk-cleaner:
    command: "C:/Users/<you>/tools/disk-cleaner-mcp.exe"
```

### Cursor
```json
// .cursor/mcp.json
{"mcpServers": {"disk-cleaner": {"command": "C:/Users/<you>/tools/disk-cleaner-mcp.exe"}}}
```

### Claude Desktop
```json
// claude_desktop_config.json
{"mcpServers": {"disk-cleaner": {"command": "C:\\Users\\<you>\\tools\\disk-cleaner-mcp.exe"}}}
```

### OpenClaw / Antigravity / Codex
Add the same command to their MCP config (format varies slightly per tool).

---

## 7. FAQ

**Q: Why not a single "clean everything" tool?**
A: Because AI agents propose, humans dispose. Splitting scan/analyze/delete
forces review between intent and action — the safety guard is the engine's
way of never trusting the model blindly.

**Q: Why tokens?**
A: Tokens bind every delete to a specific scanned path. An agent can't delete
`C:\Windows\...` because (a) the blocklist rejects it, and (b) it has no valid
token for it.

**Q: Why trash by default?**
A: Mistakes happen. Trash = recoverable. Permanent is opt-in, double-confirmed.

**Q: What about files locked by running apps?**
A: `delete` reports `errors` for locked files — Windows/macOS free them when the
app closes. They're never force-deleted.

---

*Security note: this document is guidance, not policy. The Rust engine enforces
safety at runtime regardless of what an agent reads here.*