# ARCHITECTURE.md — Disk Cleaner MCP (Rust)

## 1. Mô hình 2 tầng

```
┌────────────────────────────┐      JSON-RPC over stdio       ┌─────────────────────────────┐
│  Tầng 1 — Rust Engine       │ ◄────────────────────────────► │  Tầng 2 — AI Agent (LLM)    │
│  (MCP Server, binary)       │                                │  (Hermes, Claude, Cursor…)  │
│                             │                                │                             │
│ • Scan I/O song song        │──── scan_id + metadata ──────► │ đọc, suy luận ngữ cảnh,      │
│ • Metadata nhẹ (size/time)  │                                │ lập danh sách đề xuất       │
│ • Categorize junk           │◄──── approval (paths+tokens) ──│ gửi approval_token          │
│ • Cấp approval_token SHA-256│                                │ khi Chủ dự án duyệt         │
│ • Safety Guard + trash      │                                │                             │
└────────────────────────────┘                                └─────────────────────────────┘
```

**Tại sao tách hoặc ẩn logic?** Rust lo phần quét/nuốt tín hiệu + an toàn (không thể bị "thuyết phục" xóa nhầm). LLM lo phần suy luận ngữ cảnh (file rác = gì, an toàn hay không) — nơi LLM mạnh. LLM KHÔNG bao giờ chạm đường dẫn trực tiếp khi xóa: phải thông qua token.

## 2. Luồng dữ liệu chi tiết

### Scan (`tools/call scan`)
1. Validate root (tồn tại, không nằm ở chế độ cấm *root xóa*, có mount).
2. Tạo session: `scan_id = hex(rand 12B)`, `salt = rand 32B` (bí mật, không bao giờ xuất ra).
3. `jwalk` đi bộ song song root; `process_read_dir` prune `.git`, `$Recycle.Bin`, `System Volume Information`; max_depth mặc định 15.
4. Với từng entry: lọc tên/đuôi trước → `metadata` (stat) bằng `rayon` song song → lọc kích thước → categorize → `approval_token = hex(sha256(salt ‖ ":" ‖ normalized_path))`.
5. Tổng hợp: `ScanSummary` (counts, category_totals, top-20 largest) + cache entries trong bộ nhớ (LRU, tối đa 3 scan gần nhất).
6. **Không đổ toàn bộ entries về client** — client dùng `analyze` để phân trang.

### Analyze
- Lọc server-side: `kind`, `category`, `name_glob`, `extension`, `min_size`, `min_age_days`.
- Sắp xếp theo `sort_by` (default size desc), phân trang `offset/limit` (tối đa 500/trang). Mỗi entry đi kèm `approval_token`.
- `insights`: top file lớn, thư mục lớn nhất, đề xuất mẫu.

### Delete
- Input: `scan_id` + mảng `{approval_token, path}`.
- Guard order: (1) path phải ∈ session; (2) không chạm protected (Safety Guard); (3) token khớp `sha256(salt:path)`; (4) trash hoặc remove theo flag.
- Mặc định `trash`; xóa vĩnh viễn chỉ khi `permanent=true && confirm_permanent=true`. Mỗi item trả `result trạng thái` riêng.

## 3. Module map (src/)

| Module | Trách nhiệm |
|---|---|
| `main.rs` | Entry, tracing, `serve(stdio)` |
| `server.rs` | MCP tool định nghĩa (`#[tool(tool_box)]`) |
| `engine.rs` | ScanEngine: walk + stat + token + cache |
| `safety.rs` | SecurityGuard: blocklist, normalize, verify token, protected check |
| `analytics.rs` | Lọc/sort/phân trang/glob/insights/report markdown |
| `insights.rs` | TreeSize-grade analytics: folder tree, file types, duplicate finder, scan diff |
| `sysinfo_helper.rs` | System status, standard dirs per OS |
| `model.rs` | Các struct serde (ScanEntry, ScanSummary…) |

### Insights (TreeSize-grade, v0.2 — src/insights.rs)
- `get_tree`: roll size mỗi file lên toàn bộ ancestor → node giữ recursive size; children sort size desc, truncate `top` + rollup "(+N more)" giữ tổng chính xác.
- `file_types`: group extension → (count, size), sort size desc.
- `find_duplicates`: prefilter theo size → head hash 64KB+len → full SHA-256 CHỈ nhóm trùng head → group theo (size, sha256). File >4GB dùng sampled hash (head 64KB + tail 64KB + size salt), flag `partial` + `partial_groups` — client verify trước khi xóa. Mỗi file trả kèm approvalToken → AI xóa bản thừa qua luồng delete an toàn. `files` oldest-first.
- `compare_scans`: diff 2 snapshot đã persist vào `data_dir/disk-cleaner-mcp/snapshots/<scan_id>.json` (prune giữ 50 mới nhất). Mỗi scan tự ghi snapshot sau khi xong → compare được cả scan cũ sau restart.
- Tất cả read-only, không cần token, không sửa Safety Guard.

## 3b. Data model insights (JSON, camelCase)

```jsonc
TreeNode        { name, path, size (recursive), files, directSize, directFiles, percent, children[], childrenTruncated }
ExtensionStat   { extension, count, size }
FileTypeReport  { scanId, totalFiles, totalSize, extensionCount, byExtension[], truncated }
DuplicateFile   { path, size, modified, category, categoryLabel, approvalToken }
DuplicateGroup  { hash, size, fileCount, wastedSize, files[] (oldest-first) }
DuplicateReport { scanId, groupsFound, topGroups[], totalWasted, candidateFiles, hashedFiles, unreadableFiles, truncated }
FileChange      { path, before, after, delta }
CompareReport   { scanA, scanB, rootA, rootB, totalA, totalB, netDelta, addedCount/Size, removedCount/Size, changedCount, topAdded[], topRemoved[], topChanged[], warnings[] }
```

## 4. Data model (JSON, camelCase)

```jsonc
ScanEntry      { kind: "file"|"dir", path, size, modified (epoch s), extension, category, categoryLabel, approvalToken, depth }
ScanSummary    { scanId, startedAt, durationMs, root, filesScanned, dirsScanned, totalSize, truncated, maxEntries, categoryTotals[], largestEntries[], warnings[] }
DeleteOutcome  { path, status: "trashed"|"permanent"|"rejected"|"error", message }
```

Category keys: `temp`, `log`, `cache`, `browser_cache`, `node_cache`, `python_cache`, `installer`, `download`, `backup`, `archive`, `crash_dump`, `thumbnail`, `other`.

## 5. Toolchain notes (Windows dev)

- PATH bash không có cargo → `export PATH="$HOME/.cargo/bin:$PATH"` trước mỗi cargo.
- Toolchain active: `x86_64-pc-windows-gnu` (rustup default), msvc cũng có.
- **OneDrive stall:** target dir đặt ngoài thư mục đồng bộ → `export CARGO_TARGET_DIR="$HOME/.cargo/target/dc-mcp"` (KHÔNG commit config cá nhân).
- `trash` trên Windows cần COM per-thread → mọi xóa chạy trong thread riêng (`std::thread::spawn`) để tránh apartment lỗi.

## 6. Limitation / Hướng mở rộng

- `find_duplicates` >4GB: sampled hash (head+tail 64KB + size salt), flag `partial` — yêu cầu client verify trước khi xóa.
- `compare_scans`: snapshot persist ra đĩa (giữ 50); không cần quét lại sau restart.
- Không hỗ trợ mac/Linux delete test tự động trên CI Windows (cross-check thủ công).
- `empty_trash` tool 14 (requires `confirm=true`). Custom rules (`config.json`) implemented. Still open: streaming scan >1M entry, `--token`/`--canary`.