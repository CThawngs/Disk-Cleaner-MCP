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
| `dirs.rs` | System status, standard dirs per OS |
| `model.rs` | Các struct serde (ScanEntry, ScanSummary…) |

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

- Không hỗ trợ mac/Linux delete test tự động trên CI Windows (cross-check thủ công).
- `empty_trash`, `custom rules`, chunked streaming scan (quá 1M entry) — để v0.2.
- Cửa mở: `--token`, `--canary`?