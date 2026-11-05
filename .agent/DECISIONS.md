# ADR — Quyết định kiến trúc

Định dạng: ngắn gọn, mỗi dòng một quyết định có lý do. ADR mới thêm cuối file, ghi ngày.

| # | Ngày | Quyết định | Lý do |
|---|---|---|---|
| 001 | 2026-08-09 | Dùng `rmcp` (Rust SDK chính thức, stdio) thay vì tự viết JSON-RPC | Tuân spec MCP, hỗ trợ health `tools/list`, nâng cấp sau này. |
| 002 | 2026-08-09 | `jwalk` + `rayon` cho metadata, không dùng walkdir tuần tự | File system I/O nhanh hơn hàng chục lần ở C:\ (nhiều triệu entry). |
| 003 | 2026-08-09 | Xóa mặc định luôn `trash` crate (Thùng rác HĐH) | An toàn; file có thể khôi phục. `rm` vĩnh viễn = flag cờ đỏ kép. |
| 004 | 2026-08-09 | `approval_token = hex(sha256(salt‖path))`, salt 32B mỗi scan | Token gắn khóa 1 đường dẫn của 1 scan: không phải thay 1 file hợp nhất → ngăn replay/giả mạo. |
| 005 | 2026-08-09 | Cache scan trong RAM (LRU 3 scan), KHÔNG đổ hết entries ra client | Client MCP result nhỏ; AI dùng `analyze` phân trang; tránh payload 100MB+. |
| 006 | 2026-08-09 | Scan: cấm prune trong `.git`, Recycle Bin. Vẫn cho phép quét mọi root (read-only), cấm xóa protected root | Nhẹ nhàng giữ nguyên dữ kiện cho AI, bảo vệ chắc ở pha delete. |
| 007 | 2026-08-09 | Linux/macOS × Windows: danh sách protected path 2 bảng (json) trong `safety.rs`, test liệt kê | Nền tảng chéo; chống path thất bại vì phân biệt hoa thường. |
| 008 | 2026-08-09 | Xóa: spawn thread riêng cho `trash::delete` | Tránh lỗi COM apartment trên Windows worker threads. |
| 009 | 2026-08-09 | Phân phối: GitHub Actions cross-build + `install.ps1`/`install.sh` tải release, không dùng `cargo-binstall` | Free 100%, đóng gói nhẹ, tự cấu hình MCP cho các client. |
| 010 | 2026-09-10 | Port tính năng phân tích TreeSize thành tools NATIVE trong `insights.rs` (get_tree, file_types, find_duplicates, compare_scans), KHÔNG shell-out sang app TreeSize | TreeSize closed-source, trả phí, Windows-only → phá ethos free/cross-platform/single binary. Native = AI được dữ liệu cùng độ sâu, license sạch. |
| 011 | 2026-09-10 | `find_duplicates` reuse approvalToken có sẵn + prefilter size trước khi hash | Nhóm duplicate dùng đúng token của scan → xóa bản thừa đi qua Safety Guard chuẩn, không đường tắt. Hash chỉ file cùng size → I/O bounded. |
| 012 | 2026-09-10 | `compare_scans` chỉ so 2 session còn sống trong RAM, không persist snapshot ra đĩa | Tái dùng cache LRU-3 có sẵn; tránh ghi đĩa ngoài ý muốn mỗi lần quét. Lịch sử lâu dài = v0.3 (SpaceObServer-style DB). |
| 013 | 2026-11-05 | P0 hardening: CI masking bỏ, action pin SHA, checksum SHA256 fail-closed, CSPRNG salt (`getrandom`), RwLock+`spawn_blocking`, TOCTOU `verify_safe_target`, skip-dir prune, `light_normalize` | Xem BUG-20261105-001. |
| 014 | 2026-11-05 | P1–P4: `generate_id` CSPRNG 64-bit, lock poison `into_inner` (không panic), permanent-delete gate `is_dir()`, `age_days` clamp ≥0, hoist `Pattern`, alloc-free `should_skip_dir`, head-hash 64KB stage cho `find_duplicates`, CI `--locked`+smoke, checksums gồm installer, Codex TOML fix, smoke assert đủ 11 tools | P1 correctness, P2 perf, P3 CI/release, P4 docs — đúng diff tối thiểu, xem BUG-20261105-002. |
| 015 | 2026-11-05 | Brain `src/brain.rs`: pure `assess()`/entry → verdict safe_to_delete/review/keep/blocked + importance 0–100 + reasons; delete gate: blocked luôn reject, review/keep cần `confirm_risk=true`, `dry_run` mandatory-report; audit JSONL | "Không xóa Ngu": mỗi file nhỏ→lớn được phán xét trước khi xóa, xem BUG-20261105-004. |
| 016 | 2026-11-05 | Partial-hash: file >4GB dùng sampled hash (head 64KB + tail 64KB + size salt), flag `partial` + `partial_groups`; head-stage bỏ cap MAX (chỉ đọc 64KB) | File >4GB trước đây bị skip hoàn toàn; sampled hash bounded I/O, client verify trước khi xóa. |
| 017 | 2026-11-05 | Tool `empty_trash` (12 tools): Win/Linux `trash::os_limited::list/purge_all`, macOS walk `~/.Trash`; bắt buộc `confirm=true`; snapshot prune giữ 50 mới nhất; audit thêm `iso` ISO-8601 UTC | `trash` crate không có sẵn `empty_trash`; snapshot dir tăng vô hạn; audit chỉ có epoch. |