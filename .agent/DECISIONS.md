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