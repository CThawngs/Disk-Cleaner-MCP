# DATA INTAKE — disk-cleaner-mcp (tự điền)

## Thông tin Chủ dự án

- **Chủ dự án:** Zero — nguyenchithang2804@gmail.com — GitHub: **CThawngs**.
- **Vai trò:** end-user, vibe-code 100%; AI tự vận hành kỹ thuật.

## Yêu cầu sản phẩm (đã chốt)

1. MCP Server chuẩn (stdio) để Hermes/Claude/Cursor/OpenClaw quét ổ & xóa rác Windows/macOS/Linux.
2. Tầng 1 Rust: quét siêu tốc, metadata nhẹ, cấp token. Tầng 2 LLM: suy luận ngữ cảnh + đề xuất.
3. Safety: chặn tuyệt đối hệ thống; `trash` mặc định; xóa phải có `approval_token`.
4. Phân phối: GitHub public + GitHub Actions cross-compile + install.ps1/install.sh.
5. (v0.2) Phân tích sâu kiểu TreeSize cho AI: cây thư mục, loại file, duplicate, so sánh 2 lần quét — native Rust, không phụ thuộc app bên thứ ba (xem ADR-010).

## Quyết định mặc định (Chủ đồng ý ngầm — có thể đổi bất cứ lúc nào)

- Ngôn ngữ giao diện tool: tiếng Anh (vì MCP schema fake JSON-RPC); nhãn category song ngữ VL/EN.
- `scan` bỏ trống `root` → mặc định quét thư mục **Downloads** của user (hành vi đã cài trong `server.rs`).
- Không tự ý xóa gì khi chưa có lệnh; AI đề xuất, chủ duyệt.

## Môi trường (đã scan, cập nhật 2026-09-10)

- OS: Windows 10/11, Rust 1.95 stable; rustup default = `msvc` nhưng máy thiếu `link.exe` → build bằng `cargo +stable-x86_64-pc-windows-gnu` + w64devkit trong PATH.
- Cargo ở `~/.cargo/bin`; smoke test dùng `py` launcher (python không có trong PATH) + `PYTHONIOENCODING=utf-8`.
- OneDrive: thư mục dự án đang được đồng bộ → `CARGO_TARGET_DIR` ngoài OneDrive (`~/.cargo/target/dc-mcp`).

## Gaps — ĐÃ ĐÓNG TẤT CẢ (2026-09-10)

- **GAP-1 (đóng):** GitHub username = `CThawngs` — đã dùng trong `Cargo.toml`, `install.ps1`, `install.sh`, README.
- **GAP-2 (đóng):** `scan` không có `root` → quét Downloads (đơn giản, dự đoán được; ghép nhiều thư mục chuẩn để v0.3 nếu cần).
