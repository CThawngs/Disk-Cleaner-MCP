# DATA INTAKE — disk-cleaner-mcp (tự điền)

## Thông tin Chủ dự án

- **Chủ dự án:** (chưa khai — cần GitHub username để đánh được install script, xem GAP-1)
- **Vai trò:** end-user, vibe-code 100%; AI tự vận hành kỹ thuật.

## Yêu cầu sản phẩm (đã chốt)

1. MCP Server chuẩn (stdio) để Hermes/Claude/Cursor/OpenClaw quét ổ & xóa rác Windows/macOS/Linux.
2. Tầng 1 Rust: quét siêu tốc, metadata nhẹ, cấp token. Tầng 2 LLM: suy luận ngữ cảnh + đề xuất.
3. Safety: chặn tuyệt đối hệ thống; `trash` mặc định; xóa phải có `approval_token`.
4. Phân phối: GitHub public + GitHub Actions cross-compile + install.ps1/install.sh.

## Quyết định mặc định (Chủ đồng ý ngầm — có thể đổi bất cứ lúc nào)

- Ngôn ngữ giao diện tool: tiếng Anh (vì MCP schema fake JSON-RPC); nhãn category song ngữ VL/EN.
- Dutch: quét root mặc định = `temp` + `cache` + `downloads` được ghép khi AI gọi scan với root chỉ định.
- Không tự ý xóa gì khi chưa có lệnh; AI đề xuất, chủ duyệt.

## Môi trường (đã scan)

- OS: Windows 10/11 (git-bash MSYS), Rust 1.95 stable (gnu active, msvc có).
- Cargo ở `~/.cargo/bin` (không trong PATH bash).
- OneDrive: thư mục dự án đang được đồng bộ → `CARGO_TARGET_DIR` ngoài OneDrive.

## Gaps (cần Chủ trả lời 1 lần)

- **GAP-1:** GitHub username/org để tạo release URL trong `install.ps1`/`install.sh` + README (mặc định đang là placeholder).
- **GAP-2:** Có muốn tool `scan` mặc định quét tự động danh sách thư mục rác chuẩn (temp/cache/download) khi bỏ trống `root` không? (mặc định: có)