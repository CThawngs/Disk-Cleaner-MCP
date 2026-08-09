# QUY TẮC BẮT BUỘC CHO MỌI AGENT (Hermes, Claude, Cursor, OpenClaw, Codex)

1. Tự động đọc `.agent/00_INDEX.md` trước khi làm bất kỳ việc gì.
2. Tự đối chiếu `.agent/ARCHITECTURE.md` với mã thực tế trước khi sửa code.
3. **Safety Guard (bất biến, không được tắt):**
   - Chặn tuyệt đối xóa: `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`, `C:\System Volume Information`, `$Recycle.Bin`, `/usr`, `/bin`, `/sbin`, `/boot`, `/etc`, `/var`, `/System`, `/Library`, `/Applications`, `/Volumes`, `/dev`, `/proc`, `/sys` + `pagefile.sys`, `hiberfil.sys`, `swapfile.sys`.
   - Mặc định xóa = chuyển Thùng rác (`trash` crate). Xóa vĩnh viễn bắt buộc có `permanent + confirm_permanent`.
   - Mọi lệnh xóa phải kèm `approval_token` (SHA-256 do engine cấp riêng cho từng scan) — token lệch → từ chối.
3. Kiểm tra `.agent/DEFINITION_OF_DONE.md` trước khi báo "xong": `cargo fmt` → `cargo clippy` → `cargo check` → `cargo test` → smoke test.
4. Bug/lỗi → tự tạo `.agent/issues/OPEN/BUG-*.md` → tự fix → chuyển `.agent/issues/FIXED/`.
5. Docs kiến trúc nằm trong `.agent/*`, KHÔNG phình file này (giữ < 5.000 ký tự).
6. Cộng đồng viết code bằng tiếng Anh; giao tiếp với Chủ dự án bằng tiếng Việt (có dấu đầy đủ).