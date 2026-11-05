# 00 — INDEX DỰ ÁN `disk-cleaner-mcp`

> MCP Server bằng Rust: quét, phân tích, tổ chức và xóa rác ổ cứng an toàn cho AI Agents.

## Bản đồ tài liệu

| File | Nội dung | Khi nào đọc |
|---|---|---|
| `AGENTS.md` (root) | Quy tắc bắt buộc mọi agent | Mọi phiên |
| `ARCHITECTURE.md` | Kiến trúc 2 tầng, luồng token, data model | Trước khi sửa code |
| `DECISIONS.md` | Mọi ADR/quyết định kiến trúc | Khi thay đổi hành vi |
| `DATA_INTAKE_TEMPLATE.md` | Yêu cầu sản phẩm + giả định đã tự điền | Khi thêm tính năng |
| `DEFINITION_OF_DONE.md` | Checklist nghiệm thu | Trước khi báo "xong" |
| `issues/OPEN/` | Bug đang mở | Mỗi khi gặp lỗi |
| `issues/FIXED/` | Bug đã fix | — |
| `reports/` | Báo cáo phiên (markdown) | Khi cần bối cảnh cũ |

## Trạng thái dự án

- **Giai đoạn:** v0.3.0 — Chưa tag (đang dev trên `main`): brain per-file judgment + safe-delete gates (`confirm_risk`, `dry_run`, audit JSONL) + 12 tools (thêm `empty_trash`) + partial-hash >4GB + snapshot prune 50 + audit ISO. Đã release v0.2.1 (tag `v0.2.1`, commit `23f0acd`): P0–P4 hardening + multiplatform.
- **Stack:** Rust (rmcp 3.1, tokio, jwalk 0.9, rayon, sysinfo, trash 5, sha2).
- **Nhịp công việc:** 10-bước Autonomous Agent (xem thủ công trong phiên Hermes).
- **Trạng thái phiên 2026-09-11:** ✅ merge vào `main` (`fd5f334`, CI 3 OS success) + tag `v0.2.0` (Release workflow publish binaries) + docs đồng bộ + đóng GAP-1/2.
- **Trạng thái phiên 2026-09-10:** ✅ insights port (ADR-010..012) — `cargo fmt` ✓, `cargo clippy -D warnings` ✓, `cargo test` 29/29 ✓, `cargo build --release` ✓, smoke test E2E 4 tool mới ✓.
- **Trạng thái phiên 2026-08-09:** ✅ `cargo fmt` ✓, `cargo clippy -D warnings` ✓, `cargo test` 19/19 ✓, `cargo build --release` ✓, smoke test E2E ✓, commit `23ee603` ✓.
- **Toolchain Windows:** default rustup = `msvc` nhưng máy thiếu `link.exe` → build bằng `cargo +stable-x86_64-pc-windows-gnu` + `w64devkit` (`C:\tools\w64devkit\bin` trong PATH) + `CARGO_TARGET_DIR` ngoài OneDrive.
- **Ghi chú API:** param structs dùng `#[serde(rename_all = "camelCase")]`; `scan()` trả `summary.scanId` (không phải top-level).

## Hướng dẫn nhanh cho agent mới

1. `cargo check` trước, test sau cùng của từng sửa đổi.
2. Windows build cần `CARGO_TARGET_DIR` ngoài OneDrive (xem `ARCHITECTURE.md` §Toolchain).
3. Không commit `target/`. Không sửa blocklist trong `src/safety.rs` một cách vô căn cứ.