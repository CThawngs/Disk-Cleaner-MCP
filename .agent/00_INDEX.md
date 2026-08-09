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

- **Giai đoạn:** v0.1 — MVP MCP server (stdio) + Safety Guard + phân phối GitHub Actions.
- **Stack:** Rust (rmcp 3.1, tokio, jwalk 0.9, rayon, sysinfo, trash 5, sha2).
- **Nhịp công việc:** 10-bước Autonomous Agent (xem thủ công trong phiên Hermes).

## Hướng dẫn nhanh cho agent mới

1. `cargo check` trước, test sau cùng của từng sửa đổi.
2. Windows build cần `CARGO_TARGET_DIR` ngoài OneDrive (xem `ARCHITECTURE.md` §Toolchain).
3. Không commit `target/`. Không sửa blocklist trong `src/safety.rs` một cách vô căn cứ.