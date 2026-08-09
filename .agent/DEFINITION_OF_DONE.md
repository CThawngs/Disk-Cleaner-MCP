# DEFINITION OF DONE — checklist nghiệm thu

Mọi phiên báo "xong" PHẢI vượt qua, theo thứ tự:

## Build & static
- [ ] `cargo fmt` không thay đổi gì (đã format)
- [ ] `cargo clippy --all-targets -- -D warnings` — 0 warning
- [ ] `cargo check` — 0 error
- [ ] `cargo build --release` — ra binary

## Test
- [ ] `cargo test` — toàn bộ đơn vị test pass
- [ ] Smoke test E2E qua MCP stdio (`python scripts/smoke_test.py`): initialize → tools/list → get_system_status → scan fixture → analyze → delete (trash + permanent) → protected-path rejection → token mismatch rejection

## An toàn
- [ ] SecurityGuard unit test pass: chặn `C:\Windows\System32`, `/usr/bin`, `pagefile.sys`…
- [ ] Phân quyền: token sai path (khác salt) bị từ chối
- [ ] Protected path bị từ chối kể cả khi token hợp lệ hình thức

## Phân phối
- [ ] `.github/workflows/ci.yml` + `release.yml` sẵn sàng (build 3 OS + upload artifact)
- [ ] `install.ps1` + `install.sh` tồn tại, lệnh 1 dòng doc đầy đủ

## Tài liệu
- [ ] `README.md` đầy đủ: quickstart, cấu hình MCP từng client, test guide
- [ ] `.agent/00_INDEX.md` cập nhật trạng thái