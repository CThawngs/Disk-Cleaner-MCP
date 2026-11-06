# BUG-20261106-010 — CI macos-latest runner capacity failure

## Triệu chứng
- Run `42252136843` (`db2016e`) trên `main` failed duy nhất job `test (macos-latest)`.
- Nội dung: `The job was not acquired by Runner of type hosted`, `Due to capacity constraints, jobs targeting macOS arm64 runners may experience longer queue times`.
- 5 job còn lại pass: `ubuntu-24.04-arm`, `ubuntu-latest`, `coverage`, `windows-latest`, `macos-15-intel`.

## Nguyên nhân gốc
- Hạ tầng GitHub Actions thiếu runner `macos-latest` (arm64), job xếp hàng 15 phút rồi lỗi acquire.
- Không liên quan thay đổi code: commit `db2016e` chỉ xóa 2 template `Formula/disk-cleaner-mcp.rb`, `manifests/CThawngs.DiskCleanerMCP.manifest`.
- Local đã pass `cargo fmt`, `cargo clippy -D warnings`, `cargo check`, `cargo test` 46/46, smoke test E2E.

## Cách sửa
- Re-run failed jobs để cấp lại runner macOS arm64 cho `42252136843`.
- Không đổi workflow trừ khi failure tái diễn.
