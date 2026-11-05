# BUG-20261105-005 — Forgotten v0.3 batch: empty_trash, partial-hash >4GB, snapshot prune, audit ISO, docs

Ngày: 2026-11-05 · Trạng thái: FIXED (local)

## Triệu chứng
User rà session, phát hiện task quên làm (từ backlog "Chua lam (v0.3)" trong BUG-20261105-002 + report-2026-09-10):
- Không có `empty_trash` tool (chỉ có trash, không purge).
- File >4GB bị skip hoàn toàn trong `find_duplicates`.
- Snapshot dir trên đĩa tăng vô hạn (không prune).
- Audit log chỉ có epoch `ts`, không có ISO-8601.
- Docs chưa sync: `00_INDEX.md` vẫn ghi v0.2.0; DECISIONS thiếu ADR brain/partial/empty_trash.
- Commit `bc4c0fc` (brain) chưa push.

## Fix
- `model.rs`: `DuplicateGroup.partial` + `DuplicateReport.partial_groups` (default false); `EmptyTrashParams { confirm }` / `EmptyTrashResult { purged_items, purged_bytes, message }`.
- `insights.rs`: `hash_file_head` bỏ cap MAX (chỉ đọc 64KB); `hash_file_sampled` head 64KB + tail 64KB + size + `"partial"` salt; stage-2 dispatch theo size; group flag `partial`; 1 test sampled deterministic + khác full hash.
- `engine.rs`: `empty_trash()` + `empty_trash_impl()` (Win/Linux `trash::os_limited`, macOS walk `~/.Trash`); confirm gate; `prune_snapshots` giữ 50 mới nhất; `audit` thêm `iso` (civil_from_days bỏ cfg linux-only); 1 test empty_trash reject không confirm.
- `server.rs`: tool `empty_trash` (12 tools) qua `spawn_blocking`; `find_duplicates` description ghi partial.
- `smoke_test.py`: assert 12 tools + step empty_trash không confirm → reject.
- Docs: `00_INDEX.md` → v0.3.0 dev; `DECISIONS.md` ADR-015/016/017.

## Verify
- `cargo fmt` ✓ · `cargo clippy --locked --all-targets -D warnings` ✓ · `cargo test --locked` 41/41 ✓ · `cargo build --locked --release` ✓ · `py smoke_test.py` ALL PASSED (12 tools).

## Skipped / pending owner
- Chunked/streaming scan >1M entries, custom rules, HTTP mode/token, Python packaging (.deb/.rpm, crates.io), cargo-deny/Dependabot/SBOM, Developer ID notarization, `/var/cache` allowlist (xung đột Safety Guard bất biến), tag v0.3.0 — chờ owner quyết.
