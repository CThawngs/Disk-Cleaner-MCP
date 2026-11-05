# BUG-20261105-001: CI mask test failures; supply-chain gaps; delete/organize race (TOCTOU) + symlink bypass

- severity: critical
- reproduced: yes (đọc code: `cargo test || true` + `grep` trong ci.yml; `verify_safe_target` chưa tồn tại — delete/organize chỉ check `is_protected` + token rồi thao tác trực tiếp trên path thô)
- root_cause:
  1. `ci.yml` chạy `cargo test ... || true` rồi `grep FAILED` + `tail -5` — exit code luôn 0, fail bị nuốt.
  2. GitHub Actions pin bằng tag mutable (`@v5`, `@stable`, `@v2`) — tag có thể bị move, supply-chain risk.
  3. Release assets không có checksum; install.sh/install.ps1 tải binary không verify → MITM / asset thay thế có thể giả mạo.
  4. Salt cho approval token sinh từ time + stack addr — đoán được, token forge được.
  5. `is_protected()` dùng canonicalize (fail khi path không tồn tại) + không chặn symlink/ancestor-symlink; delete/organize không verify path tại thời điểm thao tác → symlink trỏ vào protected dir hoặc đổi path giữa scan và delete (TOCTOU).
  6. Skip-dir chỉ `continue` entry dir, không chặn children (jwalk walker vẫn duyệt `.git/`, `node_modules/`...).
  7. `Arc<Mutex<ScanEngine>>` giữ lock qua toàn bộ handler; `scan()` đồng bộ chặn async executor.
- fix:
  1. `ci.yml`: `cargo test` thẳng, bỏ mask/grep/tail.
  2. Pin mọi action về commit SHA (checkout, rust-toolchain, rust-cache, upload/download-artifact, action-gh-release) + comment tag gốc.
  3. `release.yml` job publish: `sha256sum disk-cleaner-mcp-* > checksums.txt` upload kèm assets; install.sh/install.ps1 tải checksums.txt và verify (fail-closed nếu tool thiếu hoặc mismatch).
  4. `generate_salt()`: `getrandom::fill()` CSPRNG (32 bytes) qua OS.
  5. `safety.rs` mới: `lexical_clean()` (collapse `.`/`..` khi canonicalize fail), `strip_ads()` (NTFS ADS `file:stream`), `verify_safe_target()` — symlink_metadata chặn symlink thật, canonical phải khớp lexical absolute (chặn symlink ancestor), reject protected canonical; delete/organize gọi guard ngay trước thao tác và dùng canonical path.
  6. Scan loop: drop entry bất kỳ có ancestor component khớp `should_skip_dir()`.
  7. Sessions: `RwLock<HashMap>` + `RwLock<VecDeque>` FIFO (max 3); `scan()` đổi sang `&self`; server bỏ Mutex, `scan/delete/organize` chạy trong `tokio::task::spawn_blocking`, handler khác chỉ clone `Arc<ScanSession>` dưới read lock ngắn.
- regression_test: `safety::tests::test_verify_safe_target_symlink_rejected` (tạo symlink → guard phải reject; file thật → ok; tự skip trên Windows thiếu SeCreateSymbolicLinkPrivilege), `test_lexical_clean`, `test_ads_stripped`; `cargo test` 32/32 pass; clippy `-D warnings` sạch.
- status: FIXED (2026-11-05)

## Ghi chú / giới hạn

- Minisign/cosign chưa làm (cần secret key chưa có) — checksum SHA256 là baseline.
- Chưa pin SHA cho `rust-toolchain` beyond `stable` branch hiện tại.
- Smoke test E2E installer chưa có (v0.3).
