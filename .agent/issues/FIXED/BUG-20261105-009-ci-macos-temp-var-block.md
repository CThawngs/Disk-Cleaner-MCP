# BUG-20261105-009 — macOS CI: brain tests blocked bởi /var (temp_dir)

- **Phát hiện:** CI run 41986339820 trên commit 243056f — macOS 37 passed / 4 failed (cùng 4 test brain như run 41984965342 trên dbb5f48).
- **Triệu chứng:** `test_temp_junk_safe` (left "blocked" right "safe_to_delete"), `test_executable_keep`/`test_config_keep` (left "blocked" right "keep"), `test_duplicate_lowers_importance` (importance không hạ vì cả 2 đều blocked).
- **Nguyên nhân:** `brain::assess` chỉ trả "blocked" qua `is_protected` (brain.rs:61). Path test `p()` nằm trong `std::env::temp_dir()` — macOS: `/var/folders/.../dcm-brain-test/...` — prefix-match `PROTECTED_UNIX` `"/var"` (safety.rs:20) → blocked. Fix v1 (7bb31c7) exempt temp trong `is_protected` nhưng dùng `normalize(temp_dir())` (canonicalize `/var` → `/private/var`) so với path test không tồn tại (lexical-clean `/var/...`) → prefix mismatch, exemption không fire trên CI.
- **Fix v2:** `is_protected()` so cả 2 dạng: lexical `temp_dir()` + `normalize(temp_dir())`. Chỉ exempt subtree temp của user; system subdirs dưới `/var` vẫn bị chặn. `is_extra_protected` vẫn chạy trước.
- **Kiểm chứng local:** cargo fmt --check 0, cargo clippy --all-targets 0, --features http 0, cargo test 43/43, smoke ALL PASSED (128 items).
- **Commit:** (pending push) — chờ CI 3 OS xanh.
