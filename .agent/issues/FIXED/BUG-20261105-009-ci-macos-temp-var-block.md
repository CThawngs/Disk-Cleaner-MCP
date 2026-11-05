# BUG-20261105-009: macOS brain blocked via /var prefix on temp paths

- **Status:** FIXED
- **Severity:** P1 (CI macOS 4 failures)
- **Run:** 41984965342 (37 passed / 4 failed) on commit dbb5f48

## Symptoms
- `brain::assess` returned `"blocked"` for temp-dir files: `test_temp_junk_safe`
  (expected safe_to_delete), `test_executable_keep` (`left: "blocked" right: "keep"`),
  `test_config_keep`, `test_duplicate_lowers_importance` (importance not lowered
  because blocked verdict short-circuits scoring).

## Root cause
- `brain::assess` blocks solely via `safety::is_protected` (brain.rs:61).
- `is_protected` prefix-matches normalized path against `PROTECTED_UNIX` which
  includes `"/var"` (safety.rs:20).
- macOS `std::env::temp_dir()` = `/var/folders/...` → every `p()` test path
  prefix-matched `/var` → blocked.
- Previous fix (BUG-20261105-008) only exempted `/var`/`/tmp` in
  `verify_safe_target` ancestor loop, not in `is_protected`.

## Fix
- `src/safety.rs` `is_protected()` non-Windows block: exempt per-user
  `std::env::temp_dir()` subtree (normalized, lowercased, prefix match) BEFORE
  `PROTECTED_UNIX` loop. `is_extra_protected` still checked first (wins).
  `/var` system subdirs outside temp dir stay blocked.
- Rationale: cleaning caches under temp dir is the tool's purpose; Safety Guard
  protects system dirs, not user temp scratch space.

## Verification
- `cargo fmt --check`: 0
- `cargo clippy --all-targets` + `--features http`: 0 warnings
- `cargo check`: 0
- `cargo test`: 43/43 passed
- `cargo build --release`: ok
- `py smoke_test.py`: ALL PASSED (list_trash: 126 item(s))
- macOS proof requires CI green (unverifiable on Windows host).
