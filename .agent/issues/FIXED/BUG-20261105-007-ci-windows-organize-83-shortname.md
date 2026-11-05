# BUG-20261105-007 CI Windows organize false-positive (8.3 short names)

Status: FIXED
Date: 2026-11-05

## Symptom
CI run 41979158977 (windows): `test_organize_*` failed `left: 0, right: 1` — dest refused.
Local Windows dev machine: 5/5 pass. CI-runner-specific.

## Cause
`verify_safe_target` (`src/safety.rs`) string-compared `light_normalize(canonical)` vs `light_normalize(lexical)`. Windows CI temp dirs use 8.3 short names (`RUNNER~1` vs `runneradmin`) + `\\?\` prefix divergence → false "symlinked ancestor" refusal. Also latent: ubuntu brain tests hardcoded `C:/Users/x/...` (join with `current_dir()` under `/home/runner/...` → `blocked` verdict), `test_protected_unix_usr` failed on `/home` in `PROTECTED_UNIX`, macOS `safety.rs` fallback cfgs `not(windows)` type-mismatched, `sysinfo_helper.rs` unused `mount`.

## Fix
- `verify_safe_target`: check each ancestor with `symlink_metadata(...).file_type().is_symlink()` directly; no canonical-vs-lexical string compare. `light_normalize` kept `#[allow(dead_code)]` with explanatory comment.
- `PROTECTED_UNIX`: remove `/home` (match Safety Guard spec — protected list in AGENTS.md has no `/home`).
- macOS cfgs: `not(any(windows, target_os = "macos"))` both `normalize()` + `light_normalize()`.
- `sysinfo_helper.rs:119`: `let _ = mount;` (macOS branch).
- `brain.rs` tests: `p(name)` = `std::env::temp_dir()/dcm-brain-test/<name>`.

## Verify
- `cargo fmt --check` clean
- `cargo clippy --all-targets` clean (default + `--features http`)
- `cargo check` clean
- `cargo test` 43 passed / 0 failed; `test_organize` 5/5
- `cargo build --release` Finished
- `py smoke_test.py` ALL SMOKE TESTS PASSED (13 tools, `list_trash: 123 item(s)`)
- CI successor pending (commit + push this fix)
