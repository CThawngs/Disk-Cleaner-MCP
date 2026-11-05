# BUG-20261105-008 CI macOS symlinked-ancestor false-positive (/var -> /private/var)

Status: FIXED
Date: 2026-11-05

## Symptom
CI run 41982965390 (commit `2313df3`, macOS): 29 passed / 12 failed. Failed tests: `brain::test_duplicate_lowers_importance`, `brain::test_config_keep`, `brain::test_executable_keep`, `brain::test_temp_junk_safe`, `engine::test_delete_permanent_with_confirmation`, `engine::test_delete_review_requires_confirm_risk_and_dry_run_safe`, `engine::test_organize_moves_by_category`, `test_organize_dry_run_moves_nothing`, `test_scan_and_delete_protected_rejected`, `test_organize_wrong_token_rejected`, `test_organize_skips_existing_dest`, `safety::test_verify_safe_target_symlink_rejected`.
Signatures: brain verdict `left: "blocked" right: "keep"/"safe_to_delete"`; organize `Destination rejected: Target has a symlinked ancestor — refused.`; `assertion failed: verify_safe_target(&real).is_ok()` at `src/safety.rs:381`.

## Cause
`std::env::temp_dir()` on macOS resolves under `/var/folders/...`; `/var` is a system symlink to `/private/var` (also `/tmp -> /private/tmp`). `verify_safe_target` flagged any symlinked ancestor, so every temp-dir target was refused as `blocked`. Linux `/tmp` and Windows temp are not symlinked, so those CI jobs passed. Previous fix BUG-20261105-007 changed ancestor checks to `symlink_metadata` per ancestor (fixing Windows 8.3 short-name false-positives) but still tripped on real system symlinks under macOS temp dir.

## Fix
- `src/safety.rs` `verify_safe_target`: skip macOS system ancestors `/var` and `/tmp` in the symlinked-ancestor loop (`#[cfg(target_os = "macos")]`). Still rejects user-created symlinked ancestors. Comment explains macOS system symlink rationale alongside Windows 8.3 rationale.

## Verify (local Windows)
- `cargo fmt --check` exit 0
- `cargo clippy --all-targets` + `--features http` exit 0
- `cargo check` exit 0
- `cargo test` 43 passed / 0 failed (incl. `safety::tests::test_verify_safe_target_symlink_rejected ... ok`)
- `cargo build --release` exit 0
- `py smoke_test.py` ALL SMOKE TESTS PASSED (13 tools, `list_trash: 125 item(s)`)
- macOS runtime unverifiable on Windows host; proof requires CI run on `macos-latest`.
