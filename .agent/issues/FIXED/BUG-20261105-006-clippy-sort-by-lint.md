# BUG-20261105-006 clippy sort_by lint blocks DoD gate

Status: FIXED
Date: 2026-11-05

## Symptom
`cargo clippy --all-targets -- -D warnings` failed (exit 101):
`src/engine.rs:659:9: error: consider using sort_by_key`

## Cause
`list_trash` used `entries.sort_by(|a, b| b.time_deleted.cmp(&a.time_deleted))`.

## Fix
`entries.sort_by_key(|b| std::cmp::Reverse(b.time_deleted));`

## Verify
- `cargo fmt` ok
- `cargo clippy --all-targets -- -D warnings` Finished (default + `--features http`)
- `cargo test` 43 passed
- release build Finished, smoke test ALL PASSED (13 tools incl. `list_trash`)
