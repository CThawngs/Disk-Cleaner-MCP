# BUG-20261105-003 — Multiplatform optimizations (Windows / macOS / Linux)

Status: FIXED (2026-11-05)

## Round scope
Cross-platform hardening + features, minimal diffs, no new deps.

## Changes
1. `safety::light_normalize` + `normalize`: lowercase on macOS too (APFS
   case-insensitive) — fixes false "symlinked ancestor" rejections.
2. `safety::is_protected`: Windows roots resolved against real system drive
   (`%SystemRoot%`, `%ProgramData%`) instead of hardcoded `C:\` — covers
   Windows installed on D:.
3. `engine::trash_fallback`: headless XDG Trash (Linux, writes `.trashinfo`)
   and `~/.Trash` (macOS) when `trash` crate fails (no D-Bus/Gio, no Finder).
   Windows keeps COM path only.
4. Snapshot persistence: `ScanSession` serialized to
   `data_dir/disk-cleaner-mcp/snapshots/<scan_id>.json`; `get_session`
   reloads after process restart. Scan-id charset allowlisted (no traversal).
5. `DiskInfo.trash_bytes`: recycle-bin size per volume (best-effort).
6. macOS release: ad-hoc `codesign` in CI + Gatekeeper note in README.

## Skipped
- Streaming scan >1M entries (FIFO-3 + 200k cap sufficient for home dirs).
- Developer ID notarization (needs paid Apple cert — owner decision).
- `/var/cache` allowlist (Safety Guard immutable — owner decision).

## Verified
- `cargo fmt --check` 0, `clippy --locked --all-targets -D warnings` 0
- `cargo test --locked` 32/32 pass, release build OK, smoke ALL PASSED
- Linux/macOS paths cfg-gated; not runnable on this Windows host —
  real CI (v0.2.1 tag, 3-OS matrix) is the cross-platform proof.
