# BUG-20261105-004 — Brain per-file judgment + safe-delete gates

Status: FIXED
Date: 2026-11-05

## Problem
Delete path trusted token only — no per-file importance reasoning.
"Không xóa Ngu" requirement unmet: every file needed a 뇌 judge
(size ascending) before deletion.

## Fix
- New `src/brain.rs`: `assess()` pure judge → verdict
  (`safe_to_delete`/`review`/`keep`/`blocked`), risk
  (`safe`/`caution`/`dangerous`/`blocked`), importance 0–100,
  human-readable `reasons`. Junk categories + duplicate copy lower
  importance; executable/config/dotfile/recent/>=1GB raise it;
  protected paths always `blocked`.
- `ScanEntry` gained brain fields; scan sorts entries smallest→largest,
  fills `ScanSummary` safe/review/keep/blocked counts + `reclaimable_bytes`.
- `DeleteRequest` gained `confirm_risk` + `dry_run`; `DeleteResult`
  gained `dry_run`/`would_reclaim_bytes`.
- Delete gate: `blocked` always rejected; `review`/`keep` require
  `confirm_risk=true`; `dry_run` reports without touching disk.
- JSONL audit log appends every delete decision
  (`data_dir/disk-cleaner-mcp/audit.log`).
- MCP `delete` tool exposes `confirmRisk`/`dryRun`, description updated.
- Fresh logs classify `review` (recent-use caution), so old smoke
  delete needed `confirmRisk` — updated smoke + regression test
  `test_delete_review_requires_confirm_risk_and_dry_run_safe`.

## Verify
`cargo fmt --check` 0; `cargo clippy --locked --all-targets -D warnings` 0;
`cargo test --locked` 39/39; `cargo build --locked --release` OK;
`py smoke_test.py` ALL PASSED (11 tools, brain gate live).
