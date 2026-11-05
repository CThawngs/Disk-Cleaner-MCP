# BUG-20261105-002 — P1 correctness + P2 head-hash + P3 CI/release + P4 docs

Ngay: 2026-11-05 · Trang thai: FIXED (local, chua commit/push)

## Trieu chung
- `generate_id` time-based (2 scan cung mili giay co the trung id → session bi ghi de).
- Lock poison = panic (`expect`) → server chet thay vi recover.
- Permanent delete: `remove_file` fail moi thu `remove_dir_all` → sai nguyen nhan, 2 syscall, khong gate `is_dir`.
- `age_days` am khi `modified` o tuong lai → wrap u32 thanh so khong lo.
- `Pattern::new` + `to_lowercase` trong vong loc → alloc/lan; `should_skip_dir` alloc O(depth).
- `find_duplicates` full-hash moi file cung size → ton I/O file lon khong phai duplicate.
- CI: khong --locked, khong smoke, checksums thieu installer; install.sh ghi checksums.txt ra cwd, grep pattern sai; install.ps1 ghi JSON vao config.toml (Codex) + ghi de $env:TEMP\checksums.txt; smoke mac dinh binary .exe tren moi OS, chi assert 2/11 tools.
- Docs: ARCHITECTURE ghi `dirs.rs` (thuc te `sysinfo_helper.rs`), DoD sai duong dan `scripts/smoke_test.py`.

## Fix
- P1: `generate_id` CSPRNG 64-bit (getrandom); lock `.expect` → `.unwrap_or_else(into_inner)`; permanent-delete gate `is_dir()`; `age_days` `.max(0)`; hoist `Pattern` truoc filter; `should_skip_dir` = `eq_ignore_ascii_case`.
- P2: 2-stage dedup — `hash_file_head` (64KB + len) → chi full SHA-256 khi trung head; giu semantics group (size, full-hash), cap 4GB.
- P3: CI `--locked` + build release + smoke E2E (bash, BIN theo OS); release.yml `--locked`, checksum ca install.sh+install.ps1; install.sh checksum ra mktemp + cleanup; install.ps1 checksum per-PID + xoa sau verify, Codex TOML append `[mcp_servers...]`; smoke BIN default theo platform + assert du 11 tools.
- P4: ARCHITECTURE `sysinfo_helper.rs` + mo ta head-hash; DoD duong dan smoke; ADR-013/014.

## Chua lam (v0.3, can yat cua chu)
Persist snapshot dia, chunked scan >1M, `empty_trash`, custom rules, `--token/--canary`, partial hash >4GB ngoai head 64KB.

## Kiem chung
`cargo fmt --check` / `cargo clippy --locked --all-targets -- -D warnings` / `cargo test --locked` / `cargo build --release` + `python smoke_test.py` — chay lai sau khi sua (xem report phien).
