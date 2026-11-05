# Contributing to Disk Cleaner MCP

## Setup

```powershell
cargo build
cargo test
```

## Definition of Done

`cargo fmt` → `cargo clippy` → `cargo check` → `cargo test` → smoke test (`python smoke_test.py`).

## Safety Guard (immutable)

Denied permanently: `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`,
`C:\ProgramData`, `C:\System Volume Information`, `$Recycle.Bin`, `/usr`, `/bin`,
`/sbin`, `/boot`, `/etc`, `/var`, `/System`, `/Library`, `/Applications`,
`/Volumes`, `/dev`, `/proc`, `/sys` + `pagefile.sys`, `hiberfil.sys`, `swapfile.sys`.

Delete defaults to Trash. Permanent delete requires `permanent + confirm_permanent`.
Every delete item carries a per-scan SHA-256 `approval_token` — mismatch rejects.

## PRs

- Smallest diff that closes the issue. No drive-by refactors.
- New behavior needs a test. Bug fixes need a regression test.
- Decisions worth keeping go in `.agent/DECISIONS.md` as an ADR.

## Issues

Bug reports: open `.agent/issues/OPEN/BUG-<date>-<slug>.md`, fix, move to `FIXED/`.

## Language

Code/comments in English. Maintainer communication in Vietnamese.
