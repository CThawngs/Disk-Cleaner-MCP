# Disk-Cleaner-MCP v0.7.0 ("SSD Savior" + Multi-Agent Installer Parity) — Engineering Spec

## 0. Global Invariants & Build Rules (MANDATORY FOR ALL WAVES)
- **Toolchain & Shared Target Dir (Disk Space Guard — DO NOT VIOLATE):**
  - `$env:PATH = "C:\tools\w64devkit\bin;$env:USERPROFILE\.cargo\bin;$env:PATH"`
  - `$env:CARGO_TARGET_DIR = "C:\Users\nguye\.cargo\target\dc-mcp"`
  - Always invoke `cargo +stable-x86_64-pc-windows-gnu ...` with `--locked` (do NOT modify `Cargo.toml` or `Cargo.lock`!).
- **Strict Code Quality Gates:**
  - Every `src/*.rs` file MUST be **`<= 500` lines** (`wc -l`).
  - Zero production `.unwrap()` / `.expect()` (only allowed inside `#[cfg(test)]`).
  - Zero clippy warnings: `cargo +stable-x86_64-pc-windows-gnu clippy --locked --all-targets -- -D warnings`.
  - Cross-OS compile safety: gate any Windows FFI behind `#[cfg(windows)]` with a clear `// SAFETY:` comment, and gate Unix `MetadataExt` behind `#[cfg(unix)]`, with clean fallbacks for other OSes so Linux/macOS CI passes 100%.
  - Cloud placeholder & reparse safety: ALWAYS check `crate::insights::is_cloud_placeholder(&meta)` BEFORE opening/hashing any file, and never follow directory symlinks/junctions (`file_type.is_symlink()`).
  - Never-touch safety: check `crate::safety::check_path(&path)` — skip/protect any `SafetyLevel::NeverTouch` or `SafetyLevel::SystemProtected` path.
- **`sysinfo 0.40.4` API Note:**
  - `sysinfo::System::new()` returns `Result<System, sysinfo::Error>` (use `let Ok(mut sys) = System::new() else { ... };`).
  - `sysinfo::Disks::new_with_refreshed_list()` returns `Result<Disks, sysinfo::Error>` (use `.ok()` + `.iter()`).
- **Zero-Conflict Git Rule for Module Owners (Tracks A, B, C):**
  - While testing locally in your assigned worktree, you may temporarily add `mod <your_module>;` to `src/main.rs` so `cargo test --locked` and `cargo clippy --locked --all-targets -- -D warnings` compile and run your unit tests.
  - **BEFORE `git commit`**, run `git checkout -- src/main.rs` and commit **ONLY** your single new module file (`src/<your_module>.rs`)! CEO will wire `src/main.rs` and `src/server.rs` centrally in Wave 3.

---

## Track A (`@CTO`) — `src/project_artifacts.rs` (`scan_project_artifacts`)
- **Worktree:** `C:\Users\nguye\.openmausbot\wt-v07-a` (branch `feat/v07-a-project-artifacts`)
- **Owned File:** `src/project_artifacts.rs` (`<= 500` LOC, `#![allow(dead_code)]` at top so integration never warns before wiring).
- **Public API:**
  ```rust
  #[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
  #[serde(rename_all = "camelCase")]
  pub struct ProjectArtifactsParams {
      pub roots: Option<Vec<String>>,
      pub min_inactive_days: Option<u64>, // default 14 (0 allowed for immediate scan in tests)
      pub min_size_bytes: Option<u64>,    // default 1_048_576 (1 MiB)
      pub max_depth: Option<usize>,       // default 5
      pub max_results: Option<usize>,     // default 100
  }

  pub fn scan_project_artifacts(engine: &ScanEngine, params: ProjectArtifactsParams) -> ProjectArtifactsReport
  ```
- **Default Roots (when `params.roots` is `None` or empty):**
  - Deduplicated existing directories under `dirs::home_dir()` / `dirs::document_dir()`:
    `Projects`, `repos`, `workspace`, `workspaces`, `code`, `dev`, `src`, `GitHub`, plus `<document_dir>/Projects` and `<home>/OneDrive/Documents/Projects`.
- **Ecosystem Proof Rules (NEVER flag an arbitrary folder named `target` or `build` without sibling/inner manifest proof!):**
  - `target` → sibling `Cargo.toml` (`ecosystem: "rust"`, `kind: "build_cache"`, base `safe_to_delete`) OR sibling `pom.xml` (`ecosystem: "maven"`, `kind: "build_cache"`, base `safe_to_delete`).
  - `node_modules` → sibling `package.json` (`ecosystem: "node"`, `kind: "dependency_env"`, base `review`).
  - `.next`, `.nuxt`, `.turbo`, `.parcel-cache`, `.svelte-kit`, `.angular` → sibling `package.json` (`ecosystem: "node"`, `kind: "build_cache"`, base `safe_to_delete`).
  - `.venv`, `venv` → inner `pyvenv.cfg` (`ecosystem: "python"`, `kind: "dependency_env"`, base `review`).
  - `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `__pycache__` → sibling `pyproject.toml`, `requirements.txt`, `setup.py`, OR `*.py` file (`ecosystem: "python"`, `kind: "build_cache"`, base `safe_to_delete`).
  - `.gradle` → sibling `build.gradle` or `build.gradle.kts` or `settings.gradle*` (`ecosystem: "gradle"`, `kind: "build_cache"`, base `safe_to_delete`).
  - `build` → ONLY if inner `CMakeCache.txt` (`ecosystem: "cmake"`, `kind: "build_cache"`, base `safe_to_delete`) OR sibling `build.gradle` / `build.gradle.kts` (`ecosystem: "gradle"`, `kind: "build_cache"`, base `safe_to_delete`). Plain `build/` without those markers MUST be ignored!
  - Prune traversal inside matched artifact dirs and `.git` so we never descend into millions of nested files during discovery; compute candidate directory physical/logical size via bounded iterative walk (skipping symlinks & cloud placeholders) and capture latest mtime inside the project root (shallow project activity check: project root files + immediate `src/` mtime) vs `min_inactive_days`!
- **Mandatory Safety Guards:**
  1. **Never touch `.git`**.
  2. **Git Tracked-File Guard**: Find nearest ancestor `.git` (up to scan root). If found, run `git -C <repo_root> ls-files --error-unmatch -- <rel_candidate_path>` (or `git -C <repo_root> ls-files -z -- <rel_candidate_path>` checking non-empty stdout, with `CREATE_NO_WINDOW` on Windows if needed or standard `Command` with 3s timeout / non-blocking output check). If ANY file inside the candidate dir is git-tracked, override candidate to `git_tracked: true`, `verdict: "keep"`, `risk_level: "dangerous"`, `importance_score: 95`, and do NOT mark reclaimable!
  3. **Live Process Lock (`sysinfo`)**: Inspect running process `exe()` and `cwd()` (`ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet).with_cwd(UpdateKind::OnlyIfNotSet)`). If any compiler/runtime/IDE process (`cargo`, `rustc`, `rust-analyzer`, `node`, `bun`, `deno`, `python`, `uv`, `java`, `gradle`, `cmake`, `ninja`, `code`, `cursor`, `devenv`, `idea64`) has `cwd` or `exe` inside the project root, mark `in_use: true`, `verdict: "blocked"`, `risk_level: "blocked"`.
- **Session Registration & Report (`#[serde(rename_all = "camelCase")]`):**
  - Register candidates via `engine.register_custom_session("project_artifacts", candidates, warnings, duration_ms, true)` using `category: "project_artifact".into()`.
  - Return `ProjectArtifactsReport`: `scan_id`, `duration_ms`, `roots_scanned`, `min_inactive_days`, `total_artifacts_found`, `total_bytes`, `reclaimable_bytes`, `safe_bytes`, `review_bytes`, `by_ecosystem: BTreeMap<String, EcosystemSummary>`, `items: Vec<ProjectArtifactItem>` (including `approval_token` from `session.entries` matched by path!), `warnings`.
- **Required Unit Tests (`>= 5`):**
  1. Rust `Cargo.toml` + `target/` older than `min_inactive_days` → `safe_to_delete` + valid `approval_token`.
  2. Node `package.json` + `node_modules/` → `review`, while `.next/` → `safe_to_delete`.
  3. Plain `build/` without `CMakeCache.txt` or `build.gradle*` is NOT flagged, whereas `build/` WITH `CMakeCache.txt` IS flagged.
  4. Git tracked-file guard: real temporary `git init` repo where `build/CMakeCache.txt` exists AND `build/tracked.txt` is `git add`ed → overridden to `git_tracked == true` & `verdict == "keep"`.
  5. Recently active project (`min_inactive_days: 14`, fresh `src/main.rs`) is skipped/filtered out.

---

## Track B (`@Engineer`) — `src/containers.rs` (`scan_container_virtual_disks`)
- **Worktree:** `C:\Users\nguye\.openmausbot\wt-v07-b` (branch `feat/v07-b-containers`)
- **Owned File:** `src/containers.rs` (`<= 500` LOC, `#![allow(dead_code)]` at top).
- **Public API:**
  ```rust
  #[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
  #[serde(rename_all = "camelCase")]
  pub struct ContainerScanParams {
      pub custom_roots: Option<Vec<String>>,
      pub custom_roots_only: Option<bool>,
      pub include_docker_df: Option<bool>, // default true (false in unit tests if desired)
      pub min_log_age_hours: Option<u64>,  // default 24
  }

  pub fn scan_container_virtual_disks(engine: &ScanEngine, params: ContainerScanParams) -> ContainerReport
  ```
- **Discovery Targets:**
  - **Virtual Disks (READ-ONLY AUDIT — NEVER DELETABLE VIA MCP!):**
    - Windows: `%LOCALAPPDATA%\Docker\wsl\**\*.vhdx`, `%LOCALAPPDATA%\Packages\*\LocalState\ext4.vhdx`, `%USERPROFILE%\.wsl\**\*.vhdx`, `%LOCALAPPDATA%\rancher-desktop\**\*.vhdx`, `%LOCALAPPDATA%\containers\podman\**\*.vhdx`.
    - macOS: `~/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw` (and `.qcow2`), `~/.orbstack/data/**` (`*.img`/`*.raw`), `~/.colima/**/diffdisk`, `~/.lima/**/diffdisk`, `~/.local/share/containers/podman/machine/**` (`*.raw`/`*.qcow2`).
    - Linux: `~/.docker/desktop/vms/0/data/Docker.raw`, `~/.local/share/docker/desktop/vms/**`, `~/.local/share/containers/podman/machine/**` (`*.qcow2`/`*.raw`), `~/.lima/**/diffdisk`.
    - Also scan `custom_roots` (bounded depth <= 5) for `*.vhdx`, `Docker.raw`, `*.qcow2`, `diffdisk`.
  - **Physical vs Apparent/Virtual Size Measurement:**
    - On `#[cfg(unix)]`: `allocated_bytes = meta.blocks() * 512`, `apparent_bytes = meta.len()`.
    - On `#[cfg(windows)]`: use `GetCompressedFileSizeW` (`kernel32`) for `allocated_bytes` (fallback `meta.len()`), and parse VHDX region/metadata virtual disk size if header starts with `vhdxfile` (or `apparent_bytes = meta.len().max(allocated_bytes)` if raw/unparsed — bonus: reading VHDX virtual size or reporting file size cleanly without panicking on locked files! Note: running WSL locks `.vhdx` against `File::open` with sharing violations unless opened with `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` (`share_mode(7)` on `OpenOptionsExt`), so ALWAYS rely primarily on `std::fs::symlink_metadata` + `GetCompressedFileSizeW` and if reading header on Windows use `share_mode(7)` and fall back gracefully on error!).
  - **Non-blocking `docker system df` Probe:**
    - Pure parser helper `pub fn parse_docker_system_df_jsonl(stdout: &str) -> Vec<DockerDfCategory>` parsing lines of `docker system df --format "{{json .}}"` (`Type`, `TotalCount`, `Active`, `Size`, `Reclaimable`).
    - When `include_docker_df.unwrap_or(true)` (and not `custom_roots_only == Some(true)`), spawn `docker system df --format "{{json .}}"` on a helper thread with a strict **3-second timeout** (`mpsc::channel` + `recv_timeout(Duration::from_secs(3))`, killing child on timeout) so hung Docker Desktop daemon NEVER blocks MCP!
  - **Disposable Host Container Logs/Caches (Safe to Clean via Session):**
    - Unlocked host log/cache files older than `min_log_age_hours` (default 24h) under `%LOCALAPPDATA%\Docker\log\**` (Windows), `~/Library/Containers/com.docker.docker/Data/log/**` (macOS), `~/.docker/desktop/log/**` (Linux), or `<custom_root>/Docker/log/**` (`*.log`, `*.log.*`, `*.old`).
    - Register ONLY these disposable log/cache files via `engine.register_custom_session("container_cache", candidates, warnings, duration_ms, true)` with `category: "container_cache"`, `verdict: "safe_to_delete"`, `risk_level: "safe"`.
  - **HARD INVARIANT (TESTED BY QA!):**
    - `.vhdx`, `Docker.raw`, `.qcow2`, `diffdisk` MUST **NEVER** be added to `candidates` passed into `register_custom_session`! Every `VirtualDiskItem` in `report.virtual_disks` MUST have `verdict: "blocked"`, `deletable_via_mcp: false`, and an OS-specific `compaction_commands: Vec<String>` runbook (e.g. on Windows: `wsl --shutdown`, `Optimize-VHD -Path "<path>" -Mode Full`, `diskpart -> select vdisk file="<path>" -> attach vdisk readonly -> compact vdisk -> detach vdisk`; plus `docker system prune` / `docker builder prune` when Docker is detected).
- **Required Unit Tests (`>= 5`):**
  1. Synthetic `.vhdx` + `Docker.raw` + `Docker/log/host.log` (old) in temp `custom_roots` (`custom_roots_only: true`, `include_docker_df: false`) → `.vhdx` and `Docker.raw` appear in `virtual_disks` with `deletable_via_mcp == false` and are **ABSENT** from `engine.get_session(&report.scan_id)` entries!
  2. Old `Docker/log/host.log` (> 24h) IS registered in `ScanSession` as `category == "container_cache"`, `verdict == "safe_to_delete"`, with valid `approval_token`, while fresh `< 1h` log is skipped.
  3. `parse_docker_system_df_jsonl` accurately parses real Docker JSONL output (`Images`, `Containers`, `Local Volumes`, `Build Cache`) and ignores malformed lines without panicking.
  4. Compaction runbook generator returns Windows `wsl --shutdown` / `Optimize-VHD` / `diskpart` commands for `.vhdx` and `docker builder prune` / OrbStack / Lima guidance for `.raw`/`.qcow2`.

---

## Track C (`@Data-AI`) — `src/model_dedup.rs` (`scan_model_duplicates`)
- **Worktree:** `C:\Users\nguye\.openmausbot\wt-v07-c` (branch `feat/v07-c-model-dedup`)
- **Owned File:** `src/model_dedup.rs` (`<= 500` LOC, `#![allow(dead_code)]` at top).
- **Public API:**
  ```rust
  #[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
  #[serde(rename_all = "camelCase")]
  pub struct ModelDedupParams {
      pub extra_roots: Option<Vec<String>>,
      pub custom_roots_only: Option<bool>,
      pub min_weight_bytes: Option<u64>,       // default 16_777_216 (16 MiB)
      pub include_conda_archives: Option<bool>, // default true
      pub min_archive_age_hours: Option<u64>,  // default 24
  }

  pub fn scan_model_duplicates(engine: &ScanEngine, params: ModelDedupParams) -> ModelDedupReport
  ```
- **Default Roots (when `custom_roots_only != Some(true)`):**
  - Env vars if set & existing: `OLLAMA_MODELS`, `HF_HOME`, `HUGGINGFACE_HUB_CACHE`, `TORCH_HOME`, `CONDA_PKGS_DIRS` (split on `std::env::split_paths`).
  - Standard user paths: `~/.ollama/models`, `~/.cache/huggingface/hub`, `~/.lmstudio/models`, `~/.cache/whisper`, `~/.cache/torch/hub/checkpoints`, `~/ComfyUI/models`, `~/stable-diffusion-webui/models`, `~/.conda/pkgs`, `~/miniconda3/pkgs`, `~/anaconda3/pkgs`, `~/miniforge3/pkgs`, `%USERPROFILE%\anaconda3\pkgs`, `%USERPROFILE%\miniconda3\pkgs`, `%LOCALAPPDATA%\anaconda3\pkgs`, `%LOCALAPPDATA%\miniconda3\pkgs`.
  - Plus `extra_roots`. Deduplicate canonical/normalized roots so overlapping roots are never scanned twice!
- **Target Weight Files & 3-Stage Hardlink-Aware `BLAKE3` Pipeline:**
  1. **Weight File Eligibility (`>= min_weight_bytes`, regular file, NOT symlink, NOT `is_cloud_placeholder(&meta)`):**
     - Extensions: `.gguf`, `.safetensors`, `.pt`, `.pth`, `.ckpt`, `.onnx`, `.bin`, `.ggml`, `.tflite`
     - OR extensionless Ollama content-addressed blobs matching parent dir `blobs` and filename starting with `sha256-`!
  2. **Physical Inode / File-Index Grouping (CRITICAL FOR HARDLINKS!):**
     - Implement `physical_file_id(path: &Path, meta: &std::fs::Metadata) -> Option<(u64, u128)>`:
       - `#[cfg(unix)]`: `use std::os::unix::fs::MetadataExt; Some((meta.dev(), meta.ino() as u128))`
       - `#[cfg(windows)]`: open file read-only with `share_mode(7)` (`FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`) and call `GetFileInformationByHandle` (`kernel32`, `BY_HANDLE_FILE_INFORMATION` with `// SAFETY:` comment) to extract `(dwVolumeSerialNumber as u64, ((nFileIndexHigh as u128) << 64) | (nFileIndexLow as u128))`.
     - Paths sharing the exact same `physical_file_id` consume disk blocks ONLY ONCE! Group by `size` first; if all paths of a given size share a single `physical_file_id` (and count > 1), you can optionally report or count them in `hardlinked_groups_skipped` with `wasted_bytes = 0`, and NEVER mark hardlinked siblings for deletion!
     - When `>= 2` distinct `physical_file_id`s have the exact same `size`:
       - **Stage 2 (Partial Fingerprint)**: hash `first 64 KiB + middle 64 KiB + last 64 KiB` with `blake3` (only 192 KiB read per distinct physical file!).
       - **Stage 3 (Full Streaming `blake3`)**: ONLY when `>= 2` distinct physical files match on `(size, partial_hash)`, stream full `blake3::Hasher` (`64 KiB` stack buffer) once per distinct `physical_file_id`!
  3. **Canonical Winner Election & `ScanSession` Registration:**
     - If an active AI runtime (`crate::ai_stack::ActiveAiProcesses::detect_live()`) is running (`ollama`, `lms`, `python`, etc. matching the store), mark affected duplicate candidates `verdict: "blocked"`, `risk_level: "blocked"`.
     - Otherwise, elect 1 canonical `keep` winner per `blake3` group (prefer HuggingFace hub `blobs/` or Ollama `blobs/` canonical store first, then oldest `modified` timestamp, then shortest path).
     - All other distinct physical copies become `CustomCandidate`s with `category: "model_duplicate"`, `verdict: "review"`, `risk_level: "caution"`, `importance_score: 45`, reason explaining exact `BLAKE3` match with canonical path + SSD `TBW`-friendly hardlink suggestion (`mklink /H` on Windows / `ln` on Unix).
  4. **Conda Compressed Package Tarball Cleanup (`include_conda_archives.unwrap_or(true)`):**
     - Inside `pkgs/` directories (`conda`/`miniconda`/`anaconda`/`miniforge` or `<extra_root>/pkgs`), find unlocked top-level `*.conda` and `*.tar.bz2` archive files older than `min_archive_age_hours` (default 24h, regular file, not symlink, not cloud placeholder). (Do NOT delete extracted package folders in `pkgs/`, because Conda hardlinks environments into them — ONLY the `.conda` / `.tar.bz2` download archives, matching `conda clean --tarballs`!).
     - Register them in the same `register_custom_session("model_duplicates", candidates, warnings, duration_ms, true)` with `category: "model_duplicate"`, `verdict: "safe_to_delete"`, `risk_level: "safe"`, `importance_score: 10`.
- **Required Unit Tests (`>= 5`):**
  1. Identical `.gguf` files in `ollama/blobs/sha256-abc` and `lmstudio/models/m.gguf` (`min_weight_bytes: 1024`) → 1 duplicate group, `ollama/blobs/...` kept as canonical, `lmstudio` copy marked `review` with `wasted_bytes == file_size` and valid `approval_token`.
  2. Same-size `.safetensors` files that differ in the last byte → `0` duplicate groups (proves Stage 2/3 full verification).
  3. **Real OS Hardlink Test** (`std::fs::hard_link(&src, &dst)`): two hardlinked `.safetensors` files share the same `physical_file_id` → `wasted_bytes == 0` and NEITHER copy is registered as deletable in `ScanSession`!
  4. Conda `pkgs/pytorch-2.5.conda` & `pkgs/cuda.tar.bz2` (> 24h old) flagged `safe_to_delete`, while `pkgs/extracted_pkg_dir/lib.so` is untouched!

---

## Track D (`@Ops`) — Installers, Manpage, Completions & `release.yml`
- **Worktree:** `C:\Users\nguye\.openmausbot\wt-v07-d` (branch `feat/v07-d-packaging`)
- **Owned Files ONLY:** `install.ps1`, `install.sh`, `disk-cleaner-mcp.1`, `.github/workflows/release.yml`, `completions/disk-cleaner-mcp.bash`, `completions/disk-cleaner-mcp.zsh` (DO NOT touch `src/*` or `Cargo.*`!).
- **Exact Deliverables:**
  1. **`install.ps1` Atomic Windows Binary Hot-Swap:**
     - Add helper `Install-BinaryAtomically -SourceFile <string> -TargetExe <string>`:
       - First best-effort remove stale `$TargetExe.old` (`"$InstallDir\disk-cleaner-mcp.old.exe"`) with `-ErrorAction SilentlyContinue`.
       - Try direct `Copy-Item -Path $SourceFile -Destination $TargetExe -Force -ErrorAction Stop`.
       - In `catch`: if `$TargetExe` exists (locked by a running MCP agent!), `Move-Item -Path $TargetExe -Destination "$InstallDir\disk-cleaner-mcp.old.exe" -Force -ErrorAction Stop`, then `Copy-Item -Path $SourceFile -Destination $TargetExe -Force -ErrorAction Stop`, and print a friendly yellow/green note that the running binary was hot-swapped (`disk-cleaner-mcp.old.exe` will auto-clean on next run).
     - Use `Install-BinaryAtomically` for BOTH `-LocalBinary` and the GitHub Release download `Expand-Archive` path! Also do a best-effort silent cleanup of `disk-cleaner-mcp.old.exe` at script start and end.
  2. **`install.sh` Multi-Agent Parity + Flags (`bash -n install.sh` clean):**
     - Support CLI flags: `--local-binary <path>`, `--skip-binary`, `--version <tag>`, `--install-dir <dir>` (default `$HOME/.local/bin`), `-h|--help`.
     - If `--local-binary <path>` is passed, install atomically (`cp` to `$INSTALL_DIR/.disk-cleaner-mcp.tmp.$$` + `chmod +x` + `mv -f` to `$INSTALL_DIR/disk-cleaner-mcp`, which is POSIX-atomic even while running!). Same atomic `mv -f` for GitHub release tarball extraction!
     - Add additive UTF-8 MCP config registration using `python3` (if `command -v python3 >/dev/null 2>&1`, else print manual snippet gracefully) for ALL **7 clients** on macOS & Linux (never overwriting sibling `mcpServers` or other settings!):
       1. Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json` on Darwin; `~/.config/Claude/claude_desktop_config.json` on Linux — create/update if parent `Claude` dir exists)
       2. Claude Code (`~/.claude.json` — update if `~/.claude` dir or `~/.claude.json` exists)
       3. Cursor (`~/.cursor/mcp.json` — update if `~/.cursor` exists)
       4. Gemini CLI (`~/.gemini/settings.json` — update if `~/.gemini` exists)
       5. Antigravity (`~/.gemini/antigravity/mcp_config.json` — update if `~/.gemini/antigravity` exists)
       6. OpenCode (`~/.config/opencode/opencode.json` — `mcp.disk-cleaner-mcp = {"type": "local", "command": [BIN_PATH], "enabled": true}`, if `~/.config/opencode` exists)
       7. Codex CLI (`~/.codex/config.toml` — idempotently add/update `[mcp_servers.disk-cleaner-mcp]` `command = "<BIN_PATH>"` if `~/.codex` exists)
  3. **`disk-cleaner-mcp.1` Manpage Polish (`v0.7.0`, 23 Tools):**
     - Update `.TH DISK-CLEANER-MCP 1 "2026-04" "0.7.0" "User Commands"`.
     - Fix typo `.SH ENTIRONMENT` → `.SH ENVIRONMENT` and document `DCM_TELEMETRY` alongside `RUST_LOG`.
     - Add documentation section `.SH MCP TOOLS` listing all **23 tools** grouped cleanly (Discovery & Core Cleanup, Deep OS/App/Browser/Startup/Health/Large-Files v0.6, and SSD Savior Developer/Container/AI-Model Dedup v0.7).
  4. **`.github/workflows/release.yml` (Supersedes Dependabot PR #15):**
     - Bump `softprops/action-gh-release` from `f06a81a03... # v3.0.3` to **`8a0cd651e5b2365bd640854a3fa5dfc70e4875f3 # v3.0.4`**.
  5. **Verify:**
     - Test `install.ps1 -LocalBinary` against a real running/locked dummy `.exe` process in `$env:TEMP` to prove Atomic Hot-Swap succeeds with exit code `0`!
     - Syntax-check `install.sh` via `python` / `git bash` (`bash -n install.sh`) and test its Python config-updater block in a temp `HOME` dir across all 7 client config formats!
