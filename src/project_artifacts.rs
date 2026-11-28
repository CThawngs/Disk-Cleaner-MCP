//! Inactive developer build caches & dependency artifact scanner (`scan_project_artifacts`).
#![allow(dead_code)]
use crate::ai_stack::{is_symlink_or_junction, rd_vec};
use crate::engine::{CustomCandidate, ScanEngine};
use crate::insights::is_cloud_placeholder;
use crate::{safety, smart_scan::bump_mtime};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant, UNIX_EPOCH};
use std::{fs, io::Read, path::Path, path::PathBuf, process::Command, process::Stdio};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
const DEV_PROCS: &str = "cargo|rustc|rust-analyzer|node|bun|deno|python|python3|uv|java|javaw|gradle|cmake|ninja|code|cursor|devenv|idea64|code - insiders";
const HOME_SUBS: &str = "Projects|repos|workspace|workspaces|code|dev|src|GitHub";
const PY_FILES: &str = "pyproject.toml|requirements.txt|setup.py|setup.cfg|Pipfile";
const SKIP_ARTS: &str = "target|node_modules|.next|.nuxt|.venv|venv|build|__pycache__";
const NODE_CACHES: &str = ".next|.nuxt|.turbo|.parcel-cache|.svelte-kit|.angular";
const PY_CACHES: &str = ".pytest_cache|.mypy_cache|.ruff_cache|__pycache__";
type Spec = (&'static str, bool, &'static str);
type Tag = (&'static str, &'static str, u64, u64, bool, bool, PathBuf);
type LockEntry = (PathBuf, String, bool);
type ScanCtx<'a> = (&'a Path, u64, u64, i64, &'a [LockEntry]);
type CandOut = Option<(Tag, CustomCandidate)>;
type Rep = ProjectArtifactsReport;
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, rename_all = "camelCase")]
pub struct ProjectArtifactsParams {
    pub roots: Option<Vec<String>>,
    pub min_inactive_days: Option<u64>,
    pub min_size_bytes: Option<u64>,
    pub max_depth: Option<usize>,
    pub max_results: Option<usize>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EcosystemSummary {
    pub count: u64,
    pub total_bytes: u64,
    pub reclaimable_bytes: u64,
    pub safe_bytes: u64,
    pub review_bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectArtifactItem {
    pub path: String,
    pub project_root: String,
    pub artifact_name: String,
    pub ecosystem: String,
    pub kind: String,
    pub size_bytes: u64,
    pub file_count: u64,
    pub inactive_days: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_project_modified: Option<i64>,
    pub git_tracked: bool,
    pub in_use: bool,
    pub category: String,
    pub verdict: String,
    pub risk_level: String,
    pub approval_token: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectArtifactsReport {
    pub scan_id: String,
    pub duration_ms: u64,
    pub roots_scanned: Vec<String>,
    pub min_inactive_days: u64,
    pub total_artifacts_found: u64,
    pub total_bytes: u64,
    pub reclaimable_bytes: u64,
    pub safe_bytes: u64,
    pub review_bytes: u64,
    pub by_ecosystem: BTreeMap<String, EcosystemSummary>,
    pub items: Vec<ProjectArtifactItem>,
    pub warnings: Vec<String>,
}
fn live_locks() -> Vec<LockEntry> {
    let Ok(mut sys) = System::new() else {
        return Vec::new();
    };
    let u = UpdateKind::OnlyIfNotSet;
    let rk = ProcessRefreshKind::nothing().with_exe(u).with_cwd(u);
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, rk);
    let devs: HashSet<&str> = DEV_PROCS.split('|').collect();
    let mut out = Vec::new();
    for p in sys.processes().values() {
        let raw = p.name().to_string_lossy().to_ascii_lowercase();
        let stem = raw.strip_suffix(".exe").unwrap_or(&raw).to_string();
        let dev = devs.contains(stem.as_str()) || stem.starts_with("python3.");
        out.extend(p.exe().map(|x| (safety::normalize(x), stem.clone(), dev)));
        out.extend(
            p.cwd()
                .filter(|_| dev)
                .map(|x| (safety::normalize(x), stem, true)),
        );
    }
    out
}
fn lock_reason(locks: &[LockEntry], proj: &Path, cand: &Path) -> Option<String> {
    let (np, nc) = (safety::normalize(proj), safety::normalize(cand));
    locks
        .iter()
        .find(|(p, _, dev)| (*dev && p.starts_with(&np)) || p.starts_with(&nc))
        .map(|(_, n, _)| format!("Locked by active process '{n}'"))
}
pub fn scan_project_artifacts(engine: &ScanEngine, params: &ProjectArtifactsParams) -> Rep {
    scan_inner(engine, params, &live_locks())
}
fn scan_inner(eng: &ScanEngine, p: &ProjectArtifactsParams, locks: &[LockEntry]) -> Rep {
    let (t0, now) = (
        Instant::now(),
        UNIX_EPOCH.elapsed().unwrap_or_default().as_secs() as i64,
    );
    let (min_days, min_bytes) = (
        p.min_inactive_days.unwrap_or(14),
        p.min_size_bytes.unwrap_or(1 << 20),
    );
    let max_depth = p.max_depth.unwrap_or(5).clamp(1, 16);
    let max_res = p.max_results.unwrap_or(100).clamp(1, 2_000);
    let mut warnings = Vec::new();
    let roots = resolve_roots(&p.roots, &mut warnings);
    let roots_scanned: Vec<String> = roots.iter().map(|r| r.to_string_lossy().into()).collect();
    let (mut seen, mut found) = (HashSet::new(), Vec::new());
    for r in &roots {
        let ctx: ScanCtx<'_> = (r.as_path(), min_days, min_bytes, now, locks);
        let mut q = VecDeque::from([(r.clone(), 0usize)]);
        while let Some((dir, depth)) = q.pop_front() {
            if depth >= max_depth {
                continue;
            }
            for e in rd_vec(&dir) {
                let is_d = e.file_type().is_ok_and(|t| t.is_dir() && !t.is_symlink());
                let ch = e.path();
                let Some(nm) = ch.file_name().and_then(|n| n.to_str()).filter(|_| is_d) else {
                    continue;
                };
                let sys_dir = matches!(nm, ".git" | "$Recycle.Bin" | "System Volume Information");
                if sys_dir || safety::is_protected(&ch) || !is_real_dir(&ch) {
                    continue;
                }
                if let Some(sp) = classify(&ch, nm, &dir) {
                    if seen.insert(safety::normalize(&ch)) {
                        found.extend(eval_cand(ctx, &dir, &ch, sp));
                    }
                } else {
                    q.push_back((ch, depth + 1));
                }
            }
        }
    }
    found.sort_by(|a, b| (b.1.size, &a.1.path).cmp(&(a.1.size, &b.1.path)));
    let total_artifacts_found = found.len() as u64;
    if found.len() > 2_000 {
        warnings.push("Capped session at 2000 candidates".into());
        found.truncate(2_000);
    }
    let (tags, cands): (Vec<Tag>, Vec<CustomCandidate>) = found.into_iter().unzip();
    let (duration_ms, w2) = (t0.elapsed().as_millis() as u64, warnings.clone());
    let sess = eng.register_custom_session("project_artifacts", cands, w2, duration_ms, true);
    let emap: HashMap<&str, _> = sess.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let (mut total_bytes, mut safe_bytes, mut review_bytes) = (0u64, 0u64, 0u64);
    let mut by_ecosystem: BTreeMap<String, EcosystemSummary> = BTreeMap::new();
    let mut items = Vec::with_capacity(tags.len());
    let ps = |x: Option<&Path>| x.map(|v| v.display().to_string()).unwrap_or_default();
    for (eco_k, kind, files, days, tracked, locked, path) in tags {
        let p_str = path.to_string_lossy().to_string();
        let Some(&e) = emap.get(p_str.as_str()) else {
            continue;
        };
        let in_use = locked || e.verdict == "blocked";
        total_bytes = total_bytes.saturating_add(e.size);
        let eco = by_ecosystem.entry(eco_k.into()).or_default();
        (eco.count, eco.total_bytes) = (eco.count + 1, eco.total_bytes.saturating_add(e.size));
        if !tracked && !in_use && e.verdict == "safe_to_delete" {
            eco.reclaimable_bytes += e.size;
            (safe_bytes, eco.safe_bytes) = (safe_bytes + e.size, eco.safe_bytes + e.size);
        } else if !tracked && !in_use && e.verdict == "review" {
            eco.reclaimable_bytes += e.size;
            (review_bytes, eco.review_bytes) = (review_bytes + e.size, eco.review_bytes + e.size);
        }
        items.push(ProjectArtifactItem {
            path: p_str,
            project_root: ps(path.parent()),
            artifact_name: ps(path.file_name().map(Path::new)),
            ecosystem: eco_k.into(),
            kind: kind.into(),
            size_bytes: e.size,
            file_count: files,
            inactive_days: days,
            last_project_modified: e.modified,
            git_tracked: tracked,
            in_use,
            category: e.category.clone(),
            verdict: e.verdict.clone(),
            risk_level: e.risk_level.clone(),
            approval_token: e.approval_token.clone(),
            reasons: e.reasons.clone(),
        });
    }
    items.truncate(max_res);
    ProjectArtifactsReport {
        scan_id: sess.scan_id.clone(),
        duration_ms,
        roots_scanned,
        min_inactive_days: min_days,
        total_artifacts_found,
        total_bytes,
        reclaimable_bytes: safe_bytes.saturating_add(review_bytes),
        safe_bytes,
        review_bytes,
        by_ecosystem,
        items,
        warnings,
    }
}
fn non_link_meta(p: &Path) -> Option<fs::Metadata> {
    let m = fs::symlink_metadata(p).ok()?;
    (!is_symlink_or_junction(&m)).then_some(m)
}
fn is_real_dir(p: &Path) -> bool {
    non_link_meta(p).is_some_and(|m| m.is_dir())
}
fn is_reg(p: &Path) -> bool {
    non_link_meta(p).is_some_and(|m| m.is_file())
}
fn resolve_roots(explicit: &Option<Vec<String>>, warnings: &mut Vec<String>) -> Vec<PathBuf> {
    let (mut seen, mut out) = (HashSet::new(), Vec::new());
    let mut add = |p: PathBuf, warn: bool| {
        if !is_real_dir(&p) || safety::is_protected(&p) {
            if warn {
                warnings.push(format!("Skipped invalid root: {}", p.display()));
            }
        } else if seen.insert(safety::normalize(&p)) {
            out.push(p);
        }
    };
    if let Some(list) = explicit.as_ref().filter(|l| !l.is_empty()) {
        list.iter().for_each(|r| add(PathBuf::from(r), true));
        return out;
    }
    if let Some(h) = dirs::home_dir() {
        HOME_SUBS.split('|').for_each(|s| add(h.join(s), false));
        add(h.join("OneDrive/Documents/Projects"), false);
    }
    if let Some(d) = dirs::document_dir() {
        add(d.join("Projects"), false);
    }
    out
}
fn has_py(r: &Path) -> bool {
    let py = |p: PathBuf| is_reg(&p) && p.extension().is_some_and(|x| x.eq_ignore_ascii_case("py"));
    PY_FILES.split('|').any(|f| is_reg(&r.join(f))) || rd_vec(r).into_iter().any(|e| py(e.path()))
}
fn classify(cand: &Path, name: &str, proj: &Path) -> Option<Spec> {
    let gb = is_reg(&proj.join("build.gradle")) || is_reg(&proj.join("build.gradle.kts"));
    let gs = is_reg(&proj.join("settings.gradle")) || is_reg(&proj.join("settings.gradle.kts"));
    let pkg = is_reg(&proj.join("package.json"));
    let has = |s: &str, n: &str| s.split('|').any(|x| x == n);
    match name {
        "target" if is_reg(&proj.join("Cargo.toml")) => Some(("rust", false, "Cargo target/")),
        "target" if is_reg(&proj.join("pom.xml")) => Some(("maven", false, "Maven target/")),
        "node_modules" if pkg => Some(("node", true, "Node node_modules")),
        n if pkg && has(NODE_CACHES, n) => Some(("node", false, "JS cache")),
        ".venv" | "venv" if is_reg(&cand.join("pyvenv.cfg")) => Some(("python", true, "Py venv")),
        n if has(PY_CACHES, n) && has_py(proj) => Some(("python", false, "Py cache")),
        ".gradle" if gb || gs => Some(("gradle", false, "Gradle cache")),
        "build" if is_reg(&cand.join("CMakeCache.txt")) => Some(("cmake", false, "CMake build")),
        "build" if gb => Some(("gradle", false, "Gradle build")),
        _ => None,
    }
}
fn eval_cand(ctx: ScanCtx<'_>, proj: &Path, cand_dir: &Path, sp: Spec) -> CandOut {
    let ((root, min_days, min_bytes, now, locks), (eco, is_dep, msg)) = (ctx, sp);
    let (bytes, files, am) = walk_stats(cand_dir, usize::MAX, 250_000, false);
    let (_, _, m1) = (bytes >= min_bytes).then(|| walk_stats(proj, 0, 256, true))?;
    let (_, _, m2) = walk_stats(&proj.join("src"), 2, 256, true);
    let last_mod = [m1, m2, am].into_iter().flatten().max();
    let days = last_mod.map_or(min_days, |ts| (now.saturating_sub(ts) as u64) / 86_400);
    let tracked = (days >= min_days).then(|| git_tracked(proj, root, cand_dir).unwrap_or(false))?;
    let lock_msg = lock_reason(locks, proj, cand_dir);
    let in_use = lock_msg.is_some();
    let kind = ["build_cache", "dependency_env"][usize::from(is_dep)];
    let (verdict, risk_level, importance_score, reason) = if tracked {
        ("keep", "dangerous", 95, "Git-tracked files found".into())
    } else if let Some(m) = lock_msg {
        ("blocked", "blocked", 100, m)
    } else if is_dep {
        ("review", "caution", 35, format!("{msg} ({days}d)"))
    } else {
        ("safe_to_delete", "safe", 15, format!("{msg} ({days}d)"))
    };
    let cand = CustomCandidate {
        kind: "dir".into(),
        path: cand_dir.to_path_buf(),
        size: bytes,
        modified: last_mod,
        category: "project_artifact".into(),
        verdict: verdict.into(),
        importance_score,
        risk_level: risk_level.into(),
        reasons: vec![reason],
    };
    let tag = (
        eco,
        kind,
        files,
        days,
        tracked,
        in_use,
        cand_dir.to_path_buf(),
    );
    Some((tag, cand))
}
fn walk_stats(root: &Path, max_d: usize, max_f: usize, skip_arts: bool) -> (u64, u64, Option<i64>) {
    if !is_real_dir(root) {
        return (0, 0, None);
    }
    let (mut bytes, mut files, mut latest) = (0u64, 0u64, None);
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, d)) = stack.pop() {
        for e in rd_vec(&dir) {
            let (p, nm) = (e.path(), e.file_name());
            let s = nm.to_string_lossy();
            let skip = s == ".git" || (skip_arts && SKIP_ARTS.split('|').any(|x| x == s.as_ref()));
            if skip || !e.file_type().is_ok_and(|t| !t.is_symlink()) || safety::is_protected(&p) {
                continue;
            }
            let Some(m) = non_link_meta(&p) else {
                continue;
            };
            if m.is_dir() && d < max_d && (files as usize) < max_f {
                stack.push((p, d + 1));
            } else if m.is_file() && !is_cloud_placeholder(&m) {
                (bytes, files) = (bytes.saturating_add(m.len()), files + 1);
                bump_mtime(&mut latest, &m);
                if (files as usize) >= max_f {
                    return (bytes, files, latest);
                }
            }
        }
    }
    (bytes, files, latest)
}
fn git_tracked(proj: &Path, scan_root: &Path, cand: &Path) -> Option<bool> {
    let (stop, mut cur, mut repo) = (safety::normalize(scan_root), Some(proj), None);
    while let Some(dir) = cur {
        if fs::symlink_metadata(dir.join(".git")).is_ok() {
            repo = Some(dir);
            break;
        }
        if safety::normalize(dir) == stop {
            break;
        }
        cur = dir.parent();
    }
    let repo = repo?;
    let rel = cand.strip_prefix(repo).ok()?;
    let rel_s = (!rel.as_os_str().is_empty()).then(|| rel.to_string_lossy().replace('\\', "/"))?;
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo)
        .args(["ls-files", "-z", "--", &rel_s]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    let mut child = cmd.spawn().ok()?;
    let mut hit = false;
    if let Some(mut out) = child.stdout.take() {
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut b = [0u8; 1];
            let _ = tx.send(out.read(&mut b).is_ok_and(|n| n > 0));
        });
        let wait = Duration::from_secs(3);
        hit = !matches!(
            rx.recv_timeout(wait),
            Ok(false) | Err(RecvTimeoutError::Disconnected)
        );
    }
    let _ = (child.kill(), child.wait());
    Some(hit)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DeleteRequest;
    use std::{fs::File, io::Write, time::SystemTime};
    fn sbox(tag: &str) -> PathBuf {
        let ns = UNIX_EPOCH.elapsed().unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("dcm_pa_{tag}_{ns}"));
        fs::create_dir_all(&p).unwrap();
        p
    }
    fn aged(p: &Path, data: &[u8], days: u64) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut f = File::create(p).unwrap();
        f.write_all(data).unwrap();
        if days > 0 {
            let age = Duration::from_secs(days * 86_400 + 3600);
            f.set_modified(SystemTime::now() - age).unwrap();
        }
    }
    fn cfg(root: &Path, days: u64) -> ProjectArtifactsParams {
        ProjectArtifactsParams {
            roots: Some(vec![root.display().to_string()]),
            min_inactive_days: Some(days),
            min_size_bytes: Some(1024),
            ..Default::default()
        }
    }
    fn git(r: &Path, a: &[&str]) {
        let mut c = Command::new("git");
        assert!(c.arg("-C").arg(r).args(a).status().unwrap().success());
    }
    #[test]
    fn rust_stale_target_safe_and_deletable() {
        let r = sbox("rust");
        aged(&r.join("p/Cargo.toml"), b"[package]\nname=\"p\"\n", 20);
        aged(&r.join("p/src/lib.rs"), b"pub fn x(){}", 20);
        aged(&r.join("p/target/debug/a.rlib"), &[7u8; 4096], 20);
        let eng = ScanEngine::new();
        let rep = scan_project_artifacts(&eng, &cfg(&r, 14));
        assert_eq!(rep.items[0].verdict, "safe_to_delete");
        let tok = &rep.items[0].approval_token;
        let j = serde_json::json!({"scanId": rep.scan_id, "items": [{"approvalToken": tok, "path": rep.items[0].path}]});
        let req: DeleteRequest = serde_json::from_value(j).unwrap();
        assert_eq!(eng.delete(&req).dry_run, 1);
        let _ = fs::remove_dir_all(&r);
    }
    #[test]
    fn node_modules_review_and_dot_next_safe() {
        let r = sbox("node");
        aged(&r.join("w/package.json"), b"{}", 0);
        aged(&r.join("w/node_modules/a.js"), &[b'a'; 2048], 0);
        aged(&r.join("w/.next/b.js"), &[b'b'; 2048], 0);
        let rep = scan_project_artifacts(&ScanEngine::new(), &cfg(&r, 0));
        assert_eq!(rep.items.len(), 2);
        for i in &rep.items {
            let exp = ["review", "safe_to_delete"][usize::from(i.artifact_name == ".next")];
            assert_eq!(i.verdict, exp);
        }
        let _ = fs::remove_dir_all(&r);
    }
    #[test]
    fn plain_build_ignored_cmake_build_flagged() {
        let r = sbox("cmake");
        aged(&r.join("plain/build/a.bin"), &[1u8; 2048], 0);
        aged(&r.join("cm/build/CMakeCache.txt"), b"CMAKE", 0);
        aged(&r.join("cm/build/b.o"), &[2u8; 2048], 0);
        let rep = scan_project_artifacts(&ScanEngine::new(), &cfg(&r, 0));
        assert_eq!(rep.items.len(), 1);
        assert_eq!(rep.items[0].ecosystem, "cmake");
        let _ = fs::remove_dir_all(&r);
    }
    #[test]
    fn git_tracked_guard_overrides_to_keep() {
        let r = sbox("git");
        let repo = r.join("repo");
        aged(&repo.join("build/CMakeCache.txt"), b"CMAKE", 0);
        aged(&repo.join("build/tracked.txt"), &[b'x'; 2048], 0);
        git(&repo, &["init"]);
        git(&repo, &["add", "-f", "build/tracked.txt"]);
        let rep = scan_project_artifacts(&ScanEngine::new(), &cfg(&r, 0));
        assert!(rep.items[0].git_tracked);
        assert_eq!(rep.items[0].verdict, "keep");
        assert_eq!(rep.reclaimable_bytes, 0);
        let _ = fs::remove_dir_all(&r);
    }
    #[test]
    fn active_project_skipped_and_process_lock_blocks() {
        let r = sbox("act");
        aged(&r.join("c/Cargo.toml"), b"[package]\nname=\"c\"\n", 30);
        aged(&r.join("c/target/old.bin"), &[9u8; 2048], 30);
        aged(&r.join("c/src/main.rs"), b"fn main(){}", 0);
        let eng = ScanEngine::new();
        assert!(scan_project_artifacts(&eng, &cfg(&r, 14)).items.is_empty());
        aged(&r.join("c/src/main.rs"), b"fn main(){}", 30);
        let locks = vec![(safety::normalize(&r.join("c")), "cargo".into(), true)];
        let rep = scan_inner(&eng, &cfg(&r, 14), &locks);
        assert!(rep.items[0].in_use);
        assert_eq!(rep.items[0].verdict, "blocked");
        let _ = fs::remove_dir_all(&r);
    }
}
