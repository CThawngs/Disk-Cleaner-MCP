//! AI-Stack Surgical Cleaner + Anti-Suicide Live Process Guard (`v0.6.0`).

use crate::engine::CustomCandidate;
use crate::safety;
use crate::smart_scan::{bump_mtime, measure_dir_safe, DirStats};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const IDES: &[&str] = &["Cursor", "Code", "Windsurf", "Antigravity"];
const IDE_SUBS: &str = "CachedExtensionVSIXs|GPUCache|Code Cache|CachedData";
const PW_FAMS: &str = "chromium|chromium_headless_shell|chromium-tip-of-tree|firefox|firefox-beta|webkit|ffmpeg|winldd";

pub type Units = Vec<RawCleanupUnit>;

#[derive(Debug, Clone)]
pub struct RawCleanupUnit {
    pub unit_id: String,
    pub group: String,
    pub label: String,
    pub file_count: u64,
    pub in_use: bool,
    pub cand: CustomCandidate,
}

impl RawCleanupUnit {
    pub fn dir(s: &str, lbl: String, p: PathBuf, st: DirStats, why: &str) -> Self {
        Self::mk(s, lbl, "dir", p, st.bytes, st.files, st.mtime, why)
    }

    pub fn file(s: &str, lbl: String, p: PathBuf, m: &std::fs::Metadata, why: &str) -> Self {
        Self::mk(s, lbl, "file", p, m.len(), 1, mtime_secs(m), why)
    }

    #[allow(clippy::too_many_arguments)]
    fn mk(
        s: &str,
        label: String,
        k: &str,
        path: PathBuf,
        sz: u64,
        fc: u64,
        mt: Option<i64>,
        why: &str,
    ) -> Self {
        let p: Vec<&str> = s.splitn(3, '|').collect();
        let hex = blake3::hash(path.to_string_lossy().as_bytes()).to_hex();
        let cand = CustomCandidate {
            kind: k.into(),
            path,
            size: sz,
            modified: mt,
            category: p[2].into(),
            verdict: "safe_to_delete".into(),
            importance_score: 10,
            risk_level: "safe".into(),
            reasons: vec![why.into()],
        };
        let (unit_id, group) = (format!("{}-{}", p[0], &hex[..10]), p[1].into());
        Self {
            unit_id,
            group,
            label,
            file_count: fc,
            in_use: false,
            cand,
        }
    }

    pub fn into_review(mut self, score: u8) -> Self {
        if !self.in_use {
            (self.cand.verdict, self.cand.risk_level) = ("review".into(), "caution".into());
            self.cand.importance_score = score;
        }
        self
    }

    pub fn with_lock(mut self, locked: bool, reason: &str) -> Self {
        if locked {
            self.in_use = true;
            (self.cand.verdict, self.cand.risk_level) = ("blocked".into(), "blocked".into());
            (self.cand.importance_score, self.cand.reasons) = (100, vec![reason.into()]);
        }
        self
    }
}

fn ai_dir(pfx: &str, lbl: String, p: PathBuf, st: DirStats, why: &str) -> RawCleanupUnit {
    RawCleanupUnit::dir(&format!("{pfx}|ai_stack|ml_cache"), lbl, p, st, why)
}

fn ai_file(pfx: &str, lbl: String, p: PathBuf, m: &std::fs::Metadata, why: &str) -> RawCleanupUnit {
    RawCleanupUnit::file(&format!("{pfx}|ai_stack|ml_cache"), lbl, p, m, why)
}

#[derive(Debug, Clone, Default)]
pub struct ActiveAiProcesses {
    names: HashSet<String>,
    exes: Vec<PathBuf>,
}

impl ActiveAiProcesses {
    pub fn detect_live() -> Self {
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
        );
        let mut s = Self::default();
        for p in sys.processes().values() {
            let raw = p.name().to_string_lossy().to_lowercase();
            s.names
                .insert(raw.strip_suffix(".exe").unwrap_or(&raw).into());
            if let Some(exe) = p.exe() {
                s.exes.push(safety::normalize(exe));
            }
        }
        s
    }

    pub fn detect_scoped(roots: &[PathBuf]) -> Self {
        let norm: Vec<PathBuf> = roots.iter().map(|r| safety::normalize(r)).collect();
        let mut s = Self {
            names: HashSet::new(),
            exes: Self::detect_live().exes,
        };
        s.exes.retain(|e| norm.iter().any(|r| e.starts_with(r)));
        s
    }

    #[cfg(test)]
    pub fn from_names(list: &[&str]) -> Self {
        let mut s = Self::default();
        list.iter().for_each(|x| {
            s.names
                .insert(x.to_lowercase().trim_end_matches(".exe").into());
        });
        s
    }

    pub fn is_running(&self, key: &str) -> bool {
        let k = key.to_lowercase();
        let alt = (k == "code" && self.names.contains("code - insiders"))
            || (k == "ollama" && self.names.contains("ollama_llama_server"));
        self.names.contains(&k) || alt || self.exes.iter().any(|p| p.to_string_lossy().contains(&k))
    }

    pub fn is_path_in_use(&self, target: &Path) -> bool {
        let norm = safety::normalize(target);
        self.exes.iter().any(|e| e.starts_with(&norm))
    }
}

pub fn is_symlink_or_junction(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    if std::os::windows::fs::MetadataExt::file_attributes(meta) & 0x400 != 0 {
        return true;
    }
    meta.file_type().is_symlink()
}

pub fn safe_meta(p: &Path) -> Option<std::fs::Metadata> {
    if safety::sensitive_never_touch_reason(p).is_some() || safety::is_protected(p) {
        return None;
    }
    let m = std::fs::symlink_metadata(p).ok()?;
    (!is_symlink_or_junction(&m)).then_some(m)
}

pub fn mtime_secs(meta: &std::fs::Metadata) -> Option<i64> {
    Some(
        meta.modified()
            .ok()?
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs() as i64,
    )
}

pub fn rd_vec(p: &Path) -> Vec<std::fs::DirEntry> {
    std::fs::read_dir(p).map_or_else(|_| Vec::new(), |rd| rd.flatten().collect())
}

pub fn scan_host_ai_stack(act: &ActiveAiProcesses, warns: &mut Vec<String>) -> Units {
    let (mut out, mut seen) = (Vec::new(), HashSet::new());
    let (home, cache, loc) = (dirs::home_dir(), dirs::cache_dir(), dirs::data_local_dir());
    let j = |b: &Option<PathBuf>, r: &str| b.as_ref().map(|p| p.join(r));
    let mut take =
        |o: Option<PathBuf>| o.filter(|d| seen.insert(safety::normalize(d)) && d.is_dir());
    for d in [
        env_dir("HUGGINGFACE_HUB_CACHE"),
        j(&env_dir("HF_HOME"), "hub"),
        j(&home, ".cache/huggingface/hub"),
        j(&cache, "huggingface/hub"),
    ]
    .into_iter()
    .filter_map(&mut take)
    {
        scan_hf_hub_dir(&d, act, &mut out);
    }
    for d in [env_dir("OLLAMA_MODELS"), j(&home, ".ollama/models")]
        .into_iter()
        .filter_map(&mut take)
    {
        scan_ollama_dir(&d, act, warns, &mut out);
    }
    for d in [
        env_dir("PLAYWRIGHT_BROWSERS_PATH"),
        j(&loc, "ms-playwright"),
        j(&cache, "ms-playwright"),
        j(&home, "Library/Caches/ms-playwright"),
        j(&home, ".cache/ms-playwright"),
    ]
    .into_iter()
    .filter_map(&mut take)
    {
        scan_playwright_dir(&d, act, &mut out);
    }
    if let Some(cfg) = dirs::config_dir() {
        IDES.iter().for_each(|&app| {
            if let Some(p) = take(Some(cfg.join(app))) {
                scan_ai_ide_dir(&p, app, act, &mut out);
            }
        });
    }
    if let Some(oc) = take(j(&cache, "opencode")) {
        push_ide_sub(&oc, "OpenCode", "cache", act, &mut out);
    }
    out
}

pub fn scan_custom_ai_root(
    root: &Path,
    act: &ActiveAiProcesses,
    warns: &mut Vec<String>,
) -> (Units, Vec<PathBuf>) {
    let (mut units, mut cov) = (Vec::new(), Vec::new());
    let rel = |s: &str| {
        if s.is_empty() {
            root.to_path_buf()
        } else {
            root.join(s)
        }
    };
    for c in ["", "huggingface/hub", "hub"].map(rel) {
        if rd_vec(&c).iter().any(|e| {
            let n = e.file_name().to_string_lossy().to_lowercase();
            n.starts_with("models--") || n.starts_with("datasets--") || n.ends_with(".incomplete")
        }) {
            scan_hf_hub_dir(&c, act, &mut units);
            cov.push(c);
        }
    }
    for c in ["", "ollama/models", "ollama"].map(rel) {
        if c.join("blobs").is_dir() || c.join("manifests").is_dir() {
            scan_ollama_dir(&c, act, warns, &mut units);
            cov.push(c);
        }
    }
    for c in ["", "ms-playwright"].map(rel) {
        if rd_vec(&c)
            .iter()
            .any(|e| parse_pw_rev(&e.file_name().to_string_lossy()).is_some())
        {
            scan_playwright_dir(&c, act, &mut units);
            cov.push(c);
        }
    }
    for &app in IDES {
        let d = root.join(app);
        if d.is_dir() {
            scan_ai_ide_dir(&d, app, act, &mut units);
            cov.push(d);
        }
    }
    (units, cov)
}

pub fn scan_hf_hub_dir(hub_dir: &Path, act: &ActiveAiProcesses, out: &mut Units) {
    for entry in rd_vec(hub_dir) {
        let p = entry.path();
        let Some(m) = safe_meta(&p) else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        if m.is_file() && name.ends_with(".incomplete") {
            push_hf_inc(&p, &m, act, out);
        } else if m.is_dir()
            && "models--|datasets--|spaces--"
                .split('|')
                .any(|k| name.starts_with(k))
        {
            let (mut st, mut stack) = (DirStats::default(), vec![p.clone()]);
            while let Some(d) = stack.pop() {
                for sub in rd_vec(&d) {
                    let sp = sub.path();
                    let Some(sm) = safe_meta(&sp) else { continue };
                    if sm.is_dir() {
                        stack.push(sp);
                    } else if sm.is_file()
                        && sub.file_name().to_string_lossy().ends_with(".incomplete")
                    {
                        push_hf_inc(&sp, &sm, act, out);
                    } else if sm.is_file() {
                        (st.bytes, st.files) = (st.bytes.saturating_add(sm.len()), st.files + 1);
                        bump_mtime(&mut st.mtime, &sm);
                    }
                }
            }
            if st.bytes > 0 && p.join("snapshots").is_dir() {
                let lbl = format!("HF repo ({name})");
                let u = ai_dir("hf-repo", lbl, p.clone(), st, "HF snapshot").into_review(55);
                out.push(u.with_lock(act.is_path_in_use(&p), "Anti-Suicide: repo in use"));
            }
        }
    }
}

fn push_hf_inc(p: &Path, m: &std::fs::Metadata, act: &ActiveAiProcesses, out: &mut Units) {
    let lbl = format!(
        "HF incomplete ({})",
        p.file_name().unwrap_or_default().to_string_lossy()
    );
    let mut u = ai_file("hf-inc", lbl, p.into(), m, "HF *.incomplete");
    u.cand.importance_score = 5;
    out.push(u.with_lock(act.is_path_in_use(p), "Anti-Suicide: file in use"));
}

pub fn scan_ollama_dir(
    dir: &Path,
    act: &ActiveAiProcesses,
    warns: &mut Vec<String>,
    out: &mut Units,
) {
    let blobs = dir.join("blobs");
    if !blobs.is_dir() {
        return;
    }
    let refs = match read_ollama_digests(&dir.join("manifests")) {
        Ok(r) => r,
        Err(msg) => return warns.push(msg),
    };
    let busy = act.is_running("ollama");
    for entry in rd_vec(&blobs) {
        let p = entry.path();
        let Some(m) = safe_meta(&p) else { continue };
        let fname = entry.file_name().to_string_lossy().into_owned();
        let norm = fname.to_lowercase().replace(':', "-");
        if m.is_file() && norm.starts_with("sha256-") && !refs.contains(&norm) {
            let lbl = format!("Ollama orphan ({})", &fname[..fname.len().min(20)]);
            let u = ai_file("ollama-blob", lbl, p.clone(), &m, "Orphan blob").into_review(35);
            out.push(u.with_lock(
                busy || act.is_path_in_use(&p),
                "Anti-Suicide: ollama active",
            ));
        }
    }
}

fn read_ollama_digests(mf_dir: &Path) -> Result<HashSet<String>, String> {
    let bad = |s: String| Err(format!("Ollama {s}; fail-closed."));
    if !mf_dir.is_dir() {
        return bad(format!("manifests missing ({})", mf_dir.display()));
    }
    let io_e = |op: &str, e: std::io::Error| format!("Ollama {op} error: {e}; fail-closed.");
    let (mut refs, mut stack) = (HashSet::new(), vec![mf_dir.to_path_buf()]);
    while let Some(dir) = stack.pop() {
        for item in std::fs::read_dir(&dir).map_err(|e| io_e("read", e))? {
            let p = item.map_err(|e| io_e("walk", e))?.path();
            let m = std::fs::symlink_metadata(&p).map_err(|e| io_e("stat", e))?;
            if is_symlink_or_junction(&m) {
                continue;
            }
            if m.is_dir() {
                stack.push(p);
            } else if m.is_file() {
                let fn_l = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase();
                if matches!(fn_l.as_str(), ".ds_store" | "thumbs.db" | "desktop.ini") {
                    continue;
                }
                let raw = std::fs::read_to_string(&p).map_err(|e| io_e("file", e))?;
                let v: Value = serde_json::from_str(&raw)
                    .map_err(|e| format!("Corrupt JSON: {e}; fail-closed."))?;
                if !v.is_object()
                    || !"layers|manifests|config"
                        .split('|')
                        .any(|k| v.get(k).is_some())
                {
                    return bad(format!("invalid manifest ({})", p.display()));
                }
                collect_digests(&v, &mut refs);
            }
        }
    }
    Ok(refs)
}

fn collect_digests(val: &Value, out: &mut HashSet<String>) {
    match val {
        Value::String(s) if s.trim().to_lowercase().starts_with("sha256") => {
            out.insert(s.trim().to_lowercase().replace(':', "-"));
        }
        Value::Array(a) => a.iter().for_each(|v| collect_digests(v, out)),
        Value::Object(m) => m.values().for_each(|v| collect_digests(v, out)),
        _ => {}
    }
}

fn parse_pw_rev(name: &str) -> Option<(String, u64)> {
    let (fam, rev) = name.rsplit_once('-')?;
    let fl = fam.to_lowercase();
    (!rev.is_empty()
        && rev.chars().all(|c| c.is_ascii_digit())
        && PW_FAMS.split('|').any(|f| f == fl))
    .then(|| rev.parse().ok().map(|r| (fl, r)))?
}

pub fn scan_playwright_dir(pw_dir: &Path, act: &ActiveAiProcesses, out: &mut Units) {
    let mut fams: BTreeMap<String, Vec<(u64, PathBuf)>> = BTreeMap::new();
    for e in rd_vec(pw_dir) {
        let p = e.path();
        if safe_meta(&p).is_some_and(|m| m.is_dir()) {
            if let Some((fam, rev)) = parse_pw_rev(&e.file_name().to_string_lossy()) {
                fams.entry(fam).or_default().push((rev, p));
            }
        }
    }
    for (fam, mut revs) in fams {
        revs.sort_by_key(|b| std::cmp::Reverse(b.0));
        let Some(&(top, _)) = revs.first() else {
            continue;
        };
        for (old, p) in revs.into_iter().skip(1) {
            let st = measure_dir_safe(&p, 50_000);
            if !st.sensitive && (st.bytes > 0 || st.files > 0) {
                let (lbl, why) = (
                    format!("Playwright {fam}-{old}"),
                    format!("Superseded by r{top}"),
                );
                let u = ai_dir("pw-rev", lbl, p.clone(), st, &why);
                out.push(u.with_lock(act.is_path_in_use(&p), "Anti-Suicide: Playwright active"));
            }
        }
    }
}

pub fn scan_ai_ide_dir(dir: &Path, app: &str, act: &ActiveAiProcesses, out: &mut Units) {
    IDE_SUBS
        .split('|')
        .for_each(|sub| push_ide_sub(&dir.join(sub), app, sub, act, out));
}

fn push_ide_sub(p: &Path, app: &str, sub: &str, act: &ActiveAiProcesses, out: &mut Units) {
    if safe_meta(p).is_some_and(|m| m.is_dir()) {
        let st = measure_dir_safe(p, 50_000);
        if !st.sensitive && (st.bytes > 0 || st.files > 0) {
            let locked = act.is_running(app) || act.is_path_in_use(p);
            let lbl = format!("{app} {sub}");
            let u = ai_dir("ide-cache", lbl, p.into(), st, "IDE cache");
            out.push(u.with_lock(locked, &format!("Anti-Suicide: {app} active")));
        }
    }
}

fn env_dir(var: &str) -> Option<PathBuf> {
    let v = std::env::var(var).ok()?;
    (!v.trim().is_empty() && v.trim() != "0").then(|| PathBuf::from(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sbx(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("dcm-ai-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn wr(p: PathBuf, data: &[u8]) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    #[test]
    fn test_hf_incomplete_vs_valid_snapshot() {
        let root = sbx("hf");
        let repo = root.join("models--meta--llama");
        std::fs::create_dir_all(repo.join("snapshots/main")).unwrap();
        wr(repo.join("blobs/sha256-valid"), &[1u8; 2048]);
        wr(repo.join("blobs/sha256-part.incomplete"), &[2u8; 512]);
        let mut out = Vec::new();
        scan_hf_hub_dir(&root, &ActiveAiProcesses::default(), &mut out);
        assert_eq!(out.len(), 2);
        assert!(out
            .iter()
            .any(|u| u.cand.verdict == "safe_to_delete" && u.cand.size == 512));
        assert!(out
            .iter()
            .any(|u| u.cand.verdict == "review" && u.cand.size == 2048));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_ollama_orphan_active_lock_and_fail_closed() {
        let root = sbx("ollama");
        wr(root.join("blobs/sha256-aaaa"), &[0u8; 1000]);
        wr(root.join("blobs/sha256-bbbb"), &[0u8; 2500]);
        wr(
            root.join("manifests/lib/latest"),
            br#"{"schemaVersion":2,"config":{"digest":"sha256:aaaa"},"layers":[]}"#,
        );
        let (mut out, mut w, mut locked) = (Vec::new(), Vec::new(), Vec::new());
        let idle = ActiveAiProcesses::default();
        scan_ollama_dir(&root, &idle, &mut w, &mut out);
        assert!(w.is_empty() && out.len() == 1 && out[0].cand.verdict == "review");
        scan_ollama_dir(
            &root,
            &ActiveAiProcesses::from_names(&["ollama"]),
            &mut w,
            &mut locked,
        );
        assert!(locked[0].in_use && locked[0].cand.verdict == "blocked");
        wr(root.join("manifests/lib/broken"), b"{corrupt");
        let (mut fc_o, mut fc_w) = (Vec::new(), Vec::new());
        scan_ollama_dir(&root, &idle, &mut fc_w, &mut fc_o);
        assert!(fc_o.is_empty() && !fc_w.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_playwright_revisions_and_ide_anti_suicide() {
        let root = sbx("pw-ide");
        let pw = root.join("ms-playwright");
        for sub in ["chromium-1091", "chromium-1148", "webkit-2104"] {
            wr(pw.join(sub).join("b.bin"), &[1u8; 600]);
        }
        let (mut pw_out, idle) = (Vec::new(), ActiveAiProcesses::default());
        scan_playwright_dir(&pw, &idle, &mut pw_out);
        assert!(pw_out.len() == 1 && pw_out[0].cand.path.ends_with("chromium-1091"));
        let cur = root.join("Cursor");
        wr(cur.join("GPUCache/d0"), &[7u8; 300]);
        wr(cur.join("User/globalStorage/state.vscdb"), b"keep");
        let (mut c_idle, mut c_busy) = (Vec::new(), Vec::new());
        scan_ai_ide_dir(&cur, "Cursor", &idle, &mut c_idle);
        assert!(c_idle.len() == 1 && c_idle[0].cand.verdict == "safe_to_delete");
        scan_ai_ide_dir(
            &cur,
            "Cursor",
            &ActiveAiProcesses::from_names(&["cursor.exe"]),
            &mut c_busy,
        );
        assert!(c_busy[0].in_use && c_busy[0].cand.verdict == "blocked");
        let _ = std::fs::remove_dir_all(&root);
    }
}
