//! AI Model Weight Deduplicator + Conda Tarball Cleaner (`scan_model_duplicates`).
#![allow(dead_code)]
use crate::ai_stack::{mtime_secs, safe_meta, ActiveAiProcesses};
use crate::engine::{CustomCandidate, ScanEngine};
use crate::insights::is_cloud_placeholder;
use crate::model::ScanEntry;
use crate::safety;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, collections::*, fs::Metadata, io::*, path::*, time::*};

pub const DEFAULT_MIN_WEIGHT_BYTES: u64 = 16_777_216;
const CHUNK: u64 = 65_536;
const WEIGHT_EXTS: &str = "gguf|safetensors|pt|pth|ckpt|onnx|bin|ggml|tflite";
const ENV_VARS: &str = "OLLAMA_MODELS|HF_HOME|HUGGINGFACE_HUB_CACHE|TORCH_HOME|CONDA_PKGS_DIRS";
const CONDA_SUBS: &str = "anaconda3/pkgs|miniconda3/pkgs|miniforge3/pkgs";
const HOME_STORES: &str = ".ollama/models|.cache/huggingface/hub|.lmstudio/models|.cache/whisper|.cache/torch/hub/checkpoints|ComfyUI/models|stable-diffusion-webui/models|.conda/pkgs|miniconda3/pkgs|anaconda3/pkgs|miniforge3/pkgs";
const PRUNE_DIRS: &str = ".git|node_modules|__pycache__|$recycle.bin|system volume information";
const STORE_MAP: &str = "ollama:ollama|huggingface:huggingface|models--:huggingface|lmstudio:lmstudio|lm-studio:lmstudio|comfyui:comfyui|stable-diffusion-webui:sd_webui|sd-webui:sd_webui|whisper:whisper|torch:pytorch|conda:conda|miniforge:conda";

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModelDedupParams {
    pub extra_roots: Option<Vec<String>>,
    pub custom_roots_only: Option<bool>,
    pub min_weight_bytes: Option<u64>,
    pub include_conda_archives: Option<bool>,
    pub min_archive_age_hours: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModelDuplicateGroup {
    pub blake3_hash: String,
    pub file_size_bytes: u64,
    pub wasted_bytes: u64,
    pub canonical_path: String,
    pub canonical_store: String,
    pub ssd_tbw_tip: String,
    pub duplicates: Vec<ScanEntry>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModelDedupReport {
    pub scan_id: String,
    pub duration_ms: u64,
    pub roots_scanned: Vec<String>,
    pub hardlinked_groups_skipped: u64,
    pub wasted_bytes: u64,
    pub reclaimable_bytes: u64,
    pub duplicate_groups: Vec<ModelDuplicateGroup>,
    pub conda_archives: Vec<ScanEntry>,
    pub warnings: Vec<String>,
}
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct Wt(bool, i64, usize, PathBuf, u64, &'static str);
type Procs = ActiveAiProcesses;
type DiscOut = (Vec<Wt>, Vec<CustomCandidate>);
type RawGroups = Vec<(String, u64, Vec<Vec<Wt>>)>;

fn open_shared(path: &Path, share: u32) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::share_mode(&mut opts, share);
    #[cfg(not(windows))]
    let _ = share;
    opts.open(path)
}
pub fn physical_file_id(path: &Path, meta: &Metadata) -> Option<(u64, u128)> {
    if is_cloud_placeholder(meta) {
        return None;
    }
    #[cfg(unix)]
    {
        let _ = path;
        use std::os::unix::fs::MetadataExt;
        Some((meta.dev(), u128::from(meta.ino())))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawHandle, RawHandle};
        #[repr(C)]
        #[derive(Copy, Clone, Default)]
        struct Info(u32, [u32; 6], u32, [u32; 3], u32, u32);
        #[link(name = "kernel32")]
        extern "system" {
            fn GetFileInformationByHandle(h: RawHandle, i: *mut Info) -> i32;
        }
        let (f, mut i) = (open_shared(path, 7).ok()?, Info::default());
        // SAFETY: live share_mode(7) handle; Info matches 52-byte BY_HANDLE_FILE_INFORMATION.
        if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut i) } == 0 {
            return None;
        }
        Some((u64::from(i.2), (u128::from(i.4) << 64) | u128::from(i.5)))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, meta);
        None
    }
}
fn hash_blake3(path: &Path, partial_sz: Option<u64>) -> Option<blake3::Hash> {
    let (mut f, mut h) = (open_shared(path, 7).ok()?, blake3::Hasher::new());
    if let Some(sz) = partial_sz {
        let small = sz <= CHUNK * 3;
        let mid = if small { CHUNK } else { (sz - CHUNK) / 2 };
        let end = if small { CHUNK * 2 } else { sz - CHUNK };
        for off in [0, mid, end].into_iter().take_while(|&o| o < sz) {
            f.seek(SeekFrom::Start(off)).ok()?;
            copy(&mut (&mut f).take(CHUNK), &mut h).ok()?;
        }
    } else {
        copy(&mut BufReader::with_capacity(CHUNK as usize, f), &mut h).ok()?;
    }
    Some(h.finalize())
}
fn inspect_weight(path: &Path) -> Option<(&'static str, bool)> {
    let ext = path.extension().and_then(|e| e.to_str());
    let known = ext.is_some_and(|e| WEIGHT_EXTS.split('|').any(|w| w.eq_ignore_ascii_case(e)));
    let p_n = path.parent().and_then(|p| p.file_name());
    let f_n = path.file_name().and_then(|n| n.to_str());
    let blobs = p_n.is_some_and(|n| n.eq_ignore_ascii_case("blobs"));
    let sha = f_n.is_some_and(|n| n.len() > 7 && n[..7].eq_ignore_ascii_case("sha256-"));
    if !(known || blobs && sha) {
        return None;
    }
    let mut s = path.to_string_lossy().into_owned();
    s.make_ascii_lowercase();
    let s = s.replace('\\', "/");
    let mut k = if blobs && sha { "ollama" } else { "custom" };
    if k == "custom" {
        let mut ps = STORE_MAP.split('|').filter_map(|p| p.split_once(':'));
        k = ps.find(|(m, _)| s.contains(m)).map_or("custom", |(_, v)| v);
    }
    Some((k, blobs && (k == "ollama" || k == "huggingface" || sha)))
}
fn is_locked(k: &str, p: &Path, pr: &Procs) -> bool {
    let r = |n| pr.is_running(n);
    pr.is_path_in_use(p)
        || match k {
            "ollama" => r("ollama"),
            "lmstudio" => r("lms") || r("lm studio"),
            "conda" => r("conda") || r("mamba") || r("micromamba"),
            "custom" => false,
            _ => r("python") || r("python3"),
        }
}
pub fn hardlink_command(canon: &Path, dup: &Path) -> String {
    let (c, d) = (canon.display(), dup.display());
    if cfg!(windows) {
        format!("mklink /H \"{d}\" \"{c}\"")
    } else {
        format!("ln -f \"{c}\" \"{d}\"")
    }
}
fn mk_cand(path: PathBuf, sz: u64, mt: Option<i64>, tier: u8, why: String) -> CustomCandidate {
    let (v, r, s) = match tier {
        0 => ("safe_to_delete", "safe", 10),
        1 => ("review", "caution", 45),
        _ => ("blocked", "blocked", 100),
    };
    CustomCandidate {
        kind: "file".into(),
        path,
        size: sz,
        modified: mt,
        category: "model_duplicate".into(),
        verdict: v.into(),
        importance_score: s,
        risk_level: r.into(),
        reasons: vec![why],
    }
}
fn collect_roots(p: &ModelDedupParams, warns: &mut Vec<String>) -> Vec<PathBuf> {
    let mut raw = Vec::new();
    if p.custom_roots_only != Some(true) {
        for v in ENV_VARS.split('|') {
            if let Some(x) = std::env::var_os(v) {
                raw.extend(std::env::split_paths(&x));
            }
        }
        if let Some(h) = dirs::home_dir() {
            HOME_STORES.split('|').for_each(|r| raw.push(h.join(r)));
        }
        let ep = |k| std::env::var_os(k).map(PathBuf::from);
        let bs = [
            dirs::data_local_dir(),
            ep("LOCALAPPDATA"),
            ep("USERPROFILE"),
        ];
        for b in bs.into_iter().flatten() {
            CONDA_SUBS.split('|').for_each(|r| raw.push(b.join(r)));
        }
        raw.retain(|d| safe_meta(d).is_some_and(|m| m.is_dir()));
    }
    for s in p.extra_roots.as_deref().unwrap_or(&[]) {
        let (s, d) = (s.trim(), PathBuf::from(s.trim()));
        if !s.is_empty() && safe_meta(&d).is_some_and(|m| m.is_dir()) {
            raw.push(d);
        } else if !s.is_empty() {
            warns.push(format!("Skipped root: {s}"));
        }
    }
    let mut kd = raw
        .into_iter()
        .map(|d| (safety::normalize(&d), d))
        .collect::<Vec<_>>();
    kd.sort_by_key(|(n, _)| (n.components().count(), n.as_os_str().len()));
    let mut out: Vec<(PathBuf, PathBuf)> = Vec::new();
    for (n, orig) in kd {
        if !out.iter().any(|(a, _)| n.starts_with(a)) {
            out.push((n, orig));
        }
    }
    out.into_iter().map(|(_, d)| d).collect()
}
fn try_conda(ep: PathBuf, m: &Metadata, min_s: u64, pr: &Procs) -> Option<CustomCandidate> {
    let nl = ep.file_name()?.to_string_lossy().to_ascii_lowercase();
    let ok = nl.ends_with(".conda") || nl.ends_with(".tar.bz2");
    if !ok || !m.is_file() || is_cloud_placeholder(m) {
        return None;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    let mt = mtime_secs(m);
    let age = mt.map(|t| now.saturating_sub(t).max(0) as u64)?;
    if age < min_s || open_shared(&ep, 1).is_err() {
        return None;
    }
    let tier = if is_locked("conda", &ep, pr) { 2 } else { 0 };
    let why = format!("Conda archive ({}h old)", age / 3600);
    Some(mk_cand(ep, m.len(), mt, tier, why))
}
fn discover(roots: &[PathBuf], p: &ModelDedupParams, pr: &Procs) -> DiscOut {
    let min_wt = p.min_weight_bytes.unwrap_or(DEFAULT_MIN_WEIGHT_BYTES);
    let inc_conda = p.include_conda_archives.unwrap_or(true);
    let min_s = p.min_archive_age_hours.unwrap_or(24).saturating_mul(3600);
    let (mut weights, mut archs, mut seen) = (Vec::new(), Vec::new(), HashSet::new());
    let mut stack: Vec<(PathBuf, usize)> = roots.iter().map(|r| (r.clone(), 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        if !safe_meta(&dir).is_some_and(|m| m.is_dir()) {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let d_nm = dir.file_name();
        let is_pkgs = d_nm.is_some_and(|n| n.eq_ignore_ascii_case("pkgs"));
        for e in rd.flatten() {
            let ep = e.path();
            let Some(m) = safe_meta(&ep) else { continue };
            let key = safety::lexical_clean(&ep).to_string_lossy().into_owned();
            if is_pkgs {
                if inc_conda {
                    if let Some(c) = try_conda(ep, &m, min_s, pr).filter(|_| seen.insert(key)) {
                        archs.push(c);
                    }
                }
                continue;
            }
            let fnm = e.file_name();
            let skip = PRUNE_DIRS.split('|').any(|x| fnm.eq_ignore_ascii_case(x));
            if m.is_dir() && depth < 12 && !skip {
                stack.push((ep, depth + 1));
            } else if m.is_file() && !is_cloud_placeholder(&m) && m.len() >= min_wt {
                if let Some((st, cb)) = inspect_weight(&ep).filter(|_| seen.insert(key)) {
                    let mt = mtime_secs(&m).unwrap_or(i64::MAX);
                    weights.push(Wt(!cb, mt, ep.as_os_str().len(), ep, m.len(), st));
                }
            }
        }
    }
    archs.sort_by(|a, b| b.size.cmp(&a.size).then(a.path.cmp(&b.path)));
    (weights, archs)
}
fn group_dups(weights: Vec<Wt>) -> (u64, RawGroups) {
    let mut by_sz: BTreeMap<u64, Vec<Wt>> = BTreeMap::new();
    for w in weights {
        by_sz.entry(w.4).or_default().push(w);
    }
    let (mut hl_skip, mut groups) = (0u64, Vec::new());
    for (sz, bucket) in by_sz.into_iter().filter(|(_, b)| b.len() >= 2) {
        let mut phys: BTreeMap<(u64, u128), Vec<Wt>> = BTreeMap::new();
        for w in bucket {
            if let Ok(m) = std::fs::symlink_metadata(&w.3) {
                if let Some(fid) = physical_file_id(&w.3, &m) {
                    phys.entry(fid).or_default().push(w);
                }
            }
        }
        phys.values_mut().for_each(|g| g.sort());
        if phys.len() < 2 {
            hl_skip += u64::from(phys.values().any(|g| g.len() > 1));
            continue;
        }
        let mut by_part: BTreeMap<[u8; 32], Vec<Vec<Wt>>> = BTreeMap::new();
        for u in phys.into_values() {
            if let Some(ph) = hash_blake3(&u[0].3, Some(sz)) {
                by_part.entry(*ph.as_bytes()).or_default().push(u);
            }
        }
        for pu in by_part.into_values().filter(|u| u.len() >= 2) {
            let mut by_full: BTreeMap<String, Vec<Vec<Wt>>> = BTreeMap::new();
            for u in pu {
                if let Some(fh) = hash_blake3(&u[0].3, None) {
                    by_full.entry(fh.to_hex().to_string()).or_default().push(u);
                }
            }
            for (fh, mut fu) in by_full.into_iter().filter(|(_, u)| u.len() >= 2) {
                fu.sort();
                groups.push((fh, sz, fu));
            }
        }
    }
    groups.sort_by_key(|g| (std::cmp::Reverse(g.1 * (g.2.len() - 1) as u64), g.0.clone()));
    (hl_skip, groups)
}
pub fn scan_model_duplicates(e: &ScanEngine, p: impl Borrow<ModelDedupParams>) -> ModelDedupReport {
    scan_inner(e, p.borrow(), None)
}
fn scan_inner(eng: &ScanEngine, p: &ModelDedupParams, ovr: Option<&Procs>) -> ModelDedupReport {
    let (started, mut warns) = (Instant::now(), Vec::new());
    let roots = collect_roots(p, &mut warns);
    let scoped = p.custom_roots_only == Some(true);
    let live = if scoped {
        Procs::detect_scoped(&roots)
    } else {
        Procs::detect_live()
    };
    let procs = ovr.unwrap_or(&live);
    let (weights, arch_cands) = discover(&roots, p, procs);
    let (hardlinked_groups_skipped, raw_groups) = group_dups(weights);
    let mut cands = Vec::new();
    for (hash, sz, units) in &raw_groups {
        let canon = &units[0][0].3;
        for u in &units[1..] {
            let tier = 1 + u8::from(u.iter().any(|e| is_locked(e.5, &e.3, procs)));
            let mt = (u[0].1 != i64::MAX).then_some(u[0].1);
            let hl = hardlink_command(canon, &u[0].3);
            let why = format!("BLAKE3 ({}) == {}; {hl}", &hash[..12], canon.display());
            cands.push(mk_cand(u[0].3.clone(), *sz, mt, tier, why));
        }
    }
    let dup_cand_n = cands.len();
    cands.extend(arch_cands);
    let (dur, has_c) = (started.elapsed().as_millis() as u64, !cands.is_empty());
    let sess = eng.register_custom_session("model_duplicates", cands, warns.clone(), dur, has_c);
    let (mut idx, mut wasted_bytes) = (0usize, 0u64);
    let mut duplicate_groups = Vec::with_capacity(raw_groups.len());
    for (hash, sz, units) in raw_groups {
        let (n_dup, p0) = (units.len() - 1, &units[0][0]);
        let gwaste = sz * n_dup as u64;
        wasted_bytes += gwaste;
        let duplicates = sess.entries[idx..idx + n_dup].to_vec();
        idx += n_dup;
        let tip = "Trash duplicate, then link (`mklink /H` / `ln`) for zero SSD TBW.".into();
        duplicate_groups.push(ModelDuplicateGroup {
            blake3_hash: hash,
            file_size_bytes: sz,
            wasted_bytes: gwaste,
            canonical_path: p0.3.to_string_lossy().into(),
            canonical_store: p0.5.into(),
            ssd_tbw_tip: tip,
            duplicates,
        });
    }
    let ok_sz = |x: &ScanEntry| if x.verdict == "blocked" { 0 } else { x.size };
    let reclaim = sess.entries.iter().map(ok_sz).sum();
    ModelDedupReport {
        scan_id: sess.scan_id.clone(),
        duration_ms: dur,
        roots_scanned: roots.iter().map(|r| r.to_string_lossy().into()).collect(),
        hardlinked_groups_skipped,
        wasted_bytes,
        reclaimable_bytes: reclaim,
        duplicate_groups,
        conda_archives: sess.entries[dup_cand_n..].to_vec(),
        warnings: warns,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DeleteItemRequest, DeleteRequest};
    fn tdir(tag: &str) -> (PathBuf, ModelDedupParams) {
        let d = std::env::temp_dir().join(format!("dc-mcp-md-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = ModelDedupParams {
            extra_roots: Some(vec![d.to_string_lossy().into()]),
            custom_roots_only: Some(true),
            min_weight_bytes: Some(1024),
            ..Default::default()
        };
        (d, p)
    }
    fn mkf(p: &Path, b: u8, n: usize, age_h: u64) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, vec![b; n]).unwrap();
        if age_h > 0 {
            let ts = SystemTime::now() - Duration::from_secs(age_h * 3600);
            let ft = std::fs::FileTimes::new().set_modified(ts);
            let f = std::fs::File::options().write(true).open(p).unwrap();
            f.set_times(ft).unwrap();
        }
    }
    #[test]
    fn test_ollama_blob_vs_lmstudio_gguf_canonical() {
        let (dir, p) = tdir("ollama-lms");
        let blob = dir.join("ollama").join("blobs").join("sha256-abcdef");
        mkf(&dir.join("lmstudio/models/m.gguf"), 0x42, 4096, 0);
        mkf(&blob, 0x42, 4096, 0);
        let eng = ScanEngine::new();
        let rep = scan_model_duplicates(&eng, &p);
        assert_eq!((rep.duplicate_groups.len(), rep.wasted_bytes), (1, 4096));
        let grp = &rep.duplicate_groups[0];
        let d0 = &grp.duplicates[0];
        assert_eq!(Path::new(&grp.canonical_path), blob);
        assert_eq!(d0.verdict, "review");
        let it = DeleteItemRequest {
            path: d0.path.clone(),
            approval_token: d0.approval_token.clone(),
        };
        let del = eng.delete(&DeleteRequest {
            scan_id: rep.scan_id,
            items: vec![it],
            permanent: false,
            confirm_permanent: false,
            confirm_risk: true,
            dry_run: true,
        });
        assert_eq!((del.dry_run, del.rejected), (1, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn test_same_size_last_byte_and_mid_gap_diff() {
        let (dir, p) = tdir("diff");
        let base = vec![0xABu8; 256 * 1024];
        let (mut last_d, mut gap_d) = (base.clone(), base.clone());
        *last_d.last_mut().unwrap() = 0xCD;
        gap_d[70_000] = 0xEF;
        std::fs::write(dir.join("a.safetensors"), &base).unwrap();
        std::fs::write(dir.join("b.safetensors"), &last_d).unwrap();
        std::fs::write(dir.join("c.safetensors"), &gap_d).unwrap();
        let rep = scan_model_duplicates(&ScanEngine::new(), p);
        assert_eq!((rep.duplicate_groups.len(), rep.wasted_bytes), (0, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn test_real_os_hardlink_zero_wasted_bytes() {
        let (dir, p) = tdir("hardlink");
        let (src, dst) = (dir.join("hf/blobs/w.pt"), dir.join("hf/snap/w.pt"));
        mkf(&src, 0x77, 8192, 0);
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::hard_link(&src, &dst).unwrap();
        let eng = ScanEngine::new();
        let rep = scan_model_duplicates(&eng, &p);
        assert_eq!((rep.wasted_bytes, rep.hardlinked_groups_skipped), (0, 1));
        assert!(rep.duplicate_groups.is_empty());
        assert_eq!(serde_json::to_value(&rep).unwrap()["wastedBytes"], 0);
        assert!(eng.get_session(&rep.scan_id).unwrap().entries.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn test_conda_tarballs_safe_extracted_untouched() {
        let (dir, p) = tdir("conda");
        mkf(&dir.join("pkgs/pytorch-2.5.conda"), 0x11, 2048, 48);
        mkf(&dir.join("pkgs/cuda.tar.bz2"), 0x11, 2048, 48);
        mkf(&dir.join("pkgs/fresh.conda"), 0x11, 2048, 0);
        mkf(&dir.join("pkgs/extracted_pkg_dir/lib.so"), 0x11, 2048, 48);
        let eng = ScanEngine::new();
        let rep = scan_model_duplicates(&eng, &p);
        let ca = &rep.conda_archives;
        assert_eq!(ca.len(), 2);
        assert!(ca.iter().all(|a| a.verdict == "safe_to_delete"));
        let se = &eng.get_session(&rep.scan_id).unwrap().entries;
        assert!(se.iter().all(|e| !e.path.contains("extracted_pkg_dir")));
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn test_live_process_lock_and_overlapping_roots() {
        let (dir, mut p) = tdir("lock");
        let c = dir.join("ollama/blobs/sha256-99");
        mkf(&c, 0x55, 4096, 0);
        mkf(&dir.join("lmstudio/models/a.gguf"), 0x55, 4096, 0);
        let sub = c.parent().unwrap().to_string_lossy().into_owned();
        p.extra_roots = Some(vec![dir.to_string_lossy().into(), sub]);
        assert_eq!(collect_roots(&p, &mut Vec::new()).len(), 1);
        let rep = scan_inner(&ScanEngine::new(), &p, Some(&Procs::from_names(&["lms"])));
        assert_eq!(rep.duplicate_groups[0].duplicates[0].verdict, "blocked");
        assert_eq!(rep.reclaimable_bytes, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
