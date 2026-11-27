//! Large & Forgotten Files scanner (`find_large_forgotten`).
//! Walks user directories via `jwalk` with aggressive cache/VCS/bundle pruning,
//! skips Cloud-Only placeholders and Never-Touch / system-protected paths,
//! groups into semantic kinds, and registers a `ScanSession` (`verdict: "review"`).

#![allow(dead_code)]

use crate::engine::{CustomCandidate, ScanEngine};
use crate::insights::is_cloud_placeholder;
use crate::safety;
use jwalk::{Parallelism, WalkDirGeneric};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const DEFAULT_MIN_LARGE_BYTES: u64 = 104_857_600; // 100 MiB
const DEFAULT_MAX_RESULTS: usize = 100;
const MAX_SESSION_CANDIDATES: usize = 2_000;

const PRUNE_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "target",
    "Library",
    "AppData",
    ".cache",
    "__pycache__",
    "$Recycle.Bin",
    "System Volume Information",
    ".cargo",
    ".rustup",
    ".npm",
    ".pnpm-store",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LargeFilesParams {
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub min_size: Option<u64>,
    #[serde(default)]
    pub unused_days: Option<u64>,
    #[serde(default)]
    pub max_results: Option<usize>,
    #[serde(default)]
    pub kind_filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KindSummary {
    pub semantic_kind: String,
    pub file_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LargeFileItem {
    pub path: String,
    pub size_bytes: u64,
    pub semantic_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessed: Option<i64>,
    pub unused_days: u64,
    pub access_time_reliable: bool,
    pub category: String,
    pub verdict: String,
    pub approval_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LargeFilesReport {
    pub scan_id: String,
    pub root: String,
    pub min_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unused_days_filter: Option<u64>,
    pub access_time_reliable: bool,
    pub total_matched_files: u64,
    pub total_matched_bytes: u64,
    pub truncated: bool,
    pub by_kind: Vec<KindSummary>,
    pub files: Vec<LargeFileItem>,
    pub warnings: Vec<String>,
    pub duration_ms: u64,
}

pub fn classify_semantic_kind(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase());
    match ext.as_deref().unwrap_or("") {
        "mp4" | "mkv" | "mov" | "avi" | "webm" | "wmv" | "flv" | "m4v" | "mpeg" | "mpg" | "ts"
        | "mts" | "3gp" => "video",
        "zip" | "rar" | "7z" | "tar" | "gz" | "tgz" | "bz2" | "tbz2" | "xz" | "txz" | "zst"
        | "lz4" | "cab" => "archive",
        "msi" | "exe" | "pkg" | "deb" | "rpm" | "appimage" | "msix" | "msixbundle" | "apk"
        | "ipa" => "installer",
        "gguf" | "safetensors" | "ckpt" | "pt" | "pth" | "onnx" | "bin" | "tflite" | "h5"
        | "keras" | "pb" => "ml_model",
        "iso" | "dmg" | "vhdx" | "vhd" | "vmdk" | "qcow2" | "img" | "ova" | "wim"
        | "sparseimage" => "disk_image",
        "wav" | "flac" | "mp3" | "aac" | "m4a" | "ogg" | "opus" | "wma" | "aiff" | "alac" => {
            "audio"
        }
        "psd" | "psb" | "cr2" | "cr3" | "nef" | "arw" | "dng" | "tiff" | "tif" | "bmp" | "png"
        | "jpg" | "jpeg" | "webp" | "heic" | "exr" | "svg" => "image",
        "pdf" | "docx" | "doc" | "pptx" | "ppt" | "xlsx" | "xls" | "csv" | "parquet" | "sqlite"
        | "db" | "epub" | "indd" | "ai" => "document",
        _ => "other",
    }
}

fn has_cache_marker(dir: &Path) -> bool {
    dir.join("CACHEDIR.TAG").is_file() || dir.join("pyvenv.cfg").is_file()
}

fn should_prune_dir(name: &str, path: &Path) -> bool {
    let l = name.to_ascii_lowercase();
    l.ends_with(".app")
        || l.ends_with(".photoslibrary")
        || PRUNE_DIRS.iter().any(|s| s.eq_ignore_ascii_case(name))
        || has_cache_marker(path)
}

pub fn detect_atime_reliable(root: &Path) -> bool {
    #[cfg(windows)]
    {
        let _ = root;
        use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
        let sub = "SYSTEM\\CurrentControlSet\\Control\\FileSystem";
        if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(sub) {
            if let Ok(v) = k.get_value::<u32, _>("NtfsDisableLastAccessUpdate") {
                return !matches!(v & 0x3, 1 | 3);
            }
        }
        true
    }
    #[cfg(target_os = "linux")]
    {
        let canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let r = canon.to_string_lossy();
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
            let mut best = (0usize, false);
            for line in mounts.lines() {
                let p: Vec<&str> = line.split_whitespace().collect();
                if p.len() >= 4 && r.starts_with(p[1]) && p[1].len() >= best.0 {
                    best = (p[1].len(), p[3].split(',').any(|o| o == "noatime"));
                }
            }
            return !best.1;
        }
        true
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = root;
        true
    }
}

fn to_epoch(st: std::io::Result<SystemTime>) -> Option<i64> {
    st.ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

struct MatchedFile {
    path: PathBuf,
    size_bytes: u64,
    kind: &'static str,
    ext: Option<String>,
    modified: Option<i64>,
    accessed: Option<i64>,
    unused_days: u64,
    atime_ok: bool,
}

pub fn find_large_forgotten(engine: &ScanEngine, params: &LargeFilesParams) -> LargeFilesReport {
    let started = Instant::now();
    let min_size = params.min_size.unwrap_or(DEFAULT_MIN_LARGE_BYTES);
    let max_results = params
        .max_results
        .unwrap_or(DEFAULT_MAX_RESULTS)
        .clamp(1, 1_000);
    let kind_filter = params
        .kind_filter
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    let root_path = params
        .root
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .or_else(dirs::download_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    let root_str = root_path.to_string_lossy().to_string();
    let mut warnings = Vec::new();
    let host_atime = root_path.is_dir() && detect_atime_reliable(&root_path);
    let mut matched = Vec::new();

    if !root_path.is_dir() {
        warnings.push(format!(
            "Scan root does not exist or is not a directory: {root_str}"
        ));
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let busy_timeout = std::time::Duration::from_secs(10);
        let walker = WalkDirGeneric::<((), ())>::new(&root_path)
            .follow_links(false)
            .max_depth(20)
            .sort(false)
            .parallelism(Parallelism::RayonDefaultPool { busy_timeout })
            .process_read_dir(|depth, dir_path, _st, children| {
                if depth.unwrap_or(0) > 0 && has_cache_marker(dir_path) {
                    children.clear();
                    return;
                }
                children.retain(|res| {
                    let Ok(e) = res else { return true };
                    if e.file_type().is_symlink() {
                        return false;
                    }
                    let name = e.file_name().to_string_lossy();
                    !(e.file_type().is_dir() && should_prune_dir(&name, &e.path()))
                });
            });

        for res in walker {
            let entry = match res {
                Ok(e) => e,
                Err(e) => {
                    if warnings.len() < 20 {
                        warnings.push(format!("Walk warning: {e}"));
                    }
                    continue;
                }
            };
            if entry.depth == 0 || !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if safety::sensitive_never_touch_reason(&path).is_some() || safety::is_protected(&path)
            {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() || !meta.is_file() || is_cloud_placeholder(&meta) {
                continue;
            }
            let size_bytes = meta.len();
            if size_bytes < min_size {
                continue;
            }
            let kind = classify_semantic_kind(&path);
            if kind_filter.as_deref().is_some_and(|kf| kf != kind) {
                continue;
            }
            let modified = to_epoch(meta.modified());
            let accessed = to_epoch(meta.accessed()).filter(|&a| a > 946_684_800);
            let atime_ok =
                host_atime && accessed.is_some_and(|a| modified.is_none_or(|m| a + 60 >= m));
            let ref_ts = if atime_ok {
                accessed
                    .zip(modified)
                    .map(|(a, m)| a.max(m))
                    .or(accessed)
                    .or(modified)
            } else {
                modified.or(accessed)
            };
            let unused_days =
                ref_ts.map_or(0, |ts| (now.saturating_sub(ts).max(0) as u64) / 86_400);
            if params.unused_days.is_some_and(|min_d| unused_days < min_d) {
                continue;
            }
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase());
            matched.push(MatchedFile {
                path,
                size_bytes,
                kind,
                ext,
                modified,
                accessed,
                unused_days,
                atime_ok,
            });
        }
    }

    matched.sort_by(|a, b| {
        b.size_bytes
            .cmp(&a.size_bytes)
            .then(b.unused_days.cmp(&a.unused_days))
            .then(a.path.cmp(&b.path))
    });

    let total_matched_files = matched.len() as u64;
    let total_matched_bytes: u64 = matched.iter().map(|m| m.size_bytes).sum();
    let mut kind_map: BTreeMap<&'static str, (u64, u64)> = BTreeMap::new();
    for m in &matched {
        let slot = kind_map.entry(m.kind).or_insert((0, 0));
        slot.0 += 1;
        slot.1 = slot.1.saturating_add(m.size_bytes);
    }
    let mut by_kind: Vec<KindSummary> = kind_map
        .into_iter()
        .map(|(k, (file_count, total_bytes))| KindSummary {
            semantic_kind: k.into(),
            file_count,
            total_bytes,
        })
        .collect();
    by_kind.sort_by_key(|k| std::cmp::Reverse(k.total_bytes));

    let truncated = matched.len() > max_results;
    let candidates: Vec<CustomCandidate> = matched
        .iter()
        .take(MAX_SESSION_CANDIDATES)
        .map(|m| CustomCandidate {
            kind: "file".into(),
            path: m.path.clone(),
            size: m.size_bytes,
            modified: m.modified,
            category: "large_forgotten".into(),
            verdict: "review".into(),
            importance_score: 45,
            risk_level: "caution".into(),
            reasons: vec![format!(
                "Large {} file (unused ~{}d)",
                m.kind, m.unused_days
            )],
        })
        .collect();

    let duration_ms = started.elapsed().as_millis() as u64;
    let persist = !matched.is_empty();
    let session = engine.register_custom_session(
        "large_forgotten",
        candidates,
        warnings.clone(),
        duration_ms,
        persist,
    );
    let take_n = max_results.min(session.entries.len());
    let files = matched[..take_n]
        .iter()
        .zip(session.entries[..take_n].iter())
        .map(|(m, e)| LargeFileItem {
            path: e.path.clone(),
            size_bytes: m.size_bytes,
            semantic_kind: m.kind.into(),
            extension: m.ext.clone(),
            modified: m.modified,
            accessed: m.accessed,
            unused_days: m.unused_days,
            access_time_reliable: m.atime_ok,
            category: e.category.clone(),
            verdict: e.verdict.clone(),
            approval_token: e.approval_token.clone(),
        })
        .collect();

    LargeFilesReport {
        scan_id: session.scan_id.clone(),
        root: root_str,
        min_size,
        unused_days_filter: params.unused_days,
        access_time_reliable: host_atime,
        total_matched_files,
        total_matched_bytes,
        truncated,
        by_kind,
        files,
        warnings,
        duration_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DeleteItemRequest, DeleteRequest};
    use std::time::Duration;

    #[test]
    fn test_classify_semantic_kinds() {
        let cases = [
            ("movie.mkv", "video"),
            ("backup.tar.zst", "archive"),
            ("setup.msi", "installer"),
            ("llama3.gguf", "ml_model"),
            ("ubuntu.iso", "disk_image"),
            ("macos.dmg", "disk_image"),
            ("stem.flac", "audio"),
            ("design.psd", "image"),
            ("data.parquet", "document"),
            ("x.xyz", "other"),
        ];
        for (f, k) in cases {
            assert_eq!(classify_semantic_kind(Path::new(f)), k);
        }
    }

    #[test]
    fn test_find_large_forgotten_prunes_and_registers_tokens() {
        let dir = std::env::temp_dir().join(format!("dc-mcp-large-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["videos", "models", "node_modules/pkg", "cached_dir", ".ssh"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let old_file = dir.join("models/weights.safetensors");
        std::fs::write(&old_file, vec![1u8; 4096]).unwrap();
        let old_t = SystemTime::now() - Duration::from_secs(400 * 86_400);
        let times = std::fs::FileTimes::new()
            .set_accessed(old_t)
            .set_modified(old_t);
        let _ = std::fs::File::options()
            .write(true)
            .open(&old_file)
            .and_then(|f| f.set_times(times));

        std::fs::write(dir.join("videos/clip.mp4"), vec![2u8; 8192]).unwrap();
        std::fs::write(dir.join("node_modules/pkg/huge.bin"), vec![3u8; 8192]).unwrap();
        std::fs::write(
            dir.join("cached_dir/CACHEDIR.TAG"),
            b"Signature: 8a477f597d28d172789f06886806bc55",
        )
        .unwrap();
        std::fs::write(dir.join("cached_dir/blob.bin"), vec![4u8; 8192]).unwrap();
        std::fs::write(dir.join(".ssh/id_ed25519"), vec![5u8; 8192]).unwrap();

        let engine = ScanEngine::new();
        let root = Some(dir.to_string_lossy().to_string());
        let p_all = LargeFilesParams {
            root: root.clone(),
            min_size: Some(1024),
            ..Default::default()
        };
        let rep = find_large_forgotten(&engine, &p_all);
        assert_eq!(rep.total_matched_files, 2);
        assert_eq!(rep.files[0].semantic_kind, "video");
        assert_eq!(rep.files[1].semantic_kind, "ml_model");

        let p_old = LargeFilesParams {
            root,
            min_size: Some(1024),
            unused_days: Some(365),
            ..Default::default()
        };
        let rep_old = find_large_forgotten(&engine, &p_old);
        assert_eq!(rep_old.total_matched_files, 1);
        let item = DeleteItemRequest {
            path: rep_old.files[0].path.clone(),
            approval_token: rep_old.files[0].approval_token.clone(),
        };
        let req = DeleteRequest {
            scan_id: rep_old.scan_id,
            items: vec![item],
            permanent: false,
            confirm_permanent: false,
            confirm_risk: true,
            dry_run: true,
        };
        let del = engine.delete(&req);
        assert_eq!(del.dry_run, 1);
        assert_eq!(del.rejected, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
