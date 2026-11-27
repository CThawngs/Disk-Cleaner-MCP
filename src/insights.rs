//! TreeSize-grade insights computed from an existing scan's cached entries.
//!
//! Four analyses, all derived WITHOUT re-walking the filesystem except the
//! content-hash pass in `find_duplicates`:
//!   * `build_tree`        — recursive folder sizes (TreeSize "folder view")
//!   * `file_types`        — per-extension size/count breakdown
//!   * `find_duplicates`   — size prefilter + head/tail + streaming BLAKE3 dedup
//!   * `compare_snapshots` — diff two scans (TreeSize "compare over time")

use crate::model::*;
use crate::safety;
use blake3::Hasher;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Read size of the largest file we fully content-hash. Larger files use a
/// sampled hash (head 64KB + tail 64KB + length) and are flagged partial.
const MAX_HASH_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Head/tail stage reads at most 64KB per window so large same-size
/// non-duplicates avoid full file reads.
const HEAD_HASH_BYTES: usize = 64 * 1024;
/// Extension shown for files with no extension.
const NO_EXT: &str = "(none)";

/// Windows file attribute mask for Cloud-Only / unpinned files (OneDrive, iCloud, Cloud Files API):
/// FILE_ATTRIBUTE_OFFLINE (0x1000) | FILE_ATTRIBUTE_RECALL_ON_OPEN (0x40000) | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS (0x400000).
const WINDOWS_CLOUD_PLACEHOLDER_MASK: u32 = 0x0000_1000 | 0x0004_0000 | 0x0040_0000;

#[inline]
pub(crate) fn is_cloud_attributes_windows(file_attributes: u32) -> bool {
    (file_attributes & WINDOWS_CLOUD_PLACEHOLDER_MASK) != 0
}

#[inline]
pub(crate) fn is_cloud_blocks_unix(blocks: u64, len: u64) -> bool {
    blocks == 0 && len > 0
}

/// Cross-platform check for Cloud-Only / unpinned placeholder files so scanners
/// and content hashers NEVER trigger involuntary cloud hydration downloads.
pub fn is_cloud_placeholder(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let _ = is_cloud_blocks_unix;
        is_cloud_attributes_windows(meta.file_attributes())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = is_cloud_attributes_windows;
        is_cloud_blocks_unix(meta.blocks(), meta.len())
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (meta, is_cloud_attributes_windows, is_cloud_blocks_unix);
        false
    }
}

// ── path helpers (paths are stored with forward slashes) ──

fn strip_filename(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[..i],
        None => "",
    }
}

fn base_name(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

// ── 1. folder tree ──

/// Build a recursive folder-size tree from a scan's flat entries.
///
/// `root` is the normalized scan root (forward-slash). Children of each node
/// are sorted by recursive size desc and truncated to `top`; the remainder is
/// folded into a synthetic "(+N more)" node so percentages stay exact.
pub fn build_tree(entries: &[ScanEntry], root: &str, top: usize) -> TreeNode {
    // Entry paths are stored with forward slashes; normalize root the same way.
    let root_owned = root.replace('\\', "/");
    let root_norm = root_owned.trim_end_matches('/');

    // dir path -> (recursive size, recursive file count)
    let mut rec: HashMap<&str, (u64, u64)> = HashMap::new();
    // dir path -> (direct size, direct file count)
    let mut direct: HashMap<&str, (u64, u64)> = HashMap::new();
    // parent dir -> child dir paths
    let mut children: HashMap<&str, HashSet<&str>> = HashMap::new();
    let mut all_dirs: HashSet<&str> = HashSet::new();
    all_dirs.insert(root_norm);

    for e in entries {
        if e.kind != "file" {
            continue;
        }
        let parent = strip_filename(&e.path);
        if parent.is_empty() {
            continue;
        }
        let d = direct.entry(parent).or_insert((0, 0));
        d.0 += e.size;
        d.1 += 1;

        // Roll file size up through every ancestor between parent and root.
        let mut cur = parent;
        loop {
            let r = rec.entry(cur).or_insert((0, 0));
            r.0 += e.size;
            r.1 += 1;
            all_dirs.insert(cur);
            if cur == root_norm || !cur.starts_with(root_norm) {
                break;
            }
            let up = strip_filename(cur);
            if up.is_empty() || up == cur {
                break;
            }
            // link edge up -> cur
            children.entry(up).or_default().insert(cur);
            all_dirs.insert(up);
            cur = up;
        }
        // ensure the immediate parent's own edge exists even if it == root
        children.entry(parent).or_default();
    }

    // Root's recursive totals define 100%.
    let root_total = rec.get(root_norm).map(|v| v.0).unwrap_or(0).max(1);

    assemble_node(root_norm, root_total, top, &rec, &direct, &children)
}

fn assemble_node(
    dir: &str,
    root_total: u64,
    top: usize,
    rec: &HashMap<&str, (u64, u64)>,
    direct: &HashMap<&str, (u64, u64)>,
    children: &HashMap<&str, HashSet<&str>>,
) -> TreeNode {
    let (rsize, rfiles) = rec.get(dir).copied().unwrap_or((0, 0));
    let (dsize, dfiles) = direct.get(dir).copied().unwrap_or((0, 0));

    let mut kids: Vec<&str> = children
        .get(dir)
        .map(|s| s.iter().copied().collect())
        .unwrap_or_default();
    kids.sort_by_key(|k| std::cmp::Reverse(rec.get(k).map(|v| v.0).unwrap_or(0)));

    let truncated = kids.len() > top;
    let mut child_nodes: Vec<TreeNode> = kids
        .iter()
        .take(top)
        .map(|k| assemble_node(k, root_total, top, rec, direct, children))
        .collect();

    if truncated {
        let rest = &kids[top..];
        let (msize, mfiles): (u64, u64) = rest
            .iter()
            .map(|k| rec.get(*k).copied().unwrap_or((0, 0)))
            .fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
        child_nodes.push(TreeNode {
            name: format!("(+{} more)", rest.len()),
            path: format!("{}/*", dir),
            size: msize,
            files: mfiles,
            direct_size: 0,
            direct_files: 0,
            percent: pct(msize, root_total),
            children: Vec::new(),
            children_truncated: false,
        });
    }

    TreeNode {
        name: if dir.is_empty() {
            "/".into()
        } else {
            base_name(dir).to_string()
        },
        path: dir.to_string(),
        size: rsize,
        files: rfiles,
        direct_size: dsize,
        direct_files: dfiles,
        percent: pct(rsize, root_total),
        children: child_nodes,
        children_truncated: truncated,
    }
}

fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64 / whole as f64) * 100.0
    }
}

// ── 2. file types ──

/// Aggregate file sizes/counts per extension, largest first.
pub fn file_types(entries: &[ScanEntry], scan_id: &str, limit: usize) -> FileTypeReport {
    let mut map: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut total_size = 0u64;
    let mut total_files = 0u64;
    for e in entries {
        if e.kind != "file" {
            continue;
        }
        let ext = e.extension.clone().unwrap_or_else(|| NO_EXT.into());
        let v = map.entry(ext).or_insert((0, 0));
        v.0 += 1;
        v.1 += e.size;
        total_size += e.size;
        total_files += 1;
    }

    let mut stats: Vec<ExtensionStat> = map
        .into_iter()
        .map(|(extension, (count, size))| ExtensionStat {
            extension,
            count,
            size,
        })
        .collect();
    stats.sort_by_key(|a| std::cmp::Reverse(a.size));

    let extension_count = stats.len();
    let truncated = stats.len() > limit;
    stats.truncate(limit);

    FileTypeReport {
        scan_id: scan_id.into(),
        total_files,
        total_size,
        extension_count,
        by_extension: stats,
        truncated,
    }
}

// ── 3. duplicates (SIMD BLAKE3 + Cloud-Only & Hardlink Guards) ──

/// Inspect metadata without following symlinks; reject symlinks, non-files, and cloud placeholders.
fn inspect_hashable_meta(path: &Path) -> Result<Option<std::fs::Metadata>, ()> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if meta.file_type().is_symlink() || !meta.is_file() || is_cloud_placeholder(&meta) {
        return Ok(None);
    }
    Ok(Some(meta))
}

/// Streaming full BLAKE3 of a file's content, or None if unreadable/too large/cloud placeholder.
fn full_hash(path: &str) -> Option<String> {
    let p = Path::new(path);
    let meta = inspect_hashable_meta(p).ok()??;
    if meta.len() > MAX_HASH_BYTES {
        return None;
    }
    let mut f = std::fs::File::open(p).ok()?;
    let mut hasher = Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return None,
        };
        hasher.update(&buf[..n]);
    }
    Some(hasher.finalize().to_hex().to_string())
}

/// Cheap prefilter: BLAKE3 of head 64KB (+ tail 64KB when size > 64KB) + file length.
fn head_tail_hash(path: &str, size: u64) -> Option<String> {
    let p = Path::new(path);
    let _meta = inspect_hashable_meta(p).ok()??;
    let mut f = std::fs::File::open(p).ok()?;
    let mut hasher = Hasher::new();
    let mut buf = vec![0u8; HEAD_HASH_BYTES];
    let n = f.read(&mut buf).ok()?;
    hasher.update(&buf[..std::cmp::min(n, size as usize)]);
    if size > HEAD_HASH_BYTES as u64 {
        let tail_start = size.saturating_sub(HEAD_HASH_BYTES as u64);
        if f.seek(SeekFrom::Start(tail_start)).is_err() {
            return None;
        }
        let m = f.read(&mut buf).ok()?;
        hasher.update(&buf[..std::cmp::min(m, HEAD_HASH_BYTES)]);
    }
    hasher.update(&size.to_le_bytes());
    hasher.update(b"head_tail");
    Some(hasher.finalize().to_hex().to_string())
}

/// Sampled BLAKE3 hash for >4GB files: head 64KB + tail 64KB + length + marker.
/// Same-size files differing outside those windows may collide — callers
/// flag such groups `partial` so the agent verifies before deleting.
fn sampled_hash(path: &str, size: u64) -> Option<String> {
    let p = Path::new(path);
    let _meta = inspect_hashable_meta(p).ok()??;
    let mut f = std::fs::File::open(p).ok()?;
    let mut hasher = Hasher::new();
    let mut head = vec![0u8; HEAD_HASH_BYTES];
    let n = f.read(&mut head).ok()?;
    hasher.update(&head[..std::cmp::min(n, HEAD_HASH_BYTES)]);
    let tail_start = size.saturating_sub(HEAD_HASH_BYTES as u64);
    if f.seek(SeekFrom::Start(tail_start)).is_err() {
        return None;
    }
    let mut tail = vec![0u8; HEAD_HASH_BYTES];
    let m = f.read(&mut tail).ok()?;
    hasher.update(&tail[..std::cmp::min(m, HEAD_HASH_BYTES)]);
    hasher.update(&size.to_le_bytes());
    hasher.update(b"partial");
    Some(hasher.finalize().to_hex().to_string())
}

/// Find byte-identical duplicate files within a scan.
///
/// Cheap prefilter by size (no disk reads), skips Never-Touch / system-protected
/// paths, Cloud-Only placeholders, and Unix hardlinks `(dev, ino)`, then runs
/// parallel head+tail + streaming SIMD BLAKE3 over colliding groups.
pub fn find_duplicates(
    entries: &[ScanEntry],
    scan_id: &str,
    min_size: u64,
    top: usize,
) -> DuplicateReport {
    let candidates: Vec<&ScanEntry> = entries
        .iter()
        .filter(|e| {
            if e.kind != "file" || e.size < min_size {
                return false;
            }
            let p = Path::new(&e.path);
            safety::sensitive_never_touch_reason(p).is_none() && !safety::is_protected(p)
        })
        .collect();

    let mut by_size: HashMap<u64, Vec<&ScanEntry>> = HashMap::new();
    for e in &candidates {
        by_size.entry(e.size).or_default().push(e);
    }

    #[cfg(unix)]
    let mut seen_inodes: HashSet<(u64, u64)> = HashSet::new();
    let mut meta_failed = 0u64;
    let mut groups_by_size: Vec<Vec<&ScanEntry>> = Vec::new();

    for mut group in by_size.into_values() {
        if group.len() < 2 {
            continue;
        }
        // Deterministic oldest-first order before hardlink deduplication.
        group.sort_by(|a, b| {
            a.modified
                .unwrap_or(i64::MAX)
                .cmp(&b.modified.unwrap_or(i64::MAX))
                .then_with(|| a.path.cmp(&b.path))
        });

        let mut eligible = Vec::with_capacity(group.len());
        for e in group {
            match inspect_hashable_meta(Path::new(&e.path)) {
                Err(()) => {
                    meta_failed += 1;
                }
                Ok(None) => {
                    // Symlink or Cloud-Only placeholder: intentionally skipped without I/O.
                }
                Ok(Some(meta)) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        if !seen_inodes.insert((meta.dev(), meta.ino())) {
                            continue;
                        }
                    }
                    #[cfg(not(unix))]
                    let _ = &meta;
                    eligible.push(e);
                }
            }
        }
        if eligible.len() >= 2 {
            groups_by_size.push(eligible);
        }
    }

    let candidate_files: u64 = groups_by_size.iter().map(|g| g.len() as u64).sum();

    // Stage 1 (cheap): head+tail BLAKE3 prefilter — full-hash only collisions.
    let heads: Vec<(&ScanEntry, Option<String>)> = groups_by_size
        .par_iter()
        .flat_map(|g| g.par_iter().map(|e| (*e, head_tail_hash(&e.path, e.size))))
        .collect();
    let mut by_head: HashMap<(u64, String), Vec<&ScanEntry>> = HashMap::new();
    let mut head_failed = 0u64;
    for (e, h) in heads {
        if let Some(h) = h {
            by_head.entry((e.size, h)).or_default().push(e);
        } else {
            head_failed += 1;
        }
    }

    // Stage 2 (exact for <=4GB, sampled for >4GB): hash only Stage 1 collisions.
    let colliding: Vec<Vec<&ScanEntry>> = by_head.into_values().filter(|g| g.len() >= 2).collect();
    let hashed: Vec<(&ScanEntry, Option<String>)> = colliding
        .par_iter()
        .flat_map(|g| {
            g.par_iter().map(|e| {
                let h = if e.size > MAX_HASH_BYTES {
                    sampled_hash(&e.path, e.size)
                } else {
                    full_hash(&e.path)
                };
                (*e, h)
            })
        })
        .collect();
    let hashed_files = hashed.iter().filter(|(_, h)| h.is_some()).count() as u64;
    let full_failed = hashed.len() as u64 - hashed_files;
    let unreadable_files = meta_failed + head_failed + full_failed;

    // Final grouping by (size, hash)
    let mut by_hash: HashMap<(u64, String), Vec<&ScanEntry>> = HashMap::new();
    for (e, h) in hashed {
        if let Some(h) = h {
            by_hash.entry((e.size, h)).or_default().push(e);
        }
    }

    let mut groups: Vec<DuplicateGroup> = Vec::new();
    let mut total_wasted = 0u64;
    for ((size, hash), mut files) in by_hash {
        if files.len() < 2 {
            continue;
        }
        // Oldest first → caller keeps files[0]
        files.sort_by_key(|e| e.modified.unwrap_or(i64::MAX));
        let wasted = size * (files.len() as u64 - 1);
        total_wasted += wasted;
        groups.push(DuplicateGroup {
            hash,
            size,
            file_count: files.len() as u64,
            wasted_size: wasted,
            partial: size > MAX_HASH_BYTES,
            files: files
                .into_iter()
                .map(|e| DuplicateFile {
                    path: e.path.clone(),
                    size: e.size,
                    modified: e.modified,
                    category: e.category.clone(),
                    category_label: e.category_label.clone(),
                    approval_token: e.approval_token.clone(),
                })
                .collect(),
        });
    }

    groups.sort_by_key(|g| std::cmp::Reverse(g.wasted_size));
    let groups_found = groups.len() as u64;
    let partial_groups = groups.iter().filter(|g| g.partial).count() as u64;
    let truncated = groups.len() > top;
    groups.truncate(top);

    DuplicateReport {
        scan_id: scan_id.into(),
        groups_found,
        top_groups: groups,
        total_wasted,
        candidate_files,
        hashed_files,
        unreadable_files,
        truncated,
        partial_groups,
    }
}

// ── 4. snapshots + compare ──

/// Build a compact persisted snapshot from a scan's file entries.
pub fn build_snapshot(summary: &ScanSummary, entries: &[ScanEntry]) -> ScanSnapshot {
    let mut map = BTreeMap::new();
    for e in entries {
        if e.kind == "file" {
            map.insert(
                e.path.clone(),
                FileSnap {
                    size: e.size,
                    modified: e.modified,
                },
            );
        }
    }
    ScanSnapshot {
        scan_id: summary.scan_id.clone(),
        root: summary.root.clone(),
        started_at: summary.started_at,
        total_size: summary.total_size,
        files_scanned: summary.files_scanned,
        map,
    }
}

/// Diff two snapshots by file path: added / removed / size-changed.
pub fn compare_snapshots(a: &ScanSnapshot, b: &ScanSnapshot, top: usize) -> CompareReport {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut added_size = 0u64;
    let mut removed_size = 0u64;

    for (path, sb) in &b.map {
        match a.map.get(path) {
            None => {
                added_size += sb.size;
                added.push(FileChange {
                    path: path.clone(),
                    before: 0,
                    after: sb.size,
                    delta: sb.size as i64,
                });
            }
            Some(sa) => {
                if sa.size != sb.size {
                    changed.push(FileChange {
                        path: path.clone(),
                        before: sa.size,
                        after: sb.size,
                        delta: sb.size as i64 - sa.size as i64,
                    });
                }
            }
        }
    }
    for (path, sa) in &a.map {
        if !b.map.contains_key(path) {
            removed_size += sa.size;
            removed.push(FileChange {
                path: path.clone(),
                before: sa.size,
                after: 0,
                delta: -(sa.size as i64),
            });
        }
    }

    top_by_abs_delta(&mut added, top);
    top_by_abs_delta(&mut removed, top);
    top_by_abs_delta(&mut changed, top);

    let mut warnings = Vec::new();
    if a.root.trim_end_matches('/') != b.root.trim_end_matches('/') {
        warnings.push(format!(
            "Roots differ: '{}' vs '{}'. Diff still computed by path.",
            a.root, b.root
        ));
    }

    CompareReport {
        scan_a: a.scan_id.clone(),
        scan_b: b.scan_id.clone(),
        root_a: a.root.clone(),
        root_b: b.root.clone(),
        started_a: a.started_at,
        started_b: b.started_at,
        total_a: a.total_size,
        total_b: b.total_size,
        net_delta: b.total_size as i64 - a.total_size as i64,
        added_count: b.map.keys().filter(|k| !a.map.contains_key(*k)).count() as u64,
        added_size,
        removed_count: a.map.keys().filter(|k| !b.map.contains_key(*k)).count() as u64,
        removed_size,
        changed_count: a
            .map
            .iter()
            .filter(|(p, sa)| b.map.get(*p).is_some_and(|sb| sb.size != sa.size))
            .count() as u64,
        top_added: added,
        top_removed: removed,
        top_changed: changed,
        warnings,
    }
}

fn top_by_abs_delta(v: &mut Vec<FileChange>, top: usize) {
    v.sort_by_key(|c| std::cmp::Reverse(c.delta.unsigned_abs()));
    v.truncate(top);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, size: u64, ext: &str, modified: Option<i64>) -> ScanEntry {
        ScanEntry {
            kind: "file".into(),
            path: path.into(),
            size,
            modified,
            extension: Some(ext.into()),
            category: "other".into(),
            category_label: "Other".into(),
            approval_token: format!("tok-{}", path),
            depth: 1,
            verdict: "review".into(),
            importance_score: 50,
            risk_level: "caution".into(),
            reasons: vec![],
        }
    }

    fn dir(path: &str, depth: usize) -> ScanEntry {
        ScanEntry {
            kind: "dir".into(),
            path: path.into(),
            size: 0,
            modified: None,
            extension: None,
            category: "other".into(),
            category_label: "Other".into(),
            approval_token: format!("tok-{}", path),
            depth,
            verdict: "review".into(),
            importance_score: 50,
            risk_level: "caution".into(),
            reasons: vec![],
        }
    }

    #[test]
    fn test_build_tree_rolls_up_sizes() {
        let entries = vec![
            dir("C:/root", 0),
            file("C:/root/big.bin", 1000, "bin", None),
            dir("C:/root/sub", 1),
            file("C:/root/sub/deep.bin", 500, "bin", None),
        ];
        let tree = build_tree(&entries, "C:/root", 10);
        assert_eq!(tree.size, 1500, "root recursive size");
        assert_eq!(tree.files, 2);
        assert_eq!(tree.direct_size, 1000);
        assert_eq!(tree.direct_files, 1);
        let sub = tree
            .children
            .iter()
            .find(|c| c.name == "sub")
            .expect("sub node");
        assert_eq!(sub.size, 500);
        assert_eq!(sub.percent, (500.0 / 1500.0) * 100.0);
    }

    #[test]
    fn test_build_tree_truncates_with_rollup() {
        let mut entries = vec![dir("C:/root", 0)];
        for i in 0..30 {
            entries.push(file(
                &format!("C:/root/f{}.bin", i),
                (i + 1) * 10,
                "bin",
                None,
            ));
            entries.push(dir(&format!("C:/root/d{}", i), 1));
            entries.push(file(
                &format!("C:/root/d{}/x.bin", i),
                (i + 1) * 100,
                "bin",
                None,
            ));
        }
        let tree = build_tree(&entries, "C:/root", 5);
        assert!(tree.children_truncated, "children should be truncated");
        assert_eq!(tree.children.len(), 6);
        let rollup = tree.children.last().unwrap();
        assert!(rollup.name.starts_with("(+"));
        let total: u64 = (1..=30).map(|i| (i * 10) + (i * 100)).sum();
        assert_eq!(tree.size, total);
    }

    #[test]
    fn test_file_types_groups_and_sorts() {
        let entries = vec![
            file("C:/r/a.log", 10, "log", None),
            file("C:/r/b.log", 20, "log", None),
            file("C:/r/c.bin", 100, "bin", None),
            dir("C:/r/sub", 1),
        ];
        let r = file_types(&entries, "scan-1", 10);
        assert_eq!(r.total_files, 3);
        assert_eq!(r.total_size, 130);
        assert_eq!(r.by_extension[0].extension, "bin", "largest first");
        assert_eq!(r.by_extension[0].size, 100);
        assert_eq!(r.by_extension[1].extension, "log");
        assert_eq!(r.by_extension[1].count, 2);
    }

    #[test]
    fn test_find_duplicates_groups_identical_content_with_blake3() {
        let dir = std::env::temp_dir().join(format!("dc-mcp-dup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let payload = b"same-bytes-123456789!";
        std::fs::write(dir.join("one.bin"), payload).unwrap();
        std::fs::write(dir.join("two.bin"), payload).unwrap();
        std::fs::write(dir.join("unique.bin"), b"different-content-xy!").unwrap();

        let p = |n: &str, m: i64| {
            let mut e = file(
                &dir.join(n).to_string_lossy().replace('\\', "/"),
                payload.len() as u64,
                "bin",
                Some(m),
            );
            e.approval_token = format!("tok-{}", n);
            e
        };
        let entries = vec![p("one.bin", 100), p("two.bin", 200), p("unique.bin", 50)];
        let rep = find_duplicates(&entries, "scan-dup", 1, 10);

        assert_eq!(rep.groups_found, 1, "one duplicate pair");
        let g = &rep.top_groups[0];
        assert_eq!(g.file_count, 2);
        assert_eq!(g.wasted_size, 21, "one copy reclaimable");
        assert_eq!(g.hash, blake3::hash(payload).to_hex().as_str());
        assert!(g.files[0].path.ends_with("one.bin"));
        assert!(g.files.iter().all(|f| f.approval_token.starts_with("tok-")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sampled_and_head_tail_hashes_distinct_from_full() {
        let dir = std::env::temp_dir().join(format!("dc-mcp-samp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data = vec![7u8; 200_000];
        std::fs::write(dir.join("a.bin"), &data).unwrap();
        std::fs::write(dir.join("b.bin"), &data).unwrap();
        let pa = dir.join("a.bin").to_string_lossy().to_string();
        let pb = dir.join("b.bin").to_string_lossy().to_string();
        let ha = sampled_hash(&pa, 200_000).unwrap();
        let hb = sampled_hash(&pb, 200_000).unwrap();
        let ht = head_tail_hash(&pa, 200_000).unwrap();
        let hf = full_hash(&pa).unwrap();
        assert_eq!(ha, hb, "identical content → identical sampled hash");
        assert_ne!(ha, hf, "sampled hash must differ from full hash");
        assert_ne!(ht, hf, "head+tail hash must differ from full hash");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cloud_placeholder_detection_formulas() {
        assert!(is_cloud_attributes_windows(0x0000_1000)); // FILE_ATTRIBUTE_OFFLINE
        assert!(is_cloud_attributes_windows(0x0004_0000)); // RECALL_ON_OPEN
        assert!(is_cloud_attributes_windows(0x0040_0020)); // RECALL_ON_DATA_ACCESS | ARCHIVE
        assert!(!is_cloud_attributes_windows(0x0000_0020)); // Normal ARCHIVE file

        assert!(is_cloud_blocks_unix(0, 4096)); // Unpinned cloud placeholder
        assert!(!is_cloud_blocks_unix(0, 0)); // Legitimate 0-byte empty file
        assert!(!is_cloud_blocks_unix(8, 4096)); // Allocated local file
    }

    #[test]
    fn test_find_duplicates_skips_sensitive_never_touch() {
        let dir = std::env::temp_dir().join(format!("dc-mcp-nt-dup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ssh_dir = dir.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::write(ssh_dir.join("id_ed25519"), b"secret-key-material!").unwrap();
        std::fs::write(dir.join("copy.txt"), b"secret-key-material!").unwrap();
        std::fs::write(dir.join(".env"), b"secret-key-material!").unwrap();

        let entries = vec![
            file(
                &ssh_dir
                    .join("id_ed25519")
                    .to_string_lossy()
                    .replace('\\', "/"),
                20,
                "",
                Some(10),
            ),
            file(
                &dir.join(".env").to_string_lossy().replace('\\', "/"),
                20,
                "env",
                Some(20),
            ),
            file(
                &dir.join("copy.txt").to_string_lossy().replace('\\', "/"),
                20,
                "txt",
                Some(30),
            ),
        ];
        let rep = find_duplicates(&entries, "scan-nt", 1, 10);
        assert_eq!(
            rep.groups_found, 0,
            "sensitive files must never be hashed or grouped"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_find_duplicates_deduplicates_unix_hardlinks() {
        let dir = std::env::temp_dir().join(format!("dc-mcp-hl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let orig = dir.join("orig.bin");
        let link = dir.join("hardlink.bin");
        std::fs::write(&orig, b"hardlink-test-bytes!").unwrap();
        std::fs::hard_link(&orig, &link).unwrap();

        let entries = vec![
            file(&orig.to_string_lossy(), 20, "bin", Some(10)),
            file(&link.to_string_lossy(), 20, "bin", Some(10)),
        ];
        let rep = find_duplicates(&entries, "scan-hl", 1, 10);
        assert_eq!(
            rep.groups_found, 0,
            "hardlinks share one inode and waste 0 bytes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compare_snapshots_added_removed_changed() {
        let snap = |id: &str, files: Vec<ScanEntry>| {
            build_snapshot(
                &ScanSummary {
                    scan_id: id.into(),
                    started_at: 1,
                    duration_ms: 0,
                    root: "C:/root".into(),
                    files_scanned: files.len() as u64,
                    dirs_scanned: 0,
                    total_size: files.iter().map(|f| f.size).sum(),
                    truncated: false,
                    max_entries: 0,
                    version: "t".into(),
                    category_totals: vec![],
                    largest_entries: vec![],
                    warnings: vec![],
                    safe_count: 0,
                    review_count: 0,
                    keep_count: 0,
                    blocked_count: 0,
                    reclaimable_bytes: 0,
                },
                &files,
            )
        };
        let a = snap(
            "A",
            vec![
                file("C:/root/keep.bin", 10, "bin", None),
                file("C:/root/gone.bin", 30, "bin", None),
                file("C:/root/same.bin", 50, "bin", None),
            ],
        );
        let b = snap(
            "B",
            vec![
                file("C:/root/keep.bin", 40, "bin", None),
                file("C:/root/new.bin", 70, "bin", None),
                file("C:/root/same.bin", 50, "bin", None),
            ],
        );
        let diff = compare_snapshots(&a, &b, 10);
        assert_eq!(diff.added_count, 1);
        assert_eq!(diff.added_size, 70);
        assert_eq!(diff.removed_count, 1);
        assert_eq!(diff.removed_size, 30);
        assert_eq!(diff.changed_count, 1);
        assert_eq!(diff.total_a, 90);
        assert_eq!(diff.total_b, 160);
        assert_eq!(diff.net_delta, 70);
        assert_eq!(diff.top_changed[0].path, "C:/root/keep.bin");
        assert_eq!(diff.top_changed[0].delta, 30);
    }
}
