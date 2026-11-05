//! TreeSize-grade insights computed from an existing scan's cached entries.
//!
//! Four analyses, all derived WITHOUT re-walking the filesystem except the
//! content-hash pass in `find_duplicates`:
//!   * `build_tree`        — recursive folder sizes (TreeSize "folder view")
//!   * `file_types`        — per-extension size/count breakdown
//!   * `find_duplicates`   — size prefilter + streaming SHA-256 dedup
//!   * `compare_snapshots` — diff two scans (TreeSize "compare over time")

use crate::model::*;
use crate::safety;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::Path;

/// Read size of the largest file we are willing to content-hash. Larger files
/// are reported as candidates but skipped to bound I/O. `ponytail:` upgrade =
/// chunked/partial hashing if users ask for >4GB dedup.
const MAX_HASH_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Head stage reads only this many bytes + length, so large same-size
/// non-duplicates cost 64KB I/O instead of full file reads.
const HEAD_HASH_BYTES: usize = 64 * 1024;
/// Extension shown for files with no extension.
const NO_EXT: &str = "(none)";

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

// ── 3. duplicates ──

/// Streaming SHA-256 of a file's content, or None if unreadable/too large.
fn hash_file(path: &str) -> Option<String> {
    let p = Path::new(path);
    let meta = std::fs::metadata(p).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_BYTES {
        return None;
    }
    let mut f = std::fs::File::open(p).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return None,
        };
        hasher.update(&buf[..n]);
    }
    Some(safety::hex::encode(hasher.finalize()))
}

/// Hash only first HEAD_HASH_BYTES + file length (cheap prefilter).
fn hash_file_head(path: &str, size: u64) -> Option<String> {
    let p = Path::new(path);
    let meta = std::fs::metadata(p).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_BYTES {
        return None;
    }
    let mut f = std::fs::File::open(p).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HEAD_HASH_BYTES];
    let n = f.read(&mut buf).ok()?;
    let read = &buf[..std::cmp::min(n, size as usize)];
    hasher.update(read);
    hasher.update(size.to_le_bytes());
    Some(safety::hex::encode(hasher.finalize()))
}

/// Find byte-identical duplicate files within a scan.
///
/// Cheap prefilter by size (no disk reads), then parallel streaming SHA-256
/// only over same-size groups. Each returned file carries its scan `approval`
/// token so the caller can delete redundant copies via the normal safe flow.
pub fn find_duplicates(
    entries: &[ScanEntry],
    scan_id: &str,
    min_size: u64,
    top: usize,
) -> DuplicateReport {
    // candidate = files, size >= min_size, not system-protected
    let candidates: Vec<&ScanEntry> = entries
        .iter()
        .filter(|e| {
            e.kind == "file" && e.size >= min_size && !safety::is_protected(Path::new(&e.path))
        })
        .collect();

    // group by size; only sizes with >=2 files are possible duplicates
    let mut by_size: HashMap<u64, Vec<&ScanEntry>> = HashMap::new();
    for e in &candidates {
        by_size.entry(e.size).or_default().push(e);
    }
    let groups_by_size: Vec<Vec<&ScanEntry>> =
        by_size.into_values().filter(|g| g.len() >= 2).collect();
    let candidate_files: u64 = groups_by_size.iter().map(|g| g.len() as u64).sum();

    // Stage 1 (cheap): head hash (first 64KB + length) — full-hash only
    // head collisions. Files <= HEAD bytes: head read == whole file, but
    // length salt keeps it distinct from full hash; full-hash them anyway
    // when colliding (small files, cheap).
    let heads: Vec<(&ScanEntry, Option<String>)> = groups_by_size
        .par_iter()
        .flat_map(|g| g.par_iter().map(|e| (*e, hash_file_head(&e.path, e.size))))
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
    // Stage 2 (exact): full SHA-256 only for head-collision groups.
    let colliding: Vec<Vec<&ScanEntry>> = by_head.into_values().filter(|g| g.len() >= 2).collect();
    let hashed: Vec<(&ScanEntry, Option<String>)> = colliding
        .par_iter()
        .flat_map(|g| g.par_iter().map(|e| (*e, hash_file(&e.path))))
        .collect();
    let hashed_files = hashed.iter().filter(|(_, h)| h.is_some()).count() as u64;
    let full_failed = hashed.len() as u64 - hashed_files;
    let unreadable_files = head_failed + full_failed;

    // final grouping by (size, hash)
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
        // oldest first → caller keeps files[0]
        files.sort_by_key(|e| e.modified.unwrap_or(i64::MAX));
        let wasted = size * (files.len() as u64 - 1);
        total_wasted += wasted;
        groups.push(DuplicateGroup {
            hash,
            size,
            file_count: files.len() as u64,
            wasted_size: wasted,
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
        // sub dir child present with its own recursive size
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
            // force each dir to hold a file so it gets recursive size
            entries.push(file(
                &format!("C:/root/d{}/x.bin", i),
                (i + 1) * 100,
                "bin",
                None,
            ));
        }
        let tree = build_tree(&entries, "C:/root", 5);
        assert!(tree.children_truncated, "children should be truncated");
        // 5 real children + 1 rollup
        assert_eq!(tree.children.len(), 6);
        let rollup = tree.children.last().unwrap();
        assert!(rollup.name.starts_with("(+"));
        // recursive totals must still be exact regardless of truncation
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
    fn test_find_duplicates_groups_identical_content() {
        let dir = std::env::temp_dir().join(format!("dc-mcp-dup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("one.bin"), b"same-bytes-123456789").unwrap();
        std::fs::write(dir.join("two.bin"), b"same-bytes-123456789").unwrap();
        std::fs::write(dir.join("unique.bin"), b"different-content-xy!").unwrap();

        let p = |n: &str, m: i64| {
            let mut e = file(
                &dir.join(n).to_string_lossy().replace('\\', "/"),
                21,
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
        assert_eq!(g.files[0].path, rep.top_groups[0].files[0].path);
        // oldest first → keep one.bin (modified 100) at index 0
        assert!(g.files[0].path.ends_with("one.bin"));
        // tokens preserved so caller can delete safely
        assert!(g.files.iter().all(|f| f.approval_token.starts_with("tok-")));

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
        // scan A: keep.bin(10), gone.bin(30), same.bin(50)
        let a = snap(
            "A",
            vec![
                file("C:/root/keep.bin", 10, "bin", None),
                file("C:/root/gone.bin", 30, "bin", None),
                file("C:/root/same.bin", 50, "bin", None),
            ],
        );
        // scan B: keep.bin grew to 40, gone.bin removed, new.bin(70) added, same.bin unchanged
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
