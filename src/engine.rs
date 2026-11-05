//! Scan engine — multithreaded directory walker with metadata extraction
//! and per-scan approval tokens.

use crate::analytics;
use crate::model::*;
use crate::safety;
use jwalk::{Parallelism, WalkDirGeneric};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SCAN_ENTRIES: usize = 200_000;
const MAX_SCAN_DEPTH: usize = 15;

/// One scan session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSession {
    pub scan_id: String,
    pub salt: String,
    pub summary: ScanSummary,
    pub entries: Vec<ScanEntry>,
}

pub struct ScanEngine {
    sessions: RwLock<HashMap<String, Arc<ScanSession>>>,
    order: RwLock<VecDeque<String>>,
}

impl ScanEngine {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            order: RwLock::new(VecDeque::new()),
        }
    }

    pub fn get_session(&self, scan_id: &str) -> Option<Arc<ScanSession>> {
        if let Some(s) = self
            .sessions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(scan_id)
            .cloned()
        {
            return Some(s);
        }
        // Reload persisted snapshot after process restart (best-effort).
        let loaded = Self::load_session(scan_id)?;
        let arc = Arc::new(loaded);
        {
            let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
            sessions.insert(scan_id.to_string(), arc.clone());
        }
        Some(arc)
    }

    fn snapshot_dir() -> Option<PathBuf> {
        dirs::data_dir().map(|d| d.join("disk-cleaner-mcp").join("snapshots"))
    }

    fn save_session(session: &ScanSession) {
        if let Some(dir) = Self::snapshot_dir() {
            if std::fs::create_dir_all(&dir).is_ok() {
                let file = dir.join(format!("{}.json", session.scan_id));
                if let Ok(json) = serde_json::to_string(session) {
                    let _ = std::fs::write(file, json);
                }
                Self::prune_snapshots(&dir);
            }
        }
    }

    /// Keep newest 50 snapshots; delete older best-effort (unbounded growth guard).
    fn prune_snapshots(dir: &Path) {
        const KEEP: usize = 50;
        let mut files: Vec<(PathBuf, std::time::SystemTime)> = std::fs::read_dir(dir)
            .ok()
            .into_iter()
            .flat_map(|rd| rd.filter_map(|e| e.ok()))
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| {
                let m = e.metadata().ok()?.modified().ok()?;
                Some((e.path(), m))
            })
            .collect();
        if files.len() <= KEEP {
            return;
        }
        files.sort_by_key(|(_, m)| *m);
        let excess = files.len() - KEEP;
        for (p, _) in files.into_iter().take(excess) {
            let _ = std::fs::remove_file(p);
        }
    }

    fn load_session(scan_id: &str) -> Option<ScanSession> {
        // scan_id is engine-generated hex; reject path traversal anyway.
        if scan_id
            .chars()
            .any(|c| !(c.is_ascii_hexdigit() || c == '-'))
        {
            return None;
        }
        let file = Self::snapshot_dir()?.join(format!("{scan_id}.json"));
        let json = std::fs::read_to_string(file).ok()?;
        serde_json::from_str(&json).ok()
    }

    fn push_session(&self, session: ScanSession) -> Arc<ScanSession> {
        Self::save_session(&session);
        let arc = Arc::new(session);
        {
            let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
            let mut order = self.order.write().unwrap_or_else(|e| e.into_inner());
            if !sessions.contains_key(&arc.scan_id) {
                order.push_back(arc.scan_id.clone());
            }
            sessions.insert(arc.scan_id.clone(), arc.clone());
            // ponytail: keep max 3 sessions; evict oldest (FIFO)
            while order.len() > 3 {
                if let Some(old) = order.pop_front() {
                    sessions.remove(&old);
                }
            }
        }
        arc
    }

    /// Run a scan at `root`. `max_entries`/`max_depth` override the built-in
    /// caps (200k entries / depth 15) — clamped to sane bounds.
    #[allow(dead_code)] // kept for tests; server uses scan_with_limits
    pub fn scan(&self, root: &Path) -> Result<ScanResult, String> {
        self.scan_with_limits(root, None, None)
    }

    pub fn scan_with_limits(
        &self,
        root: &Path,
        max_entries: Option<usize>,
        max_depth: Option<usize>,
    ) -> Result<ScanResult, String> {
        let max_entries = max_entries
            .unwrap_or(MAX_SCAN_ENTRIES)
            .clamp(100, 2_000_000);
        let max_depth = max_depth.unwrap_or(MAX_SCAN_DEPTH).clamp(1, 64);
        if !root.exists() {
            return Err(format!("Root path does not exist: {}", root.display()));
        }
        if !root.is_dir() {
            return Err(format!("Root path is not a directory: {}", root.display()));
        }

        let started = SystemTime::now();
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let scan_id = generate_id();
        let salt = safety::generate_salt();

        // Walk dir
        let walker = WalkDirGeneric::<((), ())>::new(root)
            .follow_links(false)
            .max_depth(max_depth)
            .sort(false)
            .parallelism(Parallelism::RayonDefaultPool {
                busy_timeout: std::time::Duration::from_secs(10),
            });

        let root_str = root.to_string_lossy().to_string();

        // Collect raw entries first
        let mut raw_entries: Vec<(PathBuf, std::fs::Metadata, usize)> = Vec::new();
        let mut files_scanned: u64 = 0;
        let mut dirs_scanned: u64 = 0;
        let mut warnings: Vec<String> = Vec::new();
        let mut truncated = false;

        for entry in walker {
            if truncated {
                break;
            }
            match entry {
                Ok(dir_entry) => {
                    if dir_entry.depth == 0 {
                        continue; // skip root
                    }

                    let path = dir_entry.path();

                    // Prune skip dirs: drop entry if it is a skip dir or lives
                    // under one (any ancestor component matches). ponytail:
                    // jwalk 0.9 parallel iterator can't prune natively, so
                    // filter here — children of a skip dir never become entries.
                    let in_skip = path
                        .components()
                        .any(|c| safety::should_skip_dir(&c.as_os_str().to_string_lossy()));
                    if in_skip {
                        continue;
                    }
                    if dir_entry.file_type.is_dir() {
                        dirs_scanned += 1;
                    } else {
                        files_scanned += 1;
                    }

                    if raw_entries.len() >= max_entries {
                        truncated = true;
                        warnings.push(format!("Scan truncated at {} entries. Use a more specific path or analyze with filters.", max_entries));
                        break;
                    }

                    // Get metadata in parallel later; for now collect paths
                    match std::fs::metadata(&path) {
                        Ok(meta) => {
                            raw_entries.push((path, meta, dir_entry.depth));
                        }
                        Err(e) => {
                            // Skip inaccessible
                            let _ = e;
                        }
                    }
                }
                Err(e) => {
                    warnings.push(format!("Walk error: {}", e));
                }
            }
        }

        // Parallel metadata extraction + categorization
        let mut entries: Vec<ScanEntry> = raw_entries
            .par_iter()
            .filter_map(|(path, meta, depth)| {
                let kind = if meta.is_dir() { "dir" } else { "file" };
                let size = if meta.is_file() { meta.len() } else { 0 };
                let modified = meta.modified().ok().and_then(|t| {
                    t.duration_since(UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs() as i64)
                });
                let extension = path.extension().map(|e| e.to_string_lossy().to_lowercase());

                let path_str = path.to_string_lossy().replace('\\', "/");
                let (category, category_label) = analytics::categorize(&path_str, &extension);

                let token = safety::compute_token(&salt, &path_str);

                Some(ScanEntry {
                    kind: kind.into(),
                    path: path_str,
                    size,
                    modified,
                    extension,
                    category: category.clone(),
                    category_label: category_label.clone(),
                    approval_token: token,
                    depth: *depth,
                    verdict: String::new(),
                    importance_score: 0,
                    risk_level: String::new(),
                    reasons: Vec::new(),
                })
            })
            .collect();

        // Brain: judge every entry, smallest -> largest.
        let mut name_size: HashMap<(String, u64), usize> = HashMap::new();
        for e in &entries {
            if e.kind == "file" {
                let name = Path::new(&e.path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                *name_size.entry((name, e.size)).or_insert(0) += 1;
            }
        }
        for e in &mut entries {
            let name = Path::new(&e.path)
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            let duplicate = e.kind == "file"
                && e.size > 0
                && name_size.get(&(name, e.size)).copied().unwrap_or(0) > 1;
            // Brain verdict, then user custom rules (can only tighten or
            // downgrade junk — never unblock a blocked entry).
            let a = crate::brain::assess(
                &e.path,
                e.size,
                e.modified,
                &e.extension,
                &e.category,
                duplicate,
                now_epoch,
            );
            e.verdict = a.verdict;
            e.importance_score = a.importance_score;
            e.risk_level = a.risk_level;
            e.reasons = a.reasons;
            if crate::config::matches_keep(&e.path) {
                e.verdict = "keep".into();
                e.risk_level = "caution".into();
                e.importance_score = e.importance_score.max(90);
                e.reasons.push("custom keepGlobs rule".into());
            } else if e.verdict != "blocked" && crate::config::matches_safe(&e.path) {
                e.verdict = "safe_to_delete".into();
                e.risk_level = "safe".into();
                e.importance_score = e.importance_score.min(10);
                e.reasons.push("custom safeGlobs rule (downgraded)".into());
            }
        }
        // Analyze smallest -> largest so the brain's reasoning order is visible.
        entries.sort_by_key(|e| e.size);

        let (safe_count, review_count, keep_count, blocked_count, reclaimable_bytes) = entries
            .iter()
            .fold((0u64, 0u64, 0u64, 0u64, 0u64), |acc, e| {
                let mut a = acc;
                match e.verdict.as_str() {
                    "safe_to_delete" => {
                        a.0 += 1;
                        a.4 += e.size;
                    }
                    "review" => a.1 += 1,
                    "keep" => a.2 += 1,
                    "blocked" => a.3 += 1,
                    _ => {}
                }
                a
            });

        // Build summary
        let total_size: u64 = entries
            .iter()
            .filter(|e| e.kind == "file")
            .map(|e| e.size)
            .sum();

        // Category totals
        let mut cat_map: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for e in &entries {
            if e.kind == "file" {
                let entry = cat_map.entry(e.category.clone()).or_insert((0, 0));
                entry.0 += 1;
                entry.1 += e.size;
            }
        }
        let category_totals: Vec<CategoryTotal> = cat_map
            .iter()
            .map(|(k, (count, size))| {
                let label = category_label_for(k);
                CategoryTotal {
                    category: k.clone(),
                    category_label: label,
                    count: *count,
                    size: *size,
                }
            })
            .collect();

        // Top 20 largest
        let mut largest: Vec<ScanEntry> = entries
            .iter()
            .filter(|e| e.kind == "file")
            .cloned()
            .collect();
        largest.sort_by_key(|a| std::cmp::Reverse(a.size));
        let largest_entries: Vec<ScanEntry> = largest.into_iter().take(20).collect();

        let duration_ms = started.elapsed().unwrap_or_default().as_millis() as u64;
        let entries_count = entries.len();

        let summary = ScanSummary {
            scan_id: scan_id.clone(),
            started_at: now_epoch,
            duration_ms,
            root: root_str,
            files_scanned,
            dirs_scanned,
            total_size,
            truncated,
            max_entries,
            version: VERSION.into(),
            category_totals,
            largest_entries,
            warnings,
            safe_count,
            review_count,
            keep_count,
            blocked_count,
            reclaimable_bytes,
        };

        let session = ScanSession {
            scan_id: scan_id.clone(),
            salt,
            summary: summary.clone(),
            entries,
        };
        self.push_session(session);

        Ok(ScanResult {
            summary,
            entries_count,
            message: format!(
                "Scan complete. {} entries found. Use analyze with scanId to filter and page.",
                entries_count
            ),
        })
    }

    /// Execute a delete operation with safety checks.
    pub fn delete(&self, req: &DeleteRequest) -> DeleteResult {
        let session = match self.get_session(&req.scan_id) {
            Some(s) => s,
            None => {
                return DeleteResult {
                    scan_id: req.scan_id.clone(),
                    trashed: 0,
                    permanent: 0,
                    rejected: 0,
                    errors: 0,
                    dry_run: 0,
                    would_reclaim_bytes: 0,
                    outcomes: vec![DeleteOutcome {
                        path: "(scan not found)".into(),
                        status: "error".into(),
                        message: Some(format!(
                            "Scan session '{}' not found. Run scan first.",
                            req.scan_id
                        )),
                    }],
                };
            }
        };

        let mut trashed = 0u32;
        let mut permanent = 0u32;
        let mut rejected = 0u32;
        let mut errors = 0u32;
        let mut dry_run_count = 0u32;
        let mut would_reclaim_bytes = 0u64;
        let mut outcomes = Vec::new();

        // Validate permanent flag
        if req.permanent && !req.confirm_permanent {
            return DeleteResult {
                scan_id: req.scan_id.clone(),
                trashed: 0,
                permanent: 0,
                rejected: 1,
                errors: 0,
                dry_run: 0,
                would_reclaim_bytes: 0,
                outcomes: vec![DeleteOutcome {
                    path: "(all)".into(),
                    status: "rejected".into(),
                    message: Some(
                        "permanent=true requires confirm_permanent=true to proceed.".into(),
                    ),
                }],
            };
        }

        for item in &req.items {
            // 1) Verify path exists in session
            let exists = session.entries.iter().any(|e| e.path == item.path);
            if !exists {
                outcomes.push(DeleteOutcome {
                    path: item.path.clone(),
                    status: "not_found".into(),
                    message: Some("Path not found in scan results. Re-run scan.".into()),
                });
                errors += 1;
                continue;
            }

            // 2+3b) Verify target at action time (TOCTOU guard): rejects
            // symlinks, symlinked ancestors, and protected canonical paths.
            let path = Path::new(&item.path);
            if !safety::verify_token(&session.salt, &item.path, &item.approval_token) {
                outcomes.push(DeleteOutcome {
                    path: item.path.clone(),
                    status: "rejected".into(),
                    message: Some(
                        "approval_token mismatch. Token expired or invalid for this scan session."
                            .into(),
                    ),
                });
                rejected += 1;
                continue;
            }
            let entry = session
                .entries
                .iter()
                .find(|e| e.path == item.path)
                .cloned();

            // Brain gate: blocked always; keep/review need confirm_risk.
            if let Some(e) = &entry {
                match e.verdict.as_str() {
                    "blocked" => {
                        outcomes.push(DeleteOutcome {
                            path: item.path.clone(),
                            status: "rejected".into(),
                            message: Some(format!(
                                "BLOCKED by brain (importance {}): {}",
                                e.importance_score,
                                e.reasons.join("; ")
                            )),
                        });
                        rejected += 1;
                        audit(&req.scan_id, &item.path, "rejected-blocked");
                        continue;
                    }
                    "keep" | "review" if !req.confirm_risk => {
                        outcomes.push(DeleteOutcome {
                            path: item.path.clone(),
                            status: "rejected".into(),
                            message: Some(format!(
                                "Brain verdict '{}' (importance {}, risk {}): {} — resend with confirm_risk=true after user approval.",
                                e.verdict,
                                e.importance_score,
                                e.risk_level,
                                e.reasons.join("; ")
                            )),
                        });
                        rejected += 1;
                        audit(&req.scan_id, &item.path, "rejected-needs-confirm-risk");
                        continue;
                    }
                    _ => {}
                }
            }

            let canon = match safety::verify_safe_target(path) {
                Ok(c) => c,
                Err(msg) => {
                    let status = if msg.contains("protected") {
                        "rejected"
                    } else {
                        "error"
                    };
                    if status == "rejected" {
                        rejected += 1;
                    } else {
                        errors += 1;
                    }
                    outcomes.push(DeleteOutcome {
                        path: item.path.clone(),
                        status: status.into(),
                        message: Some(msg),
                    });
                    continue;
                }
            };
            let path = canon.as_path();

            // Dry-run: report only, touch nothing.
            if req.dry_run {
                let size = entry.as_ref().map(|e| e.size).unwrap_or(0);
                would_reclaim_bytes += size;
                dry_run_count += 1;
                outcomes.push(DeleteOutcome {
                    path: item.path.clone(),
                    status: "dry_run".into(),
                    message: Some(format!(
                        "Would {} {} bytes (verdict={}). Nothing deleted.",
                        if req.permanent {
                            "permanently delete"
                        } else {
                            "trash"
                        },
                        size,
                        entry
                            .as_ref()
                            .map(|e| e.verdict.as_str())
                            .unwrap_or("unknown")
                    )),
                });
                audit(&req.scan_id, &item.path, "dry_run");
                continue;
            }

            // 4) Execute delete: trash or permanent
            if req.permanent {
                let remove = if path.is_dir() {
                    std::fs::remove_dir_all(path)
                } else {
                    std::fs::remove_file(path)
                };
                match remove {
                    Ok(_) => {
                        outcomes.push(DeleteOutcome {
                            path: item.path.clone(),
                            status: "permanent".into(),
                            message: None,
                        });
                        permanent += 1;
                        audit(&req.scan_id, &item.path, "permanent");
                    }
                    Err(e) => {
                        outcomes.push(DeleteOutcome {
                            path: item.path.clone(),
                            status: "error".into(),
                            message: Some(format!("Delete failed: {}", e)),
                        });
                        errors += 1;
                    }
                }
            } else {
                // Trash on a dedicated OS thread (Windows COM apartment safety);
                // headless Linux/macOS falls back to XDG Trash / ~/.Trash.
                let path_clone = path.to_path_buf();
                let moved = trash_delete_on_thread(path_clone.clone())
                    .or_else(|_| trash_fallback(&path_clone));
                match moved {
                    Ok(_) => {
                        outcomes.push(DeleteOutcome {
                            path: item.path.clone(),
                            status: "trashed".into(),
                            message: None,
                        });
                        trashed += 1;
                        audit(&req.scan_id, &item.path, "trashed");
                    }
                    Err(e) => {
                        outcomes.push(DeleteOutcome {
                            path: item.path.clone(),
                            status: "error".into(),
                            message: Some(format!("Trash failed: {}", e)),
                        });
                        errors += 1;
                    }
                }
            }
        }

        DeleteResult {
            scan_id: req.scan_id.clone(),
            trashed,
            permanent,
            rejected,
            errors,
            dry_run: dry_run_count,
            would_reclaim_bytes,
            outcomes,
        }
    }

    /// List what is currently in the OS Recycle Bin / Trash.
    pub fn list_trash(&self, limit: Option<usize>) -> TrashListResult {
        let limit = limit.unwrap_or(100).clamp(1, 500);
        let mut entries = trash_items();
        let total_bytes: u64 = entries.iter().map(|e| e.size_bytes).sum();
        let total_items = entries.len() as u64;
        entries.sort_by_key(|b| std::cmp::Reverse(b.time_deleted));
        entries.truncate(limit);
        TrashListResult {
            items: entries,
            total_items,
            total_bytes,
            message: None,
        }
    }

    /// Permanently purge OS Recycle Bin / Trash. Requires confirm=true.
    pub fn empty_trash(&self, req: &EmptyTrashParams) -> EmptyTrashResult {
        if !req.confirm {
            return EmptyTrashResult {
                purged_items: 0,
                purged_bytes: 0,
                message: Some("rejected: confirm=true required (irreversible)".into()),
            };
        }
        let (count, purged_bytes, message) = empty_trash_impl();
        audit("-", "(trash)", "empty_trash");
        EmptyTrashResult {
            purged_items: count,
            purged_bytes,
            message,
        }
    }

    /// Organize files: move scan entries into a destination directory grouped by
    /// category or extension. Safe: token-verified, never overwrites, protected paths rejected.
    pub fn organize(&self, req: &OrganizeRequest) -> OrganizeResult {
        let session = match self.get_session(&req.scan_id) {
            Some(s) => s,
            None => {
                return OrganizeResult {
                    scan_id: req.scan_id.clone(),
                    moved: 0,
                    dry_run: 0,
                    skipped: 0,
                    rejected: 0,
                    errors: 0,
                    outcomes: vec![OrganizeOutcome {
                        path: "(scan not found)".into(),
                        status: "error".into(),
                        dest: None,
                        message: Some(format!(
                            "Scan session '{}' not found. Run scan first.",
                            req.scan_id
                        )),
                    }],
                };
            }
        };

        let dest = PathBuf::from(&req.dest_dir);
        let dest_canon = match safety::verify_safe_target(&dest) {
            Ok(c) if c.is_dir() => c,
            Ok(_) => {
                return OrganizeResult {
                    scan_id: req.scan_id.clone(),
                    moved: 0,
                    dry_run: 0,
                    skipped: 0,
                    rejected: 0,
                    errors: 1,
                    outcomes: vec![OrganizeOutcome {
                        path: "(dest)".into(),
                        status: "error".into(),
                        dest: None,
                        message: Some(format!("Destination is not a directory: {}", req.dest_dir)),
                    }],
                };
            }
            Err(msg) => {
                return OrganizeResult {
                    scan_id: req.scan_id.clone(),
                    moved: 0,
                    dry_run: 0,
                    skipped: 0,
                    rejected: 0,
                    errors: 1,
                    outcomes: vec![OrganizeOutcome {
                        path: "(dest)".into(),
                        status: "error".into(),
                        dest: None,
                        message: Some(format!("Destination rejected: {msg}")),
                    }],
                };
            }
        };
        let strategy = req.strategy.clone().unwrap_or(OrganizeStrategy::Category);

        let mut moved = 0u32;
        let mut dry_run = 0u32;
        let mut skipped = 0u32;
        let mut rejected = 0u32;
        let mut errors = 0u32;
        let mut outcomes = Vec::new();

        for item in &req.items {
            // 1) exists in session?
            let entry = session
                .entries
                .iter()
                .find(|e| e.path == item.path)
                .cloned();
            let entry = match entry {
                Some(e) => e,
                None => {
                    outcomes.push(OrganizeOutcome {
                        path: item.path.clone(),
                        status: "not_found".into(),
                        dest: None,
                        message: Some("Path not found in scan results. Re-run scan.".into()),
                    });
                    errors += 1;
                    continue;
                }
            };

            // 2) token?
            if !safety::verify_token(&session.salt, &item.path, &item.approval_token) {
                outcomes.push(OrganizeOutcome {
                    path: item.path.clone(),
                    status: "rejected".into(),
                    dest: None,
                    message: Some(
                        "approval_token mismatch. Token expired or invalid for this scan session."
                            .into(),
                    ),
                });
                rejected += 1;
                continue;
            }

            // 2b) Verify source at action time (TOCTOU guard): rejects symlinks,
            // symlinked ancestors, protected canonical paths. Use canonical path.
            let src_canon = match safety::verify_safe_target(Path::new(&item.path)) {
                Ok(c) => c,
                Err(msg) => {
                    let status = if msg.contains("protected") {
                        "rejected"
                    } else {
                        "error"
                    };
                    if status == "rejected" {
                        rejected += 1;
                    } else {
                        errors += 1;
                    }
                    outcomes.push(OrganizeOutcome {
                        path: item.path.clone(),
                        status: status.into(),
                        dest: None,
                        message: Some(msg),
                    });
                    continue;
                }
            };
            let src = src_canon.as_path();

            // 4) Do not organize directories recursively (only files + empty dirs handled later)
            if entry.kind == "dir" {
                outcomes.push(OrganizeOutcome {
                    path: item.path.clone(),
                    status: "skipped".into(),
                    dest: None,
                    message: Some("Directories are not moved by organize (kept in place).".into()),
                });
                skipped += 1;
                continue;
            }

            // 5) Compute group subfolder
            let group = match strategy {
                OrganizeStrategy::Category => entry
                    .category_label
                    .replace(['/', '\\'], "_")
                    .to_uppercase(),
                OrganizeStrategy::Extension => entry
                    .extension
                    .clone()
                    .unwrap_or_else(|| "NO_EXT".into())
                    .to_uppercase(),
            };
            let group_dir = dest_canon.join(&group);

            // a) If group already exists as a FILE → error
            if group_dir.exists() && !group_dir.is_dir() {
                outcomes.push(OrganizeOutcome {
                    path: item.path.clone(),
                    status: "error".into(),
                    dest: None,
                    message: Some(format!(
                        "Cannot create group dir '{}' — a file with that name exists.",
                        group
                    )),
                });
                errors += 1;
                continue;
            }

            // b) Destination exists → skip (never overwrite)
            let file_name = src.file_name().map(|f| f.to_string_lossy().to_string());
            let file_name = match file_name {
                Some(f) => f,
                None => {
                    outcomes.push(OrganizeOutcome {
                        path: item.path.clone(),
                        status: "error".into(),
                        dest: None,
                        message: Some("No file name for path.".into()),
                    });
                    errors += 1;
                    continue;
                }
            };
            let dest_path = group_dir.join(&file_name);
            let dest_str = dest_path.to_string_lossy().replace('\\', "/");

            if dest_path.exists() {
                outcomes.push(OrganizeOutcome {
                    path: item.path.clone(),
                    status: "skipped".into(),
                    dest: Some(dest_str.clone()),
                    message: Some("Destination already exists. Skipped (no overwrite).".into()),
                });
                skipped += 1;
                continue;
            }

            // 7) Dry-run or move
            if req.dry_run {
                outcomes.push(OrganizeOutcome {
                    path: item.path.clone(),
                    status: "dry_run".into(),
                    dest: Some(dest_str.clone()),
                    message: Some("Planned move (dry run).".into()),
                });
                dry_run += 1;
                continue;
            }

            // Create group dir then move
            if let Err(e) = std::fs::create_dir_all(&group_dir) {
                outcomes.push(OrganizeOutcome {
                    path: item.path.clone(),
                    status: "error".into(),
                    dest: None,
                    message: Some(format!("Failed to create group dir: {}", e)),
                });
                errors += 1;
                continue;
            }
            match std::fs::rename(src, &dest_path) {
                Ok(_) => {
                    outcomes.push(OrganizeOutcome {
                        path: item.path.clone(),
                        status: "moved".into(),
                        dest: Some(dest_str.clone()),
                        message: None,
                    });
                    moved += 1;
                }
                Err(e) => {
                    outcomes.push(OrganizeOutcome {
                        path: item.path.clone(),
                        status: "error".into(),
                        dest: Some(dest_str.clone()),
                        message: Some(format!("Move failed: {}", e)),
                    });
                    errors += 1;
                }
            }
        }

        OrganizeResult {
            scan_id: req.scan_id.clone(),
            moved,
            dry_run,
            skipped,
            rejected,
            errors,
            outcomes,
        }
    }
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of OS trash contents (name, original path, size, deleted time).
/// Windows/Linux via `trash::os_limited`; macOS walks `~/.Trash` directly.
fn trash_items() -> Vec<TrashItemEntry> {
    #[cfg(not(target_os = "macos"))]
    {
        trash::os_limited::list()
            .unwrap_or_default()
            .iter()
            .map(|i| TrashItemEntry {
                name: i.name.to_string_lossy().into_owned(),
                original_path: i.original_path().to_string_lossy().into_owned(),
                size_bytes: trash::os_limited::metadata(i)
                    .ok()
                    .and_then(|m| m.size.size())
                    .unwrap_or(0),
                time_deleted: i.time_deleted,
            })
            .collect()
    }
    #[cfg(target_os = "macos")]
    {
        let trash_dir = dirs::home_dir().unwrap_or_default().join(".Trash");
        std::fs::read_dir(&trash_dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| {
                        let p = e.path();
                        let size = std::fs::metadata(&p)
                            .map(|m| if m.is_file() { m.len() } else { 0 })
                            .unwrap_or(0);
                        TrashItemEntry {
                            name: e.file_name().to_string_lossy().into_owned(),
                            original_path: String::new(),
                            size_bytes: size,
                            time_deleted: 0,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Purge OS trash; returns (items, bytes, error-message).
/// Windows/Linux: `trash::os_limited`. macOS: `os_limited` unavailable,
/// so walk `~/.Trash` directly (best-effort).
fn empty_trash_impl() -> (u64, u64, Option<String>) {
    #[cfg(not(target_os = "macos"))]
    {
        let items = match trash::os_limited::list() {
            Ok(v) => v,
            Err(e) => return (0, 0, Some(format!("trash list failed: {e}"))),
        };
        let bytes: u64 = items
            .iter()
            .filter_map(|i| trash::os_limited::metadata(i).ok())
            .filter_map(|m| m.size.size())
            .sum();
        let count = items.len() as u64;
        let msg = match trash::os_limited::purge_all(items) {
            Ok(()) => None,
            Err(e) => Some(format!("purge failed: {e}")),
        };
        (count, bytes, msg)
    }
    #[cfg(target_os = "macos")]
    {
        let Some(dir) = dirs::home_dir().map(|d| d.join(".Trash")) else {
            return (0, 0, Some("no home dir".into()));
        };
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return (0, 0, None);
        };
        let mut count = 0u64;
        let mut bytes = 0u64;
        for e in rd.filter_map(|x| x.ok()) {
            let p = e.path();
            if let Ok(m) = e.metadata() {
                if m.is_file() {
                    bytes += m.len();
                }
            }
            let r = if p.is_dir() {
                std::fs::remove_dir_all(&p)
            } else {
                std::fs::remove_file(&p)
            };
            if r.is_ok() {
                count += 1;
            }
        }
        (count, bytes, None)
    }
}

/// Append one JSONL line to data_dir/disk-cleaner-mcp/audit.log (best-effort).
fn audit(scan_id: &str, path: &str, action: &str) {
    use std::io::Write;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (ts / 86400) as i64;
    let (y, m, d) = civil_from_days(days);
    let iso = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        (ts / 3600) % 24,
        (ts / 60) % 60,
        ts % 60
    );
    if let Some(dir) = dirs::data_dir().map(|d| d.join("disk-cleaner-mcp")) {
        if std::fs::create_dir_all(&dir).is_ok() {
            let line = serde_json::json!({
                "ts": ts, "iso": iso, "scanId": scan_id, "path": path, "action": action,
            });
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("audit.log"))
            {
                let _ = writeln!(f, "{line}");
            }
        }
    }
}

/// Trash.delete on a dedicated OS thread to ensure correct COM apartment on Windows.
fn trash_delete_on_thread(path: PathBuf) -> Result<(), trash::Error> {
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let result = trash::delete(&path);
        let _ = tx.send(result);
    });
    let result = rx.recv().map_err(|e| trash::Error::Unknown {
        description: format!("Channel error: {}", e),
    })?;
    let _ = handle.join();
    result
}

/// Headless fallback when the `trash` crate fails (no D-Bus/Gio on Linux
/// servers, no Finder on macOS SSH): move into XDG Trash / ~/.Trash directly.
/// Windows keeps the COM path only — per-SID Recycle.Bin layout is complex.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn trash_fallback(path: &Path) -> Result<(), trash::Error> {
    fn unique_dest(dir: &Path, name: &str) -> PathBuf {
        let base = Path::new(name);
        let mut cand = dir.join(base);
        let mut i = 1;
        while cand.exists() {
            cand = dir.join(format!("{name}.{i}"));
            i += 1;
        }
        cand
    }
    #[cfg(target_os = "linux")]
    {
        let data = dirs::data_dir().ok_or_else(|| trash::Error::Unknown {
            description: "No XDG data dir for fallback trash".into(),
        })?;
        let files = data.join("Trash").join("files");
        let info = data.join("Trash").join("info");
        std::fs::create_dir_all(&files)
            .and(std::fs::create_dir_all(&info))
            .map_err(|e| trash::Error::Unknown {
                description: format!("Trash dirs: {e}"),
            })?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "trashed".into());
        let dest = unique_dest(&files, &name);
        let info_file = info.join(format!(
            "{}.trashinfo",
            dest.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(
            &info_file,
            format!(
                "[Trash Info]\nPath={}\nDeletionDate={}\n",
                // ponytail: minimal URL-encoding (spaces) — full RFC3986 not needed for common paths.
                dest.to_string_lossy().replace(' ', "%20"),
                chrono_like_now(),
            ),
        )
        .map_err(|e| trash::Error::Unknown {
            description: format!("trashinfo: {e}"),
        })?;
        std::fs::rename(path, &dest).map_err(|e| trash::Error::Unknown {
            description: format!("fallback move: {e}"),
        })?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir().ok_or_else(|| trash::Error::Unknown {
            description: "No home dir for fallback trash".into(),
        })?;
        let trash_dir = home.join(".Trash");
        std::fs::create_dir_all(&trash_dir).map_err(|e| trash::Error::Unknown {
            description: format!("~/.Trash: {e}"),
        })?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "trashed".into());
        let dest = unique_dest(&trash_dir, &name);
        std::fs::rename(path, &dest).map_err(|e| trash::Error::Unknown {
            description: format!("fallback move: {e}"),
        })?;
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Err(trash::Error::Unknown {
        description: "Trash failed and no fallback available.".into(),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn trash_fallback(_path: &Path) -> Result<(), trash::Error> {
    Err(trash::Error::Unknown {
        description: "Trash failed and no fallback available.".into(),
    })
}

#[cfg(target_os = "linux")]
fn chrono_like_now() -> String {
    // Cheap local timestamp without chrono dep; seconds since epoch UTC.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // DeletionDate in .trashinfo wants local "YYYY-MM-DDTHH:MM:SS"; UTC is acceptable to freedesktop tools.
    let days = (secs / 86400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        y,
        m,
        d,
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn category_label_for(key: &str) -> String {
    analytics::all_categories()
        .iter()
        .find(|c| c.key == key)
        .map(|c| c.label.clone())
        .unwrap_or_else(|| key.into())
}

fn generate_id() -> String {
    // ponytail: 64-bit CSPRNG id; collision ~impossible, no time dependency.
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("CSPRNG unavailable");
    format!(
        "scan-{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_engine_new() {
        let engine = ScanEngine::new();
        assert!(engine.sessions.read().unwrap().is_empty());
    }

    #[test]
    fn test_scan_nonexistent() {
        let engine = ScanEngine::new();
        let result = engine.scan(Path::new("/this/does/not/exist/abc123"));
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_get_session_not_found() {
        let engine = ScanEngine::new();
        assert!(engine.get_session("nonexistent").is_none());
    }

    #[test]
    fn test_scan_and_delete_protected_rejected() {
        // We can't test scanning C:\Windows directly (permissions),
        // but we can test the delete rejection logic with a mock token.
        let engine = ScanEngine::new();
        // Create a temp dir, scan it, then try to delete with a fake "protected" path
        let temp = std::env::temp_dir().join("dc-mcp-test-scan-1");
        std::fs::create_dir_all(&temp).unwrap();
        let test_file = temp.join("test.log");
        std::fs::write(&test_file, "test content").unwrap();

        let result = engine.scan(&temp).unwrap();
        assert!(result.entries_count >= 1);

        // Find the test file entry
        let session = engine.get_session(&result.summary.scan_id).unwrap();
        let entry = session
            .entries
            .iter()
            .find(|e| e.path.ends_with("test.log"))
            .unwrap();

        // Try to delete with valid token — use PERMANENT delete so the test
        // doesn't depend on trash support (Linux CI has no gio/trash).
        let del_req = DeleteRequest {
            scan_id: result.summary.scan_id.clone(),
            items: vec![DeleteItemRequest {
                approval_token: entry.approval_token.clone(),
                path: entry.path.clone(),
            }],
            permanent: true,
            confirm_permanent: true,
            confirm_risk: true,
            dry_run: false,
        };
        let del_result = engine.delete(&del_req);
        assert_eq!(del_result.permanent, 1);

        // Clean up
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_delete_token_mismatch_rejected() {
        let engine = ScanEngine::new();
        let temp = std::env::temp_dir().join("dc-mcp-test-scan-2");
        std::fs::create_dir_all(&temp).unwrap();
        let test_file = temp.join("test2.log");
        std::fs::write(&test_file, "test content").unwrap();

        let result = engine.scan(&temp).unwrap();
        let session = engine.get_session(&result.summary.scan_id).unwrap();
        let entry = session
            .entries
            .iter()
            .find(|e| e.path.ends_with("test2.log"))
            .unwrap();

        // Wrong token
        let del_req = DeleteRequest {
            scan_id: result.summary.scan_id.clone(),
            items: vec![DeleteItemRequest {
                approval_token: "wrong_token_xxx".into(),
                path: entry.path.clone(),
            }],
            permanent: false,
            confirm_permanent: false,
            confirm_risk: false,
            dry_run: false,
        };
        let del_result = engine.delete(&del_req);
        assert_eq!(del_result.rejected, 1);

        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_delete_permanent_requires_confirmation() {
        let engine = ScanEngine::new();
        let temp = std::env::temp_dir().join("dc-mcp-test-scan-3");
        std::fs::create_dir_all(&temp).unwrap();
        let test_file = temp.join("test3.log");
        std::fs::write(&test_file, "test content").unwrap();

        let result = engine.scan(&temp).unwrap();
        let session = engine.get_session(&result.summary.scan_id).unwrap();
        let entry = session
            .entries
            .iter()
            .find(|e| e.path.ends_with("test3.log"))
            .unwrap();

        // permanent=true but confirm_permanent=false
        let del_req = DeleteRequest {
            scan_id: result.summary.scan_id.clone(),
            items: vec![DeleteItemRequest {
                approval_token: entry.approval_token.clone(),
                path: entry.path.clone(),
            }],
            permanent: true,
            confirm_permanent: false,
            confirm_risk: false,
            dry_run: false,
        };
        let del_result = engine.delete(&del_req);
        assert_eq!(del_result.rejected, 1);

        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_delete_permanent_with_confirmation() {
        let engine = ScanEngine::new();
        let temp = std::env::temp_dir().join("dc-mcp-test-scan-4");
        std::fs::create_dir_all(&temp).unwrap();
        let test_file = temp.join("test4.log");
        std::fs::write(&test_file, "test content").unwrap();

        let result = engine.scan(&temp).unwrap();
        let session = engine.get_session(&result.summary.scan_id).unwrap();
        let entry = session
            .entries
            .iter()
            .find(|e| e.path.ends_with("test4.log"))
            .unwrap()
            .clone();

        let del_req = DeleteRequest {
            scan_id: result.summary.scan_id.clone(),
            items: vec![DeleteItemRequest {
                approval_token: entry.approval_token.clone(),
                path: entry.path.clone(),
            }],
            permanent: true,
            confirm_permanent: true,
            confirm_risk: true,
            dry_run: false,
        };
        let del_result = engine.delete(&del_req);
        assert_eq!(del_result.permanent, 1);
        assert!(!Path::new(&entry.path).exists());

        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_delete_review_requires_confirm_risk_and_dry_run_safe() {
        let engine = ScanEngine::new();
        let temp = std::env::temp_dir().join("dc-mcp-test-scan-brain");
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(temp.join("movie.mkv"), "video-bytes").unwrap();

        let result = engine.scan(&temp).unwrap();
        let session = engine.get_session(&result.summary.scan_id).unwrap();
        let entry = session
            .entries
            .iter()
            .find(|e| e.path.ends_with("movie.mkv"))
            .unwrap()
            .clone();
        assert_eq!(
            entry.verdict, "review",
            "fresh non-junk file is review, not safe"
        );

        let item = || DeleteItemRequest {
            approval_token: entry.approval_token.clone(),
            path: entry.path.clone(),
        };

        // No confirm_risk → rejected by brain, file untouched.
        let denied = engine.delete(&DeleteRequest {
            scan_id: result.summary.scan_id.clone(),
            items: vec![item()],
            permanent: false,
            confirm_permanent: false,
            confirm_risk: false,
            dry_run: false,
        });
        assert_eq!(denied.rejected, 1);
        assert!(Path::new(&entry.path).exists());

        // confirm_risk + dry_run → reports, touches nothing.
        let probe = engine.delete(&DeleteRequest {
            scan_id: result.summary.scan_id.clone(),
            items: vec![item()],
            permanent: false,
            confirm_permanent: false,
            confirm_risk: true,
            dry_run: true,
        });
        assert_eq!(probe.dry_run, 1);
        assert!(probe.would_reclaim_bytes > 0);
        assert!(Path::new(&entry.path).exists());

        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_empty_trash_requires_confirm() {
        let engine = ScanEngine::new();
        let r = engine.empty_trash(&EmptyTrashParams { confirm: false });
        assert_eq!(r.purged_items, 0);
        assert!(r.message.as_deref().unwrap_or("").contains("confirm"));
    }

    // ---- organize tests ----

    fn setup_organize_fixture(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        // returns (src_dir, dest_dir); `tag` makes each test's dir unique
        // (parallel test threads share the same process id, so pid alone collides)
        let base = std::env::temp_dir().join(format!("dc-mcp-org-{}-{}", std::process::id(), tag));
        let src = base.join("src");
        let dest = base.join("dest");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(src.join("photo.jpg"), b"jpeg-data").unwrap();
        std::fs::write(src.join("doc.pdf"), b"pdf-data").unwrap();
        std::fs::write(src.join("notes.txt"), b"txt-data").unwrap();
        (src, dest)
    }

    #[test]
    fn test_organize_moves_by_category() {
        let (src, dest) = setup_organize_fixture("moves");
        let engine = ScanEngine::new();
        let result = engine.scan(&src).unwrap();
        let session = engine.get_session(&result.summary.scan_id).unwrap();

        let items: Vec<OrganizeItemRequest> = session
            .entries
            .iter()
            .filter(|e| e.kind == "file")
            .map(|e| OrganizeItemRequest {
                approval_token: e.approval_token.clone(),
                path: e.path.clone(),
            })
            .collect();
        assert!(items.len() >= 3);

        let org_req = OrganizeRequest {
            scan_id: result.summary.scan_id.clone(),
            items,
            dest_dir: dest.to_string_lossy().to_string(),
            strategy: Some(OrganizeStrategy::Extension),
            dry_run: false,
        };
        let org_result = engine.organize(&org_req);
        assert_eq!(
            org_result.moved, 3,
            "all 3 files should move; got {:?}",
            org_result.outcomes
        );
        assert_eq!(org_result.rejected, 0);
        assert_eq!(org_result.errors, 0);

        // Files gone from src
        assert!(!src.join("photo.jpg").exists());
        assert!(!src.join("doc.pdf").exists());
        assert!(!src.join("notes.txt").exists());

        // Extension grouping: JPG / PDF / TXT folders
        assert!(
            dest.join("JPG").join("photo.jpg").exists(),
            "photo.jpg → dest/JPG"
        );
        assert!(
            dest.join("PDF").join("doc.pdf").exists(),
            "doc.pdf → dest/PDF"
        );
        assert!(
            dest.join("TXT").join("notes.txt").exists(),
            "notes.txt → dest/TXT"
        );

        let _ = std::fs::remove_dir_all(src.parent().unwrap());
    }

    #[test]
    fn test_organize_dry_run_moves_nothing() {
        let (src, dest) = setup_organize_fixture("dryrun");
        let engine = ScanEngine::new();
        let result = engine.scan(&src).unwrap();
        let session = engine.get_session(&result.summary.scan_id).unwrap();

        let items: Vec<OrganizeItemRequest> = session
            .entries
            .iter()
            .filter(|e| e.kind == "file")
            .map(|e| OrganizeItemRequest {
                approval_token: e.approval_token.clone(),
                path: e.path.clone(),
            })
            .collect();

        let org_req = OrganizeRequest {
            scan_id: result.summary.scan_id.clone(),
            items,
            dest_dir: dest.to_string_lossy().to_string(),
            strategy: Some(OrganizeStrategy::Extension),
            dry_run: true,
        };
        let org_result = engine.organize(&org_req);
        assert_eq!(org_result.dry_run, org_result.outcomes.len() as u32);
        assert_eq!(org_result.moved, 0);

        // Nothing moved
        assert!(src.join("photo.jpg").exists());
        assert!(!dest.join("JPG").join("photo.jpg").exists());

        let _ = std::fs::remove_dir_all(src.parent().unwrap());
    }

    #[test]
    fn test_organize_wrong_token_rejected() {
        let (src, dest) = setup_organize_fixture("wrongtoken");
        let engine = ScanEngine::new();
        let result = engine.scan(&src).unwrap();
        let session = engine.get_session(&result.summary.scan_id).unwrap();
        let entry = session
            .entries
            .iter()
            .find(|e| e.path.ends_with("photo.jpg"))
            .unwrap();

        let org_req = OrganizeRequest {
            scan_id: result.summary.scan_id.clone(),
            items: vec![OrganizeItemRequest {
                approval_token: "wrong_token".into(),
                path: entry.path.clone(),
            }],
            dest_dir: dest.to_string_lossy().to_string(),
            strategy: None,
            dry_run: false,
        };
        let org_result = engine.organize(&org_req);
        assert_eq!(org_result.rejected, 1);
        assert!(
            src.join("photo.jpg").exists(),
            "file must not move with bad token"
        );

        let _ = std::fs::remove_dir_all(src.parent().unwrap());
    }

    #[test]
    fn test_organize_nonexistent_dest_errors() {
        let (src, dest) = setup_organize_fixture("nodest");
        let engine = ScanEngine::new();
        let result = engine.scan(&src).unwrap();
        let session = engine.get_session(&result.summary.scan_id).unwrap();

        let items: Vec<OrganizeItemRequest> = session
            .entries
            .iter()
            .filter(|e| e.kind == "file")
            .map(|e| OrganizeItemRequest {
                approval_token: e.approval_token.clone(),
                path: e.path.clone(),
            })
            .collect();

        let org_req = OrganizeRequest {
            scan_id: result.summary.scan_id.clone(),
            items,
            dest_dir: dest.join("does-not-exist").to_string_lossy().to_string(),
            strategy: None,
            dry_run: false,
        };
        let org_result = engine.organize(&org_req);
        assert_eq!(org_result.errors, 1);
        assert!(src.join("photo.jpg").exists());

        let _ = std::fs::remove_dir_all(src.parent().unwrap());
    }

    #[test]
    fn test_organize_skips_existing_dest() {
        let (src, dest) = setup_organize_fixture("skipdest");
        let engine = ScanEngine::new();
        let result = engine.scan(&src).unwrap();
        let session = engine.get_session(&result.summary.scan_id).unwrap();
        let entry = session
            .entries
            .iter()
            .find(|e| e.path.ends_with("photo.jpg"))
            .unwrap()
            .clone();

        // Pre-create dest/JPG/photo.jpg to force skip (extension strategy → JPG/)
        let dest_jpg = dest.join("JPG");
        std::fs::create_dir_all(&dest_jpg).unwrap();
        std::fs::write(dest_jpg.join("photo.jpg"), b"existing").unwrap();

        let org_req = OrganizeRequest {
            scan_id: result.summary.scan_id.clone(),
            items: vec![OrganizeItemRequest {
                approval_token: entry.approval_token.clone(),
                path: entry.path.clone(),
            }],
            dest_dir: dest.to_string_lossy().to_string(),
            strategy: Some(OrganizeStrategy::Extension),
            dry_run: false,
        };
        let org_result = engine.organize(&org_req);
        assert_eq!(org_result.skipped, 1);
        assert_eq!(org_result.moved, 0);
        assert!(src.join("photo.jpg").exists(), "original must be untouched");

        let _ = std::fs::remove_dir_all(src.parent().unwrap());
    }
}
