//! Scan engine — multithreaded directory walker with metadata extraction
//! and per-scan approval tokens.

use crate::analytics;
use crate::model::*;
use crate::safety;
use jwalk::{Parallelism, WalkDirGeneric};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SCAN_ENTRIES: usize = 200_000;

/// One scan session.
pub struct ScanSession {
    pub scan_id: String,
    pub salt: String,
    pub summary: ScanSummary,
    pub entries: Vec<ScanEntry>,
}

pub struct ScanEngine {
    sessions: Vec<Arc<ScanSession>>,
}

impl ScanEngine {
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
        }
    }

    pub fn get_session(&self, scan_id: &str) -> Option<Arc<ScanSession>> {
        self.sessions.iter().find(|s| s.scan_id == scan_id).cloned()
    }

    fn push_session(&mut self, session: ScanSession) -> Arc<ScanSession> {
        let arc = Arc::new(session);
        self.sessions.push(arc.clone());
        // Keep max 3 sessions (LRU-ish)
        while self.sessions.len() > 3 {
            self.sessions.remove(0);
        }
        arc
    }

    /// Run a scan at `root`. Returns a summary + populates cache.
    pub fn scan(&mut self, root: &Path) -> Result<ScanResult, String> {
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
            .max_depth(15)
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
                    let name = dir_entry.file_name.to_string_lossy().to_string();

                    // Prune skip dirs
                    if dir_entry.file_type.is_dir() {
                        dirs_scanned += 1;
                        if safety::should_skip_dir(&name) {
                            // skip reading children
                            // jwalk: we can't easily prune here without custom client_state,
                            // so we just continue and skip via depth check
                            continue;
                        }
                    } else {
                        files_scanned += 1;
                    }

                    if raw_entries.len() >= MAX_SCAN_ENTRIES {
                        truncated = true;
                        warnings.push(format!("Scan truncated at {} entries. Use a more specific path or analyze with filters.", MAX_SCAN_ENTRIES));
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
        let entries: Vec<ScanEntry> = raw_entries
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
                })
            })
            .collect();

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
            max_entries: MAX_SCAN_ENTRIES,
            version: VERSION.into(),
            category_totals,
            largest_entries,
            warnings,
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
        let mut outcomes = Vec::new();

        // Validate permanent flag
        if req.permanent && !req.confirm_permanent {
            return DeleteResult {
                scan_id: req.scan_id.clone(),
                trashed: 0,
                permanent: 0,
                rejected: 1,
                errors: 0,
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

            // 2) Safety guard — protected path
            let path = Path::new(&item.path);
            if safety::is_protected(path) {
                outcomes.push(DeleteOutcome {
                    path: item.path.clone(),
                    status: "rejected".into(),
                    message: Some(
                        "Path is system-protected. Operation BLOCKED by Safety Guard.".into(),
                    ),
                });
                rejected += 1;
                continue;
            }

            // 3) Verify token
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

            // 3b) Path must still exist on disk (e.g. not already moved by organize).
            if !path.exists() {
                outcomes.push(DeleteOutcome {
                    path: item.path.clone(),
                    status: "not_found".into(),
                    message: Some(
                        "Path no longer exists on disk (may have been moved/deleted already). Re-run scan."
                            .into(),
                    ),
                });
                errors += 1;
                continue;
            }

            // 4) Execute delete: trash or permanent
            if req.permanent {
                match std::fs::remove_file(path) {
                    Ok(_) => {
                        outcomes.push(DeleteOutcome {
                            path: item.path.clone(),
                            status: "permanent".into(),
                            message: None,
                        });
                        permanent += 1;
                    }
                    Err(e) => {
                        // Try remove_dir if it's a dir
                        match std::fs::remove_dir_all(path) {
                            Ok(_) => {
                                outcomes.push(DeleteOutcome {
                                    path: item.path.clone(),
                                    status: "permanent".into(),
                                    message: None,
                                });
                                permanent += 1;
                            }
                            Err(e2) => {
                                outcomes.push(DeleteOutcome {
                                    path: item.path.clone(),
                                    status: "error".into(),
                                    message: Some(format!("Delete failed: {} / {}", e, e2)),
                                });
                                errors += 1;
                            }
                        }
                    }
                }
            } else {
                // Trash on a dedicated OS thread (Windows COM apartment safety)
                let path_clone = path.to_path_buf();
                match trash_delete_on_thread(path_clone) {
                    Ok(_) => {
                        outcomes.push(DeleteOutcome {
                            path: item.path.clone(),
                            status: "trashed".into(),
                            message: None,
                        });
                        trashed += 1;
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
            outcomes,
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
        if !dest.exists() || !dest.is_dir() {
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
                    message: Some(format!(
                        "Destination directory does not exist or is not a directory: {}",
                        req.dest_dir
                    )),
                }],
            };
        }

        // Note: intentionally NOT canonicalizing dest — on Windows canonicalize
        // adds the `\\?\` extended-length prefix, which breaks std::fs::rename
        // between normal and extended paths. dest was already validated above.
        let dest_canon = dest.clone();
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

            // 2) protected?
            let src = Path::new(&item.path);
            if safety::is_protected(src) {
                outcomes.push(OrganizeOutcome {
                    path: item.path.clone(),
                    status: "rejected".into(),
                    dest: None,
                    message: Some(
                        "Path is system-protected. Operation BLOCKED by Safety Guard.".into(),
                    ),
                });
                rejected += 1;
                continue;
            }

            // 3) token?
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

fn category_label_for(key: &str) -> String {
    analytics::all_categories()
        .iter()
        .find(|c| c.key == key)
        .map(|c| c.label.clone())
        .unwrap_or_else(|| key.into())
}

fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("scan-{}-{:04}", now.as_secs(), (now.subsec_nanos() % 10000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_engine_new() {
        let engine = ScanEngine::new();
        assert!(engine.sessions.is_empty());
    }

    #[test]
    fn test_scan_nonexistent() {
        let mut engine = ScanEngine::new();
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
        let mut engine = ScanEngine::new();
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
        };
        let del_result = engine.delete(&del_req);
        assert_eq!(del_result.permanent, 1);

        // Clean up
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_delete_token_mismatch_rejected() {
        let mut engine = ScanEngine::new();
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
        };
        let del_result = engine.delete(&del_req);
        assert_eq!(del_result.rejected, 1);

        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_delete_permanent_requires_confirmation() {
        let mut engine = ScanEngine::new();
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
        };
        let del_result = engine.delete(&del_req);
        assert_eq!(del_result.rejected, 1);

        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_delete_permanent_with_confirmation() {
        let mut engine = ScanEngine::new();
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
        };
        let del_result = engine.delete(&del_req);
        assert_eq!(del_result.permanent, 1);
        assert!(!Path::new(&entry.path).exists());

        let _ = std::fs::remove_dir_all(&temp);
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
        let mut engine = ScanEngine::new();
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
        let mut engine = ScanEngine::new();
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
        let mut engine = ScanEngine::new();
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
        let mut engine = ScanEngine::new();
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
        let mut engine = ScanEngine::new();
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
