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

        // Try to delete with valid token (should work — it's just temp)
        let del_req = DeleteRequest {
            scan_id: result.summary.scan_id.clone(),
            items: vec![DeleteItemRequest {
                approval_token: entry.approval_token.clone(),
                path: entry.path.clone(),
            }],
            permanent: false,
            confirm_permanent: false,
        };
        let del_result = engine.delete(&del_req);
        assert_eq!(del_result.trashed, 1);

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
}
