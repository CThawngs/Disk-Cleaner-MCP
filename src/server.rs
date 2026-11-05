//! MCP Server handler — defines all tools using rmcp macros.

use crate::analytics;
use crate::engine::ScanEngine;
use crate::insights;
use crate::model::*;
use crate::sysinfo_helper;
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// MCP server state.
#[derive(Clone)]
pub struct DiskCleanerServer {
    engine: Arc<ScanEngine>,
    #[allow(dead_code)] // held by #[tool_router] macro internals
    tool_router: ToolRouter<Self>,
}

impl DiskCleanerServer {
    pub fn new() -> Self {
        Self {
            engine: Arc::new(ScanEngine::new()),
            tool_router: Self::tool_router(),
        }
    }
}

impl Default for DiskCleanerServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl DiskCleanerServer {
    /// Get system status: platform, disks, user directories.
    #[tool(
        name = "get_system_status",
        description = "Get system info: platform (Windows/macOS/Linux), disk usage, home/temp/download dirs. Read-only, safe to call anytime."
    )]
    async fn get_system_status(&self) -> String {
        let status = sysinfo_helper::get_system_status();
        serde_json::to_string_pretty(&status).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// List all junk categories.
    #[tool(
        name = "list_categories",
        description = "List all file categories the server can classify: temp, log, cache, browser_cache, node_cache, python_cache, installer, download, backup, archive, crash_dump, thumbnail, other."
    )]
    async fn list_categories(&self) -> String {
        let cats = analytics::all_categories();
        serde_json::to_string_pretty(&cats).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Scan a root path for files.
    #[tool(
        name = "scan",
        description = "Scan a root path for files and junk. Returns a summary with scanId, category totals, and top 20 largest files. Use 'analyze' with the scanId to filter and paginate entries.\n\nSafety: NEVER scan C:\\Windows, C:\\Program Files, /usr, /boot, or other system paths. The scan is read-only — file content is never read, only metadata (size, modified, path).\n\nParameters:\n- root: Root path to scan (default: user Downloads dir if omitted)"
    )]
    async fn scan(&self, Parameters(params): Parameters<ScanParams>) -> String {
        let root_path = match params.root {
            Some(r) if !r.is_empty() => r,
            _ => dirs::download_dir()
                .map(|d| d.to_string_lossy().to_string())
                .unwrap_or_else(|| {
                    dirs::home_dir()
                        .map(|d| d.to_string_lossy().to_string())
                        .unwrap_or_else(|| ".".into())
                }),
        };

        let engine = self.engine.clone();
        // ponytail: full scan blocks for seconds — keep it off the async executor.
        let result =
            tokio::task::spawn_blocking(move || engine.scan(std::path::Path::new(&root_path)))
                .await
                .unwrap_or_else(|e| Err(format!("Scan task failed: {e}")));

        match result {
            Ok(scan_result) => serde_json::to_string_pretty(&scan_result)
                .unwrap_or_else(|e| format!("Error serializing: {}", e)),
            Err(e) => {
                let err = serde_json::json!({
                    "error": true,
                    "message": e,
                });
                serde_json::to_string_pretty(&err).unwrap_or(e)
            }
        }
    }

    /// Analyze / filter scan entries.
    #[tool(
        name = "analyze",
        description = "Filter and paginate entries from a previous scan. Requires scanId from scan().\n\nFilters:\n- kind: 'file' or 'dir'\n- category: one of list_categories() keys\n- name_glob: glob pattern like '*.log'\n- extension: file extension like 'log'\n- min_size: minimum size in bytes\n- min_age_days: minimum age in days (based on modified time)\n\nSorting:\n- sort_by: 'size' (default), 'modified', or 'name'\n- sort_desc: true (default)\n\nPagination:\n- offset: starting index (default 0)\n- limit: page size (default 100, max 500)\n\nReturns entries with approvalToken for each file."
    )]
    async fn analyze(&self, Parameters(params): Parameters<AnalyzeParams>) -> String {
        match self.engine.get_session(&params.scan_id) {
            Some(session) => {
                let req = AnalyzeRequest {
                    scan_id: params.scan_id.clone(),
                    kind: params.kind,
                    category: params.category,
                    name_glob: params.name_glob,
                    extension: params.extension,
                    min_size: params.min_size,
                    min_age_days: params.min_age_days,
                    sort_by: params.sort_by,
                    sort_desc: params.sort_desc,
                    offset: params.offset,
                    limit: params.limit,
                };
                let (entries, total) = analytics::analyze_entries(&session.entries, &req);
                let result = serde_json::json!({
                    "scanId": params.scan_id,
                    "page": entries,
                    "total": total,
                    "pageSize": entries.len(),
                });
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            None => {
                let err = serde_json::json!({
                    "error": true,
                    "message": format!("Scan '{}' not found. Run scan first.", params.scan_id),
                });
                serde_json::to_string_pretty(&err).unwrap_or_else(|_| "Error".into())
            }
        }
    }

    /// Delete files (trash or permanent).
    #[tool(
        name = "delete",
        description = "Delete files from a previous scan. Requires scanId + items with approvalToken from analyze().\n\nSafety:\n- Default action: move to Recycle Bin/Trash (recoverable)\n- Permanent delete requires permanent=true AND confirm_permanent=true\n- Brain judges every file: safe_to_delete (trash ok), review/keep (needs confirm_risk=true after user approval), blocked (never)\n- dry_run=true reports what would be deleted without touching disk\n- System-protected paths (C:\\Windows, /usr, etc.) are ALWAYS rejected\n- Each item must have a valid approvalToken from the original scan\n\nParameters:\n- scanId: from scan()\n- items: array of { approvalToken, path }\n- permanent: true for permanent delete (default: false = trash)\n- confirm_permanent: must be true if permanent=true\n- confirm_risk: must be true to delete brain review/keep files\n- dry_run: report only, delete nothing"
    )]
    async fn delete(&self, Parameters(params): Parameters<DeleteParams>) -> String {
        let engine = self.engine.clone();
        let req = DeleteRequest {
            scan_id: params.scan_id.clone(),
            items: params.items.clone(),
            permanent: params.permanent,
            confirm_permanent: params.confirm_permanent,
            confirm_risk: params.confirm_risk,
            dry_run: params.dry_run,
        };
        let scan_id = req.scan_id.clone();
        // ponytail: trash/permanent IO blocks — off the async executor.
        let result = tokio::task::spawn_blocking(move || engine.delete(&req))
            .await
            .unwrap_or_else(|e| DeleteResult {
                scan_id,
                trashed: 0,
                permanent: 0,
                rejected: 0,
                errors: 1,
                dry_run: 0,
                would_reclaim_bytes: 0,
                outcomes: vec![DeleteOutcome {
                    path: "(task)".into(),
                    status: "error".into(),
                    message: Some(format!("Delete task failed: {e}")),
                }],
            });
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Organize files into subfolders by category/extension.
    #[tool(
        name = "organize",
        description = "Organize files into the destination directory, grouped into subfolders by category (default) or extension. Safe: token-verified (like delete), NEVER overwrites existing files, protected system paths are rejected, directories are skipped (not moved).\n\nParameters:\n- scanId: from scan()\n- items: array of { approvalToken, path } from analyze()\n- destDir: existing destination directory (server will NOT create it; creates only group subfolders inside it)\n- strategy: 'category' (default) or 'extension'\n- dryRun: true → only compute planned moves, move nothing\n\nExample: organize(scanId, [{approvalToken, path}], 'C:/Users/me/Organized', strategy='category') moves a .jpg into .../Organized/Images/, a .log into .../Organized/Log Files/."
    )]
    async fn organize(&self, Parameters(params): Parameters<OrganizeParams>) -> String {
        let engine = self.engine.clone();
        let req = OrganizeRequest {
            scan_id: params.scan_id.clone(),
            items: params.items.clone(),
            dest_dir: params.dest_dir.clone(),
            strategy: params.strategy,
            dry_run: params.dry_run,
        };
        let scan_id = req.scan_id.clone();
        // ponytail: rename IO blocks — off the async executor.
        let result = tokio::task::spawn_blocking(move || engine.organize(&req))
            .await
            .unwrap_or_else(|e| OrganizeResult {
                scan_id,
                moved: 0,
                dry_run: 0,
                skipped: 0,
                rejected: 0,
                errors: 1,
                outcomes: vec![OrganizeOutcome {
                    path: "(task)".into(),
                    status: "error".into(),
                    dest: None,
                    message: Some(format!("Organize task failed: {e}")),
                }],
            });
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Get a markdown report of scan results.
    #[tool(
        name = "get_report",
        description = "Generate a Markdown report of a scan. Requires scanId. Returns a formatted report with category breakdown and top files."
    )]
    async fn get_report(&self, Parameters(params): Parameters<ReportParams>) -> String {
        match self.engine.get_session(&params.scan_id) {
            Some(session) => analytics::generate_report(&session.summary, &session.entries),
            None => format!(
                "# Error\n\nScan '{}' not found. Run scan first.",
                params.scan_id
            ),
        }
    }

    // ── TreeSize-grade insights (all read-only, operate on cached scan entries) ──

    /// TreeSize-style recursive folder tree.
    #[tool(
        name = "get_tree",
        description = "TreeSize-style aggregated folder tree: every folder with its RECURSIVE size (this folder + all descendants), file counts, and share of the scan root. Use it to answer 'where did the space go' before picking files. Requires scanId from scan(). Read-only.\n\nParameters:\n- scanId: from scan()\n- top: max children per folder (default 10). Truncated folders are folded into a '(+N more)' rollup so totals stay exact."
    )]
    async fn get_tree(&self, Parameters(params): Parameters<TreeParams>) -> String {
        match self.engine.get_session(&params.scan_id) {
            Some(session) => {
                let tree = insights::build_tree(
                    &session.entries,
                    &session.summary.root,
                    params.top.unwrap_or(10).clamp(1, 50),
                );
                serde_json::to_string_pretty(&tree).unwrap_or_else(|e| format!("Error: {}", e))
            }
            None => scan_not_found(&params.scan_id),
        }
    }

    /// Per-extension size breakdown.
    #[tool(
        name = "file_types",
        description = "TreeSize-style file-type breakdown: total size and count per file extension, largest first. Shows WHAT is eating space (videos, archives, logs...). Requires scanId from scan(). Read-only.\n\nParameters:\n- scanId: from scan()\n- limit: max extensions returned (default 30) sorted by size desc."
    )]
    async fn file_types(&self, Parameters(params): Parameters<FileTypesParams>) -> String {
        match self.engine.get_session(&params.scan_id) {
            Some(session) => {
                let report = insights::file_types(
                    &session.entries,
                    &params.scan_id,
                    params.limit.unwrap_or(30).clamp(1, 200),
                );
                serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("Error: {}", e))
            }
            None => scan_not_found(&params.scan_id),
        }
    }

    /// Content-hash duplicate finder with safe-delete tokens.
    #[tool(
        name = "find_duplicates",
        description = "TreeSize-style duplicate file finder: groups files with byte-identical content (same size + SHA-256; files >4GB use sampled head+tail hash, flagged partial — verify before delete), reports wasted bytes, and returns each copy's approvalToken so you can delete redundant copies via delete(). Content is only read for files that share a size with another file.\n\nParameters:\n- scanId: from scan()\n- minSize: minimum file size in bytes to consider (default 1048576 = 1 MiB; use 0 to include small files)\n- top: max groups returned (default 50), sorted by wasted bytes desc.\n\nSafety: never delete ALL copies — keep at least one (files are oldest-first; files[0] is usually the original)."
    )]
    async fn find_duplicates(&self, Parameters(params): Parameters<DuplicateParams>) -> String {
        match self.engine.get_session(&params.scan_id) {
            Some(session) => {
                let min_size = params.min_size.unwrap_or(1_048_576);
                let report = insights::find_duplicates(
                    &session.entries,
                    &params.scan_id,
                    min_size,
                    params.top.unwrap_or(50).clamp(1, 200),
                );
                serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("Error: {}", e))
            }
            None => scan_not_found(&params.scan_id),
        }
    }

    /// Diff two scans (TreeSize "compare over time").
    #[tool(
        name = "compare_scans",
        description = "TreeSize-style 'compare over time': diff two scans of the same tree and see what changed — files added, removed, and size changes, plus net delta (negative = space freed). Requires TWO live scanIds from scan() (scans are cached in RAM, max 3 — re-scan both roots if a session was evicted).\n\nParameters:\n- scanIdA: earlier scan\n- scanIdB: later scan\n- top: max rows per section (default 50)."
    )]
    async fn compare_scans(&self, Parameters(params): Parameters<CompareParams>) -> String {
        let (sa, sb) = match (
            self.engine.get_session(&params.scan_id_a),
            self.engine.get_session(&params.scan_id_b),
        ) {
            (Some(a), Some(b)) => (a, b),
            (missing_a, missing_b) => {
                let missing = [
                    ("A", &params.scan_id_a, missing_a.is_none()),
                    ("B", &params.scan_id_b, missing_b.is_none()),
                ]
                .into_iter()
                .filter(|(_, _, m)| *m)
                .map(|(slot, id, _)| format!("{} ('{}')", slot, id))
                .collect::<Vec<_>>()
                .join(" and ");
                return scan_not_found(&missing);
            }
        };
        let snap_a = insights::build_snapshot(&sa.summary, &sa.entries);
        let snap_b = insights::build_snapshot(&sb.summary, &sb.entries);
        let report =
            insights::compare_snapshots(&snap_a, &snap_b, params.top.unwrap_or(50).clamp(1, 200));
        serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Permanently empty the OS Recycle Bin / Trash.
    #[tool(
        name = "empty_trash",
        description = "Permanently purge the OS Recycle Bin / Trash (IRREVERSIBLE, no undo). Use AFTER delete(trash) to actually reclaim space. Requires confirm=true. Returns purged item count + bytes (best-effort)."
    )]
    async fn empty_trash(&self, Parameters(params): Parameters<EmptyTrashParams>) -> String {
        let engine = self.engine.clone();
        let req = EmptyTrashParams {
            confirm: params.confirm,
        };
        // ponytail: trash purge IO blocks — off the async executor.
        let result = tokio::task::spawn_blocking(move || engine.empty_trash(&req))
            .await
            .unwrap_or_else(|e| EmptyTrashResult {
                purged_items: 0,
                purged_bytes: 0,
                message: Some(format!("Task failed: {e}")),
            });
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }
}

#[tool_handler]
impl ServerHandler for DiskCleanerServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(rmcp::model::Implementation::new(
                "disk-cleaner-mcp",
                VERSION,
            ))
            .with_instructions(
                "Disk Cleaner MCP Server. Scan, analyze, and safely delete junk files.\n\
                 Workflow: get_system_status → scan → get_tree/file_types/find_duplicates/analyze → (review) → delete\n\
                 Insights: get_tree shows which folders hold the space; file_types shows which file types;\n\
                 find_duplicates reports byte-identical copies with deletion tokens; compare_scans diffs two scans.\n\
                 Safety: System files are protected. Default delete = trash (recoverable).",
            )
    }
}

// --- Parameter structs (deserialized from JSON-RPC params) ---

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanParams {
    #[schemars(description = "Root path to scan. Default: user Downloads directory if omitted.")]
    #[serde(default)]
    pub root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeParams {
    #[schemars(description = "Scan ID returned from scan()")]
    pub scan_id: String,
    #[schemars(description = "Filter by kind: 'file' or 'dir'")]
    #[serde(default)]
    pub kind: Option<String>,
    #[schemars(description = "Filter by category (see list_categories)")]
    #[serde(default)]
    pub category: Option<String>,
    #[schemars(description = "Glob pattern for filename, e.g. '*.log'")]
    #[serde(default)]
    pub name_glob: Option<String>,
    #[schemars(description = "Filter by file extension, e.g. 'log'")]
    #[serde(default)]
    pub extension: Option<String>,
    #[schemars(description = "Minimum file size in bytes")]
    #[serde(default)]
    pub min_size: Option<u64>,
    #[schemars(description = "Minimum age in days")]
    #[serde(default)]
    pub min_age_days: Option<u32>,
    #[schemars(description = "Sort by: 'size' (default), 'modified', 'name'")]
    #[serde(default)]
    pub sort_by: Option<String>,
    #[schemars(description = "Sort descending: true (default)")]
    #[serde(default)]
    pub sort_desc: Option<bool>,
    #[schemars(description = "Starting offset for pagination (default 0)")]
    #[serde(default)]
    pub offset: Option<usize>,
    #[schemars(description = "Page size (default 100, max 500)")]
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteParams {
    #[schemars(description = "Scan ID from scan()")]
    pub scan_id: String,
    #[schemars(
        description = "Array of items to delete, each with approvalToken + path from analyze()"
    )]
    pub items: Vec<DeleteItemRequest>,
    #[schemars(
        description = "Permanently delete (bypass trash). Requires confirm_permanent=true."
    )]
    #[serde(default)]
    pub permanent: bool,
    #[schemars(description = "Must be true to confirm permanent deletion.")]
    #[serde(default)]
    pub confirm_permanent: bool,
    #[schemars(
        description = "Acknowledge brain review/keep verdicts. Required to delete files brain marked risky."
    )]
    #[serde(default)]
    pub confirm_risk: bool,
    #[schemars(description = "True → report what would be deleted, touch nothing.")]
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizeParams {
    #[schemars(description = "Scan ID from scan()")]
    pub scan_id: String,
    #[schemars(
        description = "Array of items to organize, each with approvalToken + path from analyze()"
    )]
    pub items: Vec<OrganizeItemRequest>,
    #[schemars(description = "Existing destination directory (group subfolders created inside)")]
    pub dest_dir: String,
    #[schemars(description = "Grouping strategy: 'category' (default) or 'extension'")]
    #[serde(default)]
    pub strategy: Option<OrganizeStrategy>,
    #[schemars(description = "True → only plan moves, move nothing")]
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReportParams {
    #[schemars(description = "Scan ID from scan()")]
    pub scan_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TreeParams {
    #[schemars(description = "Scan ID from scan()")]
    pub scan_id: String,
    #[schemars(description = "Max child folders shown per node (default 10, max 50)")]
    #[serde(default)]
    pub top: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileTypesParams {
    #[schemars(description = "Scan ID from scan()")]
    pub scan_id: String,
    #[schemars(description = "Max extensions returned, largest first (default 30, max 200)")]
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateParams {
    #[schemars(description = "Scan ID from scan()")]
    pub scan_id: String,
    #[schemars(
        description = "Only files >= this many bytes are considered (default 1048576 = 1 MiB; 0 = all)"
    )]
    #[serde(default)]
    pub min_size: Option<u64>,
    #[schemars(description = "Max duplicate groups returned (default 50, max 200)")]
    #[serde(default)]
    pub top: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CompareParams {
    #[schemars(description = "Earlier scan ID")]
    pub scan_id_a: String,
    #[schemars(description = "Later scan ID")]
    pub scan_id_b: String,
    #[schemars(description = "Max rows per added/removed/changed section (default 50)")]
    #[serde(default)]
    pub top: Option<usize>,
}

/// Shared error payload when a scan session is missing/evicted.
fn scan_not_found(id: &str) -> String {
    let err = serde_json::json!({
        "error": true,
        "message": format!("Scan '{}' not found. Run scan first (only the 3 most recent scans stay cached).", id),
    });
    serde_json::to_string_pretty(&err).unwrap_or_else(|_| "Error".into())
}
