//! MCP Server handler — defines all tools using rmcp macros.

use crate::analytics;
use crate::engine::ScanEngine;
use crate::model::*;
use crate::sysinfo_helper;
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// MCP server state.
#[derive(Clone)]
pub struct DiskCleanerServer {
    engine: Arc<Mutex<ScanEngine>>,
    #[allow(dead_code)] // held by #[tool_router] macro internals
    tool_router: ToolRouter<Self>,
}

impl DiskCleanerServer {
    pub fn new() -> Self {
        Self {
            engine: Arc::new(Mutex::new(ScanEngine::new())),
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

        let root_std = std::path::Path::new(&root_path);

        let result = {
            let mut engine = self.engine.lock().unwrap();
            engine.scan(root_std)
        };

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
        let engine = self.engine.lock().unwrap();
        match engine.get_session(&params.scan_id) {
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
        description = "Delete files from a previous scan. Requires scanId + items with approvalToken from analyze().\n\nSafety:\n- Default action: move to Recycle Bin/Trash (recoverable)\n- Permanent delete requires permanent=true AND confirm_permanent=true\n- System-protected paths (C:\\Windows, /usr, etc.) are ALWAYS rejected\n- Each item must have a valid approvalToken from the original scan\n\nParameters:\n- scanId: from scan()\n- items: array of { approvalToken, path }\n- permanent: true for permanent delete (default: false = trash)\n- confirm_permanent: must be true if permanent=true"
    )]
    async fn delete(&self, Parameters(params): Parameters<DeleteParams>) -> String {
        let engine = self.engine.lock().unwrap();
        let req = DeleteRequest {
            scan_id: params.scan_id.clone(),
            items: params.items.clone(),
            permanent: params.permanent,
            confirm_permanent: params.confirm_permanent,
        };
        let result = engine.delete(&req);
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Organize files into subfolders by category/extension.
    #[tool(
        name = "organize",
        description = "Organize files into the destination directory, grouped into subfolders by category (default) or extension. Safe: token-verified (like delete), NEVER overwrites existing files, protected system paths are rejected, directories are skipped (not moved).\n\nParameters:\n- scanId: from scan()\n- items: array of { approvalToken, path } from analyze()\n- destDir: existing destination directory (server will NOT create it; creates only group subfolders inside it)\n- strategy: 'category' (default) or 'extension'\n- dryRun: true → only compute planned moves, move nothing\n\nExample: organize(scanId, [{approvalToken, path}], 'C:/Users/me/Organized', strategy='category') moves a .jpg into .../Organized/Images/, a .log into .../Organized/Log Files/."
    )]
    async fn organize(&self, Parameters(params): Parameters<OrganizeParams>) -> String {
        let engine = self.engine.lock().unwrap();
        let req = OrganizeRequest {
            scan_id: params.scan_id.clone(),
            items: params.items.clone(),
            dest_dir: params.dest_dir.clone(),
            strategy: params.strategy,
            dry_run: params.dry_run,
        };
        let result = engine.organize(&req);
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Get a markdown report of scan results.
    #[tool(
        name = "get_report",
        description = "Generate a Markdown report of a scan. Requires scanId. Returns a formatted report with category breakdown and top files."
    )]
    async fn get_report(&self, Parameters(params): Parameters<ReportParams>) -> String {
        let engine = self.engine.lock().unwrap();
        match engine.get_session(&params.scan_id) {
            Some(session) => analytics::generate_report(&session.summary, &session.entries),
            None => format!(
                "# Error\n\nScan '{}' not found. Run scan first.",
                params.scan_id
            ),
        }
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
                 Workflow: get_system_status → scan → analyze → (review) → delete\n\
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
