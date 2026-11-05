//! Data model: JSON-serializable structs for MCP tool I/O.
//! All camelCase (for JS clients), serde rename_all = "camelCase".

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One scan result entry (file/dir).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScanEntry {
    pub kind: String, // "file" | "dir"
    pub path: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<i64>, // epoch seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
    pub category: String,
    pub category_label: String,
    pub approval_token: String,
    pub depth: usize,
    /// Brain verdict: safe_to_delete | review | keep | blocked.
    #[serde(default)]
    pub verdict: String,
    /// Brain importance 0 (junk) .. 100 (critical).
    #[serde(default)]
    pub importance_score: u8,
    /// Brain risk: safe | caution | dangerous | blocked.
    #[serde(default)]
    pub risk_level: String,
    /// Why brain decided this (human-readable signals).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CategoryTotal {
    pub category: String,
    pub category_label: String,
    pub count: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub scan_id: String,
    pub started_at: i64, // epoch seconds
    pub duration_ms: u64,
    pub root: String,
    pub files_scanned: u64,
    pub dirs_scanned: u64,
    pub total_size: u64,
    pub truncated: bool,
    pub max_entries: usize,
    pub version: String,
    pub category_totals: Vec<CategoryTotal>,
    pub largest_entries: Vec<ScanEntry>, // top 20
    pub warnings: Vec<String>,
    /// Brain counts: entries brain is sure are junk.
    #[serde(default)]
    pub safe_count: u64,
    #[serde(default)]
    pub review_count: u64,
    #[serde(default)]
    pub keep_count: u64,
    #[serde(default)]
    pub blocked_count: u64,
    /// Bytes reclaimable if all safe_to_delete were removed.
    #[serde(default)]
    pub reclaimable_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub summary: ScanSummary,
    /// Count available for analyze(); not sending full entries.
    pub entries_count: usize,
    pub message: String,
}

/// Per-item delete request from client.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteItemRequest {
    pub approval_token: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRequest {
    pub scan_id: String,
    pub items: Vec<DeleteItemRequest>,
    #[serde(default)]
    pub permanent: bool,
    #[serde(default)]
    pub confirm_permanent: bool,
    /// Acknowledge brain review/keep verdicts (dangerous) for this batch.
    #[serde(default)]
    pub confirm_risk: bool,
    /// Compute + report only; touch nothing on disk.
    #[serde(default)]
    pub dry_run: bool,
}

/// One item's delete result.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteOutcome {
    pub path: String,
    pub status: String, // "trashed" | "permanent" | "rejected" | "error" | "not_found" | "dry_run"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResult {
    pub scan_id: String,
    pub trashed: u32,
    pub permanent: u32,
    pub rejected: u32,
    pub errors: u32,
    #[serde(default)]
    pub dry_run: u32,
    #[serde(default)]
    pub would_reclaim_bytes: u64,
    pub outcomes: Vec<DeleteOutcome>,
}

/// Per-item organize request (path+token). Reuses token verification.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizeItemRequest {
    pub approval_token: String,
    pub path: String,
}

/// Organize strategy controls how files are grouped.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum OrganizeStrategy {
    /// Group by junk category: Images, Documents, Archives, ...
    #[serde(rename = "category")]
    Category,
    /// Group by file extension: jpg → JPG/, pdf → PDF/
    #[serde(rename = "extension")]
    Extension,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizeRequest {
    pub scan_id: String,
    pub items: Vec<OrganizeItemRequest>,
    /// Destination directory; MUST exist (server does not create arbitrary dirs).
    pub dest_dir: String,
    #[serde(default)]
    pub strategy: Option<OrganizeStrategy>,
    /// If true, only compute + return planned moves; nothing is moved.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizeOutcome {
    pub path: String,
    /// "moved" | "dry_run" | "skipped" | "rejected" | "error" | "not_found"
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizeResult {
    pub scan_id: String,
    pub moved: u32,
    pub dry_run: u32,
    pub skipped: u32,
    pub rejected: u32,
    pub errors: u32,
    pub outcomes: Vec<OrganizeOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeRequest {
    pub scan_id: String,
    #[serde(default)]
    pub kind: Option<String>, // "file" | "dir"
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub name_glob: Option<String>, // glob like "*.log"
    #[serde(default)]
    pub extension: Option<String>,
    #[serde(default)]
    pub min_size: Option<u64>,
    #[serde(default)]
    pub min_age_days: Option<u32>,
    #[serde(default)]
    pub sort_by: Option<String>, // "size" (default) | "modified" | "name"
    #[serde(default)]
    pub sort_desc: Option<bool>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>, // default 100, max 500
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiskInfo {
    pub mount_point: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f64,
    /// Bytes sitting in the OS trash/recycle bin on this volume (best-effort).
    pub trash_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatus {
    pub platform: String,
    pub hostname: String,
    pub home_dir: String,
    pub temp_dir: String,
    pub disks: Vec<DiskInfo>,
    pub user_dirs: BTreeMap<String, String>,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CategoryInfo {
    pub key: String,
    pub label: String,
    pub description: String,
}

// ── TreeSize-grade insights (tree / file types / duplicates / compare) ──

/// One node of the aggregated folder tree (TreeSize "folder view").
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TreeNode {
    pub name: String,
    pub path: String,
    /// Recursive size: this folder + all descendants (bytes).
    pub size: u64,
    /// Recursive file count.
    pub files: u64,
    /// Size of files DIRECTLY in this folder (not descendants).
    pub direct_size: u64,
    /// Files DIRECTLY in this folder.
    pub direct_files: u64,
    /// Share of the subtree root's size (0-100).
    pub percent: f64,
    /// Children sorted by size desc, truncated to `top` with a "(+N more)" rollup.
    pub children: Vec<TreeNode>,
    /// True when children list was truncated (rollup node keeps totals exact).
    pub children_truncated: bool,
}

/// Aggregated stats for one file extension (TreeSize "file types" view).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionStat {
    /// Extension without dot, or "(none)" for files without one.
    pub extension: String,
    pub count: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileTypeReport {
    pub scan_id: String,
    pub total_files: u64,
    pub total_size: u64,
    pub extension_count: usize,
    pub by_extension: Vec<ExtensionStat>,
    pub truncated: bool,
}

/// One file inside a duplicate group (approval token included so the AI can
/// immediately `delete` redundant copies through the normal safety flow).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateFile {
    pub path: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<i64>,
    pub category: String,
    pub category_label: String,
    pub approval_token: String,
}

/// A group of ≥2 files with identical content (same size + same SHA-256).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateGroup {
    pub hash: String,
    pub size: u64,
    pub file_count: u64,
    /// Bytes reclaimable by deleting all but one copy: size * (count - 1).
    pub wasted_size: u64,
    /// True when hash is sampled (head+tail) for files > 4 GB — verify before delete.
    #[serde(default)]
    pub partial: bool,
    /// Oldest-first; typically the first entry is the "original" to keep.
    pub files: Vec<DuplicateFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateReport {
    pub scan_id: String,
    pub groups_found: u64,
    pub top_groups: Vec<DuplicateGroup>,
    /// Bytes reclaimable across ALL found groups (not just returned page).
    pub total_wasted: u64,
    pub candidate_files: u64,
    pub hashed_files: u64,
    pub unreadable_files: u64,
    pub truncated: bool,
    /// Groups matched by sampled hash (>4 GB files), verify before delete.
    #[serde(default)]
    pub partial_groups: u64,
}

/// Permanently purge the OS Recycle Bin / Trash.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EmptyTrashParams {
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EmptyTrashResult {
    pub purged_items: u64,
    pub purged_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// One changed file between two scans.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileChange {
    pub path: String,
    pub before: u64,
    pub after: u64,
    pub delta: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CompareReport {
    pub scan_a: String,
    pub scan_b: String,
    pub root_a: String,
    pub root_b: String,
    pub started_a: i64,
    pub started_b: i64,
    pub total_a: u64,
    pub total_b: u64,
    /// total_b - total_a (negative = space freed).
    pub net_delta: i64,
    pub added_count: u64,
    pub added_size: u64,
    pub removed_count: u64,
    pub removed_size: u64,
    pub changed_count: u64,
    pub top_added: Vec<FileChange>,
    pub top_removed: Vec<FileChange>,
    pub top_changed: Vec<FileChange>,
    pub warnings: Vec<String>,
}

/// In-memory snapshot of a scan's file set, built on demand from a live scan
/// session. `compare_scans` diffs two of these (TreeSize "compare over time").
/// No disk persistence: only scans still cached (LRU 3) can be compared.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSnapshot {
    pub scan_id: String,
    pub root: String,
    pub started_at: i64,
    pub total_size: u64,
    pub files_scanned: u64,
    /// path → {size, modified} for every file.
    #[serde(rename = "m")]
    pub map: BTreeMap<String, FileSnap>,
}

/// Compact per-file snapshot record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSnap {
    #[serde(rename = "s")]
    pub size: u64,
    #[serde(rename = "m", skip_serializing_if = "Option::is_none")]
    pub modified: Option<i64>,
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
