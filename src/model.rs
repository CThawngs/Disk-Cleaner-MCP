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
}

/// One item's delete result.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteOutcome {
    pub path: String,
    pub status: String, // "trashed" | "permanent" | "rejected" | "error" | "not_found"
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
    pub outcomes: Vec<DeleteOutcome>,
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

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
