//! Categorize files into junk categories + analytics/filtering.

use crate::model::*;
use glob::Pattern;
use std::path::Path;

/// Category keys + human-readable labels.
pub fn all_categories() -> Vec<CategoryInfo> {
    vec![
        CategoryInfo {
            key: "temp".into(),
            label: "Temporary Files".into(),
            description: "OS and app temporary files (.tmp, .temp, TMP dirs)".into(),
        },
        CategoryInfo {
            key: "log".into(),
            label: "Log Files".into(),
            description: "Application and system log files (.log)".into(),
        },
        CategoryInfo {
            key: "cache".into(),
            label: "Cache Files".into(),
            description: "Browser and application cache data".into(),
        },
        CategoryInfo {
            key: "browser_cache".into(),
            label: "Browser Cache".into(),
            description: "Chrome, Firefox, Edge cache directories".into(),
        },
        CategoryInfo {
            key: "node_cache".into(),
            label: "Node.js Cache".into(),
            description: "npm/yarn/pnpm cache and node_modules".into(),
        },
        CategoryInfo {
            key: "python_cache".into(),
            label: "Python Cache".into(),
            description: "__pycache__, .pyc, .pyo, pip cache".into(),
        },
        CategoryInfo {
            key: "installer".into(),
            label: "Installers".into(),
            description: "Setup files (.exe, .msi, .dmg, .deb, .rpm)".into(),
        },
        CategoryInfo {
            key: "download".into(),
            label: "Downloads".into(),
            description: "Files in Downloads directory".into(),
        },
        CategoryInfo {
            key: "backup".into(),
            label: "Backup Files".into(),
            description: "Backup and recovery files (.bak, .old, .backup)".into(),
        },
        CategoryInfo {
            key: "archive".into(),
            label: "Archives".into(),
            description: "Compressed archives (.zip, .tar.gz, .rar, .7z)".into(),
        },
        CategoryInfo {
            key: "crash_dump".into(),
            label: "Crash Dumps".into(),
            description: "Memory dumps and crash reports (.dmp, .mdmp, core dumps)".into(),
        },
        CategoryInfo {
            key: "thumbnail".into(),
            label: "Thumbnails".into(),
            description: "Thumbnail cache files (thumbs.db, .thumbs)".into(),
        },
        CategoryInfo {
            key: "other".into(),
            label: "Other".into(),
            description: "Uncategorized files".into(),
        },
    ]
}

/// Categorize a single file based on path + extension.
pub fn categorize(path: &str, extension: &Option<String>) -> (String, String) {
    let p = path.to_lowercase();
    let ext = extension.as_deref().unwrap_or("").to_lowercase();

    // Temp directories
    if p.contains("/temp/")
        || p.contains("/tmp/")
        || p.contains("\\temp\\")
        || p.contains("\\tmp\\")
        || ext == "tmp"
        || ext == "temp"
    {
        return ("temp".into(), "Temporary Files".into());
    }

    // Logs
    if ext == "log" || ext == "logs" {
        return ("log".into(), "Log Files".into());
    }

    // Browser cache (by directory name)
    if p.contains("cache")
        || p.contains("cache2")
        || p.contains("code cache")
        || p.contains("service worker")
    {
        if p.contains("chrome")
            || p.contains("firefox")
            || p.contains("edge")
            || p.contains("safari")
            || p.contains("chromium")
        {
            return ("browser_cache".into(), "Browser Cache".into());
        }
        return ("cache".into(), "Cache Files".into());
    }

    // Node.js
    if p.contains("node_modules")
        || p.contains("npm-cache")
        || p.contains("yarn")
        || p.contains(".pnpm-store")
        || p.contains(".npm")
    {
        return ("node_cache".into(), "Node.js Cache".into());
    }

    // Python
    if p.contains("__pycache__")
        || p.contains(".pyc")
        || ext == "pyc"
        || ext == "pyo"
        || p.contains("pip-cache")
        || p.contains(".cache/pip")
    {
        return ("python_cache".into(), "Python Cache".into());
    }

    // Installers
    if matches!(
        ext.as_str(),
        "exe" | "msi" | "dmg" | "deb" | "rpm" | "pkg" | "appimage"
    ) {
        return ("installer".into(), "Installers".into());
    }

    // Downloads
    if p.contains("/downloads/") || p.contains("\\downloads\\") {
        return ("download".into(), "Downloads".into());
    }

    // Backups
    if matches!(ext.as_str(), "bak" | "old" | "backup" | "orig") {
        return ("backup".into(), "Backup Files".into());
    }

    // Archives
    if matches!(
        ext.as_str(),
        "zip" | "gz" | "tar" | "rar" | "7z" | "bz2" | "xz" | "tgz"
    ) {
        return ("archive".into(), "Archives".into());
    }

    // Crash dumps
    if matches!(ext.as_str(), "dmp" | "mdmp" | "hdmp")
        || p.contains("core.dump")
        || p.contains("crash")
    {
        return ("crash_dump".into(), "Crash Dumps".into());
    }

    // Thumbnails
    if p.ends_with("thumbs.db")
        || p.ends_with(".thumbs")
        || p.contains("thumbnail")
        || p.contains("thumbs")
    {
        return ("thumbnail".into(), "Thumbnails".into());
    }

    ("other".into(), "Other".into())
}

/// Filter and sort entries server-side, return a page.
pub fn analyze_entries(entries: &[ScanEntry], req: &AnalyzeRequest) -> (Vec<ScanEntry>, usize) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let glob_pat = req.name_glob.as_ref().and_then(|s| Pattern::new(s).ok());

    let mut filtered: Vec<ScanEntry> = entries
        .iter()
        .filter(|e| {
            // Kind filter
            if let Some(kind) = &req.kind {
                if &e.kind != kind {
                    return false;
                }
            }
            // Category filter
            if let Some(cat) = &req.category {
                if &e.category != cat {
                    return false;
                }
            }
            // Extension filter
            if let Some(ext) = &req.extension {
                match &e.extension {
                    Some(e_ext) if e_ext.eq_ignore_ascii_case(ext) => {}
                    _ => return false,
                }
            }
            // Min size
            if let Some(min) = req.min_size {
                if e.size < min {
                    return false;
                }
            }
            // Min age days
            if let Some(min_age) = req.min_age_days {
                if let Some(modified) = e.modified {
                    let age_days = ((now - modified).max(0) / 86400) as u32;
                    if age_days < min_age {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            // Name glob
            if let Some(pattern) = &glob_pat {
                let name = Path::new(&e.path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if !pattern.matches(&name) {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    // Sort
    let sort_by = req.sort_by.as_deref().unwrap_or("size");
    let sort_desc = req.sort_desc.unwrap_or(true);
    match sort_by {
        "modified" => filtered.sort_by(|a, b| {
            let ma = a.modified.unwrap_or(0);
            let mb = b.modified.unwrap_or(0);
            if sort_desc {
                mb.cmp(&ma)
            } else {
                ma.cmp(&mb)
            }
        }),
        "name" => filtered.sort_by(|a, b| {
            if sort_desc {
                b.path.cmp(&a.path)
            } else {
                a.path.cmp(&b.path)
            }
        }),
        _ => {
            // "size"
            if sort_desc {
                filtered.sort_by_key(|a| std::cmp::Reverse(a.size));
            } else {
                filtered.sort_by_key(|a| a.size);
            }
        }
    }

    let total = filtered.len();
    let offset = req.offset.unwrap_or(0).min(total);
    let limit = req.limit.unwrap_or(100).min(500);
    let end = (offset + limit).min(total);
    let page = filtered[offset..end].to_vec();
    (page, total)
}

/// Generate a markdown report of scan results.
pub fn generate_report(summary: &ScanSummary, _entries: &[ScanEntry]) -> String {
    let mut md = String::new();
    md.push_str("# Disk Cleaner — Scan Report\n\n");
    md.push_str(&format!("**Scan ID:** `{}`\n", summary.scan_id));
    md.push_str(&format!("**Root:** `{}`\n", summary.root));
    md.push_str(&format!(
        "**Scanned:** {} files, {} dirs\n",
        summary.files_scanned, summary.dirs_scanned
    ));
    md.push_str(&format!(
        "**Total size found:** {:.2} GB\n",
        summary.total_size as f64 / 1_073_741_824.0
    ));
    md.push_str(&format!("**Duration:** {}ms\n\n", summary.duration_ms));

    md.push_str("## Category Breakdown\n\n");
    md.push_str("| Category | Files | Size |\n");
    md.push_str("|---|---:|---:|\n");
    for ct in &summary.category_totals {
        md.push_str(&format!(
            "| {} | {} | {:.2} MB |\n",
            ct.category_label,
            ct.count,
            ct.size as f64 / 1_048_576.0
        ));
    }

    md.push_str("\n## Top 20 Largest Files\n\n");
    md.push_str("| # | Size | Path | Category |\n");
    md.push_str("|---:|---:|---|---|\n");
    for (i, e) in summary.largest_entries.iter().enumerate().take(20) {
        md.push_str(&format!(
            "| {} | {:.2} MB | `{}` | {} |\n",
            i + 1,
            e.size as f64 / 1_048_576.0,
            e.path,
            e.category_label
        ));
    }

    if !summary.warnings.is_empty() {
        md.push_str("\n## Warnings\n\n");
        for w in &summary.warnings {
            md.push_str(&format!("- {}\n", w));
        }
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_categorize_log() {
        let (key, label) = categorize("/home/user/app.log", &Some("log".into()));
        assert_eq!(key, "log");
        assert_eq!(label, "Log Files");
    }

    #[test]
    fn test_categorize_installer() {
        let (key, _) = categorize("C:/Users/test/Downloads/setup.exe", &Some("exe".into()));
        assert_eq!(key, "installer");
    }

    #[test]
    fn test_categorize_temp() {
        let (key, _) = categorize(
            "C:/Users/test/AppData/Local/Temp/foo.txt",
            &Some("txt".into()),
        );
        assert_eq!(key, "temp");
    }

    #[test]
    fn test_analyze_filter_category() {
        let entries = vec![
            mock_entry("/a.log", "log", 100, Some("log".into())),
            mock_entry("/b.log", "log", 200, Some("log".into())),
            mock_entry("/c.exe", "installer", 300, Some("exe".into())),
        ];
        let req = AnalyzeRequest {
            scan_id: "test".into(),
            kind: None,
            category: Some("log".into()),
            name_glob: None,
            extension: None,
            min_size: None,
            min_age_days: None,
            sort_by: Some("size".into()),
            sort_desc: Some(true),
            offset: None,
            limit: None,
        };
        let (page, total) = analyze_entries(&entries, &req);
        assert_eq!(total, 2);
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].size, 200); // sorted desc
    }

    #[test]
    fn test_analyze_pagination() {
        let entries: Vec<ScanEntry> = (0..50)
            .map(|i| {
                mock_entry(
                    &format!("/file_{}.log", i),
                    "log",
                    i * 10,
                    Some("log".into()),
                )
            })
            .collect();
        let req = AnalyzeRequest {
            scan_id: "test".into(),
            kind: None,
            category: None,
            name_glob: None,
            extension: None,
            min_size: None,
            min_age_days: None,
            sort_by: None,
            sort_desc: None,
            offset: Some(10),
            limit: Some(5),
        };
        let (page, total) = analyze_entries(&entries, &req);
        assert_eq!(total, 50);
        assert_eq!(page.len(), 5);
    }

    fn mock_entry(path: &str, cat: &str, size: u64, ext: Option<String>) -> ScanEntry {
        ScanEntry {
            kind: "file".into(),
            path: path.into(),
            size,
            modified: Some(1700000000),
            extension: ext,
            category: cat.into(),
            category_label: cat.into(),
            approval_token: "tok".into(),
            depth: 1,
        }
    }
}
