//! Brain — per-file judgment. Every entry (smallest -> largest) is assessed
//! for importance before anyone may delete it. Pure stdlib, no I/O except
//! protected-path check (lexical, via safety::is_protected).

use std::path::Path;

/// Brain verdict for one entry.
#[derive(Debug, Clone)]
pub struct Assessment {
    pub verdict: String,      // safe_to_delete | review | keep | blocked
    pub risk_level: String,   // safe | caution | dangerous | blocked
    pub importance_score: u8, // 0 = worthless junk, 100 = critical
    pub reasons: Vec<String>,
}

const JUNK_CATS: &[&str] = &[
    "temp",
    "log",
    "cache",
    "browser_cache",
    "node_cache",
    "python_cache",
    "thumbnail",
    "crash_dump",
];

const EXEC_EXTS: &[&str] = &[
    "exe", "dll", "so", "dylib", "bin", "sys", "drv", "com", "scr", "sh", "bat", "cmd", "ps1",
    "msi",
];

const CONFIG_EXTS: &[&str] = &[
    "ini", "cfg", "conf", "config", "toml", "yaml", "yml", "dat", "db", "sqlite", "sqlite3", "reg",
    "key", "pem", "crt",
];

fn has_ext(ext: &str, list: &[&str]) -> bool {
    list.contains(&ext)
}

/// Assess one entry. `duplicate` = another entry shares size+name (copy exists).
/// `now` = epoch seconds (scan time).
pub fn assess(
    path: &str,
    size: u64,
    modified: Option<i64>,
    extension: &Option<String>,
    category: &str,
    duplicate: bool,
    now: i64,
) -> Assessment {
    let mut reasons: Vec<String> = Vec::new();
    let ext = extension.as_deref().unwrap_or("").to_lowercase();
    let name = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let age_days = modified.map(|m| ((now - m).max(0) / 86400) as u64);

    // 1. Protected paths: always blocked, never debated.
    if crate::safety::is_protected(Path::new(path)) {
        reasons.push("path is system-protected".into());
        return Assessment {
            verdict: "blocked".into(),
            risk_level: "blocked".into(),
            importance_score: 100,
            reasons,
        };
    }

    let mut importance: i32 = 50;

    // 2. Junk category = strong safe signal.
    if JUNK_CATS.contains(&category) {
        importance -= 40;
        reasons.push(format!("junk category '{category}'"));
    } else if category == "other" {
        reasons.push("uncategorized: unknown purpose".into());
    } else {
        // installer/archive/download/backup: user content, unsure.
        reasons.push(format!("user content category '{category}'"));
    }

    // 3. Executable / config = likely important.
    if has_ext(&ext, EXEC_EXTS) {
        importance += 30;
        reasons.push(format!("executable/system extension '.{ext}'"));
    }
    if has_ext(&ext, CONFIG_EXTS) {
        importance += 30;
        reasons.push(format!("config/data extension '.{ext}'"));
    }
    if name.starts_with('.') && !name.contains('.') {
        importance += 15;
        reasons.push("dotfile: likely user config".into());
    }
    if extension.is_none() && !name.contains('.') {
        importance += 10;
        reasons.push("no extension: may be script/config".into());
    }

    // 4. Recency: just-touched files may be in use.
    match age_days {
        Some(0) => {
            importance += 20;
            reasons.push("modified today: may be in use".into());
        }
        Some(d) if d < 7 => {
            importance += 10;
            reasons.push("modified within 7 days".into());
        }
        Some(d) if d >= 365 => {
            importance -= 15;
            reasons.push("untouched for over a year".into());
        }
        _ => {}
    }

    // 5. Size impact.
    if size >= 1_073_741_824 {
        importance += 15;
        reasons.push("large file (>=1GB): verify before deleting".into());
    } else if size == 0 {
        importance -= 20;
        reasons.push("zero bytes: frees nothing, safe to remove".into());
    }

    // 6. Duplicate copy exists elsewhere = safer.
    if duplicate {
        importance -= 25;
        reasons.push("duplicate copy exists in scan".into());
    }

    let importance_score = importance.clamp(0, 100) as u8;

    let (verdict, risk_level) = if importance_score < 25 && JUNK_CATS.contains(&category) {
        ("safe_to_delete", "safe")
    } else if importance_score >= 75 {
        ("keep", "dangerous")
    } else if importance_score >= 50 {
        ("review", "caution")
    } else {
        // Low importance but not proven junk: human decides.
        ("review", "caution")
    };

    Assessment {
        verdict: verdict.into(),
        risk_level: risk_level.into(),
        importance_score,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: i64 = 1_800_000_000;

    fn p(name: &str) -> String {
        std::env::temp_dir()
            .join("dcm-brain-test")
            .join(name)
            .to_string_lossy()
            .to_string()
    }

    fn a(path: &str, size: u64, ext: Option<&str>, cat: &str) -> Assessment {
        assess(
            path,
            size,
            Some(NOW - 86400 * 90),
            &ext.map(|s| s.to_string()),
            cat,
            false,
            NOW,
        )
    }

    #[test]
    fn test_temp_junk_safe() {
        let v = a(&p("junk.tmp"), 10, Some("tmp"), "temp");
        assert_eq!(v.verdict, "safe_to_delete");
        assert_eq!(v.risk_level, "safe");
    }

    #[test]
    fn test_executable_keep() {
        let v = a(&p("newtool.exe"), 5_000_000, Some("exe"), "installer");
        assert_eq!(v.verdict, "keep");
        assert_eq!(v.risk_level, "dangerous");
    }

    #[test]
    fn test_config_keep() {
        let v = a(&p("app.ini"), 200, Some("ini"), "other");
        assert_eq!(v.verdict, "keep");
    }

    #[test]
    fn test_big_other_review_not_safe() {
        let v = a(&p("movie.mkv"), 3_000_000_000, Some("mkv"), "other");
        assert_ne!(v.verdict, "safe_to_delete");
    }

    #[test]
    fn test_recent_caution() {
        let v = assess(
            &p("a.log"),
            100,
            Some(NOW),
            &Some("log".into()),
            "log",
            false,
            NOW,
        );
        assert!(
            v.importance_score >= 20 || v.verdict != "safe_to_delete" || v.risk_level != "safe"
        );
    }

    #[test]
    fn test_duplicate_lowers_importance() {
        let plain = a(&p("a.dat"), 1000, Some("dat"), "other");
        let dup = assess(
            &p("a.dat"),
            1000,
            Some(NOW - 90 * 86400),
            &Some("dat".into()),
            "other",
            true,
            NOW,
        );
        assert!(dup.importance_score < plain.importance_score);
    }
}
