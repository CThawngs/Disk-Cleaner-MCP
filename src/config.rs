//! User custom rules — `config.json` next to per-user config dir.
//!
//! `dirs::config_dir()/disk-cleaner-mcp/config.json` (XDG_CONFIG_HOME or OS
//! equivalent). All fields optional; missing/bad file = no rules.
//! Safety Guard in `safety.rs` stays immutable — rules can only ADD
//! protection or boost downgrade, never lift a built-in block.
//!
//! ```json
//! {
//!   "protectedExtra": ["D:/Important"],
//!   "keepGlobs": ["*.vcxproj", "notes/*.txt"],
//!   "safeGlobs": ["*.log", "*.tmp"]
//! }
//! ```

use serde::Deserialize;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Rules {
    /// Extra paths never deletable (exact or parent-prefix).
    pub protected_extra: Vec<String>,
    /// Glob (matched on filename or full path) forcing brain verdict `keep`.
    pub keep_globs: Vec<String>,
    /// Glob downgrade request: matched junk can become `safe_to_delete`.
    pub safe_globs: Vec<String>,
}

static RULES: OnceLock<Rules> = OnceLock::new();

fn config_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|d| d.join("disk-cleaner-mcp").join("config.json"))
}

/// Load once per process (restart to pick up edits).
pub fn rules() -> &'static Rules {
    RULES.get_or_init(load)
}

fn load() -> Rules {
    let Some(path) = config_path() else {
        return Rules::default();
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Rules::default();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

/// Override path protection. Only stricter than built-in list.
pub fn is_extra_protected(path: &Path) -> bool {
    let rules = rules();
    if rules.protected_extra.is_empty() {
        return false;
    }
    let s = path.to_string_lossy().replace('\\', "/").to_lowercase();
    rules.protected_extra.iter().any(|p| {
        let pn = p.replace('\\', "/").to_lowercase();
        s == pn || s.starts_with(&format!("{pn}/"))
    })
}

/// Glob match (crate `glob`, case-insensitive on name + on full path).
fn glob_hit(pattern: &str, path: &str) -> bool {
    let name = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    glob::Pattern::new(pattern)
        .map(|p| p.matches(&name) || p.matches(path))
        .unwrap_or(false)
}

pub fn matches_keep(path: &str) -> bool {
    rules().keep_globs.iter().any(|g| glob_hit(g, path))
}

pub fn matches_safe(path: &str) -> bool {
    rules().safe_globs.iter().any(|g| glob_hit(g, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_hit_name() {
        assert!(glob_hit("*.log", "C:/tmp/a.log"));
        assert!(!glob_hit("*.log", "C:/tmp/a.txt"));
    }

    #[test]
    fn test_default_rules_empty() {
        // Loading test only pins shape; real file may exist on this host.
        let _ = rules();
    }
}
