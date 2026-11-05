//! Safety Guard — immutable protection layer.
//!
//! Blocklists critical OS paths, normalizes paths, and verifies approval tokens.
//! This module CANNOT be bypassed by configuration — it is hardcoded policy.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Absolute paths (case-insensitive on Windows) that must NEVER be deleted.
/// Windows list is drive-aware via `protected_windows()` (SystemRoot).
#[cfg(not(windows))]
const PROTECTED_UNIX: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/etc",
    "/var",
    "/System",
    "/Library",
    "/Applications",
    "/Volumes",
    "/dev",
    "/proc",
    "/sys",
    "/opt",
    "/root",
];

#[cfg(windows)]
const PROTECTED_FILES_WINDOWS: &[&str] = &[
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "ntuser.dat",
    "ntuser.dat.LOG",
    "ntuser.ini",
];

/// Windows protected roots resolved against real system drive + env dirs,
/// so Windows installed on D: (or non-standard ProgramData) stays covered.
/// ponytail: env-based, no registry access needed.
#[cfg(windows)]
fn protected_windows() -> Vec<String> {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let drive: String = sysroot.chars().take(2).collect(); // "C:"
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| format!("{drive}\\ProgramData"));
    vec![
        sysroot,
        format!("{drive}\\Program Files"),
        format!("{drive}\\Program Files (x86)"),
        program_data,
        format!("{drive}\\System Volume Information"),
        format!("{drive}\\Recovery"),
        format!("{drive}\\$Recycle.Bin"),
        format!("{drive}\\Boot"),
        format!("{drive}\\EFI"),
        format!("{drive}\\Documents and Settings"),
    ]
}

/// Directories to SKIP during scan (prune) — read none of their contents.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "$Recycle.Bin",
    "System Volume Information",
    "node_modules",
    ".venv",
    "__pycache__",
    ".next",
    ".nuxt",
    ".cache",
];

/// Generate a random salt (32 bytes) as hex — CSPRNG via OS (getrandom).
pub fn generate_salt() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("CSPRNG unavailable");
    hex::encode(bytes)
}

/// Compute approval token: hex(sha256(salt ‖ ":" ‖ path))
pub fn compute_token(salt: &str, path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b":");
    hasher.update(path.as_bytes());
    hex::encode(hasher.finalize())
}

/// Verify that a client-supplied token matches the expected token for this salt+path.
pub fn verify_token(salt: &str, path: &str, supplied: &str) -> bool {
    let expected = compute_token(salt, path);
    // Constant-time comparison
    if expected.len() != supplied.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.bytes().zip(supplied.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Lexically collapse `.`/`..` without touching the filesystem.
/// Used as a fallback when `canonicalize` fails (path may not exist yet).
pub fn lexical_clean(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            _ => out.push(comp.as_os_str()),
        }
    }
    out
}

/// Normalize a path for comparison: absolute, forward-slash, lowercase on
/// case-insensitive filesystems (Windows NTFS + macOS APFS default).
pub fn normalize(path: &Path) -> PathBuf {
    let pb = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };

    // Canonicalize if possible (resolves symlinks, removes ..)
    let canonical = pb.canonicalize().unwrap_or_else(|_| lexical_clean(&pb));

    #[cfg(any(windows, target_os = "macos"))]
    {
        let s = canonical.to_string_lossy();
        let mut lower = s.to_lowercase().replace('\\', "/");
        // strip extended-length prefix \\?\C:\... or \\.\C:\...
        for prefix in ["//?/", "//./"] {
            if let Some(stripped) = lower.strip_prefix(prefix) {
                lower = stripped.to_string();
                break;
            }
        }
        PathBuf::from(lower)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        canonical
    }
}

/// Strip NTFS alternate-data-stream suffix (`file.txt:stream`) for checks.
fn strip_ads(s: &str) -> String {
    // Keep drive letter `C:`; drop everything after the first ':' beyond it.
    let colon = s.find(':');
    if let Some(i) = colon {
        if i == 1 && s.len() > 1 && s.as_bytes()[1] == b':' {
            if let Some(j) = s[i + 1..].find(':') {
                return s[..i + 1 + j].to_string();
            }
        } else {
            return s[..i].to_string();
        }
    }
    s.to_string()
}

/// Check if a path is protected (must NEVER be deleted).
pub fn is_protected(path: &Path) -> bool {
    // User `protectedExtra` rules: additions only, never lift a built-in block.
    if crate::config::is_extra_protected(path) {
        return true;
    }
    let normalized = normalize(path);
    let s = normalized.to_string_lossy();
    let s_str = strip_ads(&s).to_lowercase();

    #[cfg(windows)]
    {
        for p in protected_windows() {
            let pn = p.to_lowercase().replace('\\', "/");
            if s_str == pn || s_str.starts_with(&format!("{}/", pn)) {
                return true;
            }
        }
        // Protected files (basename match)
        if let Some(fname) = path.file_name() {
            let fname_str = fname.to_string_lossy().to_lowercase();
            for pf in PROTECTED_FILES_WINDOWS {
                if fname_str == pf.to_lowercase() {
                    return true;
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        for p in PROTECTED_UNIX {
            if s_str == *p || s_str.starts_with(&format!("{}/", p)) {
                return true;
            }
        }
    }

    false
}

/// Light normalization for comparing a canonical path against a lexically
/// cleaned one. Kept for reference; `verify_safe_target` now checks ancestor
/// components directly instead of string-comparing canonical vs lexical
/// (8.3 short names like `RUNNER~1` on Windows CI made that false-fire).
#[allow(dead_code)]
fn light_normalize(path: &Path) -> PathBuf {
    #[cfg(any(windows, target_os = "macos"))]
    {
        let mut lower = path.to_string_lossy().to_lowercase().replace('\\', "/");
        for prefix in ["//?/", "//./"] {
            if let Some(stripped) = lower.strip_prefix(prefix) {
                lower = stripped.to_string();
                break;
            }
        }
        PathBuf::from(lower)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        path.to_path_buf()
    }
}

/// Verify a delete/move target immediately before the operation (TOCTOU guard):
/// exists, is not a symlink itself, has no symlinked ancestors (canonical path
/// must equal the lexically-cleaned absolute path, modulo `\\?\` prefix/case),
/// and is not protected. Returns the canonical path to operate on.
pub fn verify_safe_target(path: &Path) -> Result<PathBuf, String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("Target does not exist or is inaccessible: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err("Target is a symlink — refused.".into());
    }
    let abs = if path.is_absolute() {
        lexical_clean(path)
    } else {
        lexical_clean(&std::env::current_dir().unwrap_or_default().join(path))
    };
    let canon = abs
        .canonicalize()
        .map_err(|e| format!("Cannot resolve target: {e}"))?;
    // Symlinked ancestor (or self): check each ancestor component directly.
    // String-compare against canonical form false-fires on Windows CI where
    // temp dirs use 8.3 short names (RUNNER~1 vs runneradmin).
    for anc in abs.ancestors().skip(1) {
        if let Ok(m) = std::fs::symlink_metadata(anc) {
            if m.file_type().is_symlink() {
                return Err("Target has a symlinked ancestor — refused.".into());
            }
        }
    }
    if is_protected(&canon) {
        return Err("Path is system-protected. Operation BLOCKED by Safety Guard.".into());
    }
    Ok(canon)
}

/// Check if a directory name should be skipped during scan (prune).
pub fn should_skip_dir(name: &str) -> bool {
    SKIP_DIRS.iter().any(|d| d.eq_ignore_ascii_case(name))
}

/// Minimal hex encode (no extra dep).
pub mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn test_protected_windows_system32() {
        let p = Path::new("C:\\Windows\\System32\\drivers");
        assert!(is_protected(p));
    }

    #[cfg(windows)]
    #[test]
    fn test_protected_program_files() {
        let p = Path::new("C:\\Program Files\\SomeApp");
        assert!(is_protected(p));
    }

    #[cfg(windows)]
    #[test]
    fn test_protected_pagefile() {
        let p = Path::new("C:\\pagefile.sys");
        assert!(is_protected(p));
    }

    #[test]
    fn test_token_roundtrip() {
        let salt = generate_salt();
        let path = "C:/Users/test/AppData/Local/Temp/foo.log";
        let token = compute_token(&salt, path);
        assert!(verify_token(&salt, path, &token));
    }

    #[test]
    fn test_token_wrong_path() {
        let salt = generate_salt();
        let token = compute_token(&salt, "C:/path/a");
        assert!(!verify_token(&salt, "C:/path/b", &token));
    }

    #[test]
    fn test_token_wrong_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let token = compute_token(&salt1, "C:/path/a");
        assert!(!verify_token(&salt2, "C:/path/a", &token));
    }

    #[test]
    fn test_lexical_clean() {
        assert_eq!(lexical_clean(Path::new("/a/b/../c")), PathBuf::from("/a/c"));
        assert_eq!(lexical_clean(Path::new("/a/./b")), PathBuf::from("/a/b"));
    }

    #[test]
    fn test_ads_stripped() {
        assert_eq!(strip_ads("c:/windows/system32:f"), "c:/windows/system32");
        assert_eq!(strip_ads("c:/windows/system32"), "c:/windows/system32");
    }

    #[test]
    fn test_should_skip_dir() {
        assert!(should_skip_dir(".git"));
        assert!(should_skip_dir("node_modules"));
        assert!(should_skip_dir("__pycache__"));
        assert!(!should_skip_dir("my-project"));
    }

    #[cfg(unix)]
    #[test]
    fn test_protected_unix_usr() {
        assert!(is_protected(Path::new("/usr/bin")));
        assert!(is_protected(Path::new("/boot")));
        assert!(!is_protected(Path::new("/home/user/project")));
    }

    #[test]
    fn test_verify_safe_target_symlink_rejected() {
        let dir = std::env::temp_dir().join(format!("dcm-symlink-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let real = dir.join("real.txt");
        let link = dir.join("link.txt");
        std::fs::write(&real, b"hi").unwrap();
        #[cfg(unix)]
        let link_ok = std::os::unix::fs::symlink(&real, &link).is_ok();
        #[cfg(windows)]
        let link_ok = std::os::windows::fs::symlink_file(&real, &link).is_ok();
        if !link_ok {
            // Windows without SeCreateSymbolicLinkPrivilege — skip.
            let _ = std::fs::remove_file(&real);
            let _ = std::fs::remove_dir(&dir);
            return;
        }
        assert!(verify_safe_target(&link).is_err());
        assert!(verify_safe_target(&real).is_ok());
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&real);
        let _ = std::fs::remove_dir(&dir);
    }
}
