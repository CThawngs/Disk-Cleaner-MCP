//! Safety Guard — immutable protection layer.
//!
//! Blocklists critical OS paths, normalizes paths, and verifies approval tokens.
//! This module CANNOT be bypassed by configuration — it is hardcoded policy.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Absolute paths (case-insensitive on Windows) that must NEVER be deleted.
#[cfg(windows)]
const PROTECTED_WINDOWS: &[&str] = &[
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    "C:\\System Volume Information",
    "C:\\Recovery",
    "C:\\$Recycle.Bin",
    "C:\\Boot",
    "C:\\EFI",
    "C:\\Documents and Settings",
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
    "/home",
];

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

/// Generate a random salt (32 bytes) as hex.
pub fn generate_salt() -> String {
    // OS rng via time + stack entropy; per-session salt only.
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut bytes = [0u8; 32];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let stack_var = 0u8;
    let stack_addr = &stack_var as *const u8 as u64;
    let tid = std::thread::current()
        .name()
        .map(|s| s.len() as u64)
        .unwrap_or(0);
    let seed: u128 = now ^ ((stack_addr as u128) << 1) ^ ((tid as u128) << 3);
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = ((seed >> ((i % 16) * 8)) & 0xFF) as u8;
    }
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

/// Normalize a path for comparison: absolute, forward-slash, lowercase on Windows.
pub fn normalize(path: &Path) -> PathBuf {
    let pb = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };

    // Canonicalize if possible (resolves symlinks, removes ..)
    let canonical = pb.canonicalize().unwrap_or_else(|_| pb.clone());

    #[cfg(windows)]
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
    #[cfg(not(windows))]
    {
        canonical
    }
}

/// Check if a path is protected (must NEVER be deleted).
pub fn is_protected(path: &Path) -> bool {
    let normalized = normalize(path);
    let s = normalized.to_string_lossy();
    let s_str = s.as_ref().to_lowercase();

    #[cfg(windows)]
    {
        for p in PROTECTED_WINDOWS {
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

/// Check if a directory name should be skipped during scan (prune).
pub fn should_skip_dir(name: &str) -> bool {
    let nl = name.to_lowercase();
    SKIP_DIRS.iter().any(|d| nl == d.to_lowercase())
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
}
