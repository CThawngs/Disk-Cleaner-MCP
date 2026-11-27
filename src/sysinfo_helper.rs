//! System status + standard directories per OS.

use crate::model::*;
use std::collections::BTreeMap;
use sysinfo::{Disks, System};

pub fn get_system_status() -> SystemStatus {
    let disks_info = Disks::new_with_refreshed_list();

    let platform = if cfg!(windows) {
        "windows".into()
    } else if cfg!(target_os = "macos") {
        "macos".into()
    } else if cfg!(target_os = "linux") {
        "linux".into()
    } else {
        "unknown".into()
    };

    let hostname = System::host_name().unwrap_or_default();

    let temp_dir = std::env::temp_dir().to_string_lossy().to_string();
    let home_dir = dirs::home_dir()
        .map(|d| d.to_string_lossy().to_string())
        .unwrap_or_default();

    // Disk info
    let mut disks = Vec::new();
    for disk in disks_info.list() {
        let mount = disk.mount_point().to_string_lossy().to_string();
        let total = disk.total_space();
        let available = disk.available_space();
        let used = total.saturating_sub(available);
        let usage = if total > 0 {
            (used as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        disks.push(DiskInfo {
            mount_point: mount.clone(),
            total_bytes: total,
            used_bytes: used,
            available_bytes: available,
            usage_percent: usage,
            trash_bytes: trash_size_for(&mount),
        });
    }

    // User dirs
    let mut user_dirs = BTreeMap::new();
    if let Some(d) = dirs::home_dir() {
        user_dirs.insert("home".into(), d.to_string_lossy().to_string());
    }
    let temp = std::env::temp_dir();
    user_dirs.insert("temp".into(), temp.to_string_lossy().to_string());
    if let Some(d) = dirs::download_dir() {
        user_dirs.insert("downloads".into(), d.to_string_lossy().to_string());
    }
    if let Some(d) = dirs::cache_dir() {
        user_dirs.insert("cache".into(), d.to_string_lossy().to_string());
    }
    if let Some(d) = dirs::config_dir() {
        user_dirs.insert("config".into(), d.to_string_lossy().to_string());
    }
    if let Some(d) = dirs::data_dir() {
        user_dirs.insert("data".into(), d.to_string_lossy().to_string());
    }
    if let Some(d) = dirs::document_dir() {
        user_dirs.insert("documents".into(), d.to_string_lossy().to_string());
    }

    let metrics = Metrics {
        disk_count: disks.len() as u64,
        total_bytes: disks.iter().map(|d| d.total_bytes).sum(),
        used_bytes: disks.iter().map(|d| d.used_bytes).sum(),
        available_bytes: disks.iter().map(|d| d.available_bytes).sum(),
        trash_bytes: disks.iter().map(|d| d.trash_bytes).sum(),
        max_usage_percent: disks.iter().map(|d| d.usage_percent).fold(0.0f64, f64::max),
    };
    let health = if metrics.max_usage_percent >= 90.0 {
        "degraded".into()
    } else {
        "ok".into()
    };

    SystemStatus {
        platform,
        hostname,
        home_dir,
        temp_dir,
        disks,
        user_dirs,
        version: VERSION.into(),
        health,
        telemetry_enabled: std::env::var("DCM_TELEMETRY").is_ok(),
        metrics,
    }
}

/// Bounded iterative size of a trash bin; 0 when inaccessible (permissions, missing).
/// Never follows symlinks/reparse points and caps entry budget so huge trashed
/// trees (`node_modules`, `target`) cannot stall `get_system_status`.
#[cfg(not(windows))]
fn dir_size(root: &std::path::Path) -> u64 {
    const MAX_TRASH_WALK_ENTRIES: usize = 50_000;
    let mut total = 0u64;
    let mut seen = 0usize;
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&p) else {
            continue;
        };
        for e in rd.flatten() {
            seen += 1;
            if seen > MAX_TRASH_WALK_ENTRIES {
                return total;
            }
            let Ok(ft) = e.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(e.path());
            } else if let Ok(m) = e.metadata() {
                total = total.saturating_add(m.len());
            }
        }
    }
    total
}

#[cfg(windows)]
fn windows_recycle_bin_size(mount: &str) -> u64 {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    #[cfg_attr(target_arch = "x86", repr(C, packed))]
    #[cfg_attr(not(target_arch = "x86"), repr(C))]
    struct ShQueryRbInfo {
        cb_size: u32,
        i64_size: i64,
        i64_num_items: i64,
    }

    #[link(name = "shell32")]
    extern "system" {
        fn SHQueryRecycleBinW(
            psz_root_path: *const u16,
            p_sh_query_rb_info: *mut ShQueryRbInfo,
        ) -> i32;
    }

    if mount.is_empty() {
        return 0;
    }
    let wide: Vec<u16> = OsStr::new(mount)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut info = ShQueryRbInfo {
        cb_size: std::mem::size_of::<ShQueryRbInfo>() as u32,
        i64_size: 0,
        i64_num_items: 0,
    };
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 root path and `info` has `cb_size` initialized
    // to the exact ABI layout expected by `SHQueryRecycleBinW` (`shellapi.h`).
    let hr = unsafe { SHQueryRecycleBinW(wide.as_ptr(), &mut info) };
    if hr == 0 && info.i64_size > 0 {
        info.i64_size as u64
    } else {
        0
    }
}

fn trash_size_for(mount: &str) -> u64 {
    #[cfg(windows)]
    {
        windows_recycle_bin_size(mount)
    }
    #[cfg(target_os = "linux")]
    {
        // XDG trash lives on the home volume only.
        dirs::data_dir()
            .map(|d| (d.join("Trash").join("files"), mount))
            .filter(|(trash, _)| trash.exists())
            .map(|(trash, _)| dir_size(&trash))
            .unwrap_or(0)
    }
    #[cfg(target_os = "macos")]
    {
        let mount_path = std::path::Path::new(mount);
        // Home-volume trash lives in ~/.Trash; external volumes use
        // <mount>/.Trashes/<uid>. Measure whichever applies to this volume.
        if let Some(home) = dirs::home_dir() {
            if home.starts_with(mount_path) {
                return dir_size(&home.join(".Trash"));
            }
        }
        dir_size(&mount_path.join(".Trashes"))
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = mount;
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_status_completes_quickly_and_handles_empty_mount() {
        assert_eq!(trash_size_for(""), 0);
        let t0 = std::time::Instant::now();
        let st = get_system_status();
        assert!(!st.platform.is_empty());
        assert!(
            t0.elapsed().as_secs() < 10,
            "get_system_status took {:?}",
            t0.elapsed()
        );
    }
}
