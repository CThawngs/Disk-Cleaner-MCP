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

/// Recursive size of a trash bin; 0 when inaccessible (permissions, missing).
fn dir_size(root: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&p) else {
            continue;
        };
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() && !path.is_symlink() {
                total += dir_size(&path);
            } else if let Ok(m) = e.metadata() {
                total += m.len();
            }
        }
    }
    total
}

fn trash_size_for(mount: &str) -> u64 {
    #[cfg(windows)]
    {
        dir_size(&std::path::Path::new(mount).join("$Recycle.Bin"))
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
