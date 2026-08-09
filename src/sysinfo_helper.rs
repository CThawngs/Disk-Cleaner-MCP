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
            mount_point: mount,
            total_bytes: total,
            used_bytes: used,
            available_bytes: available,
            usage_percent: usage,
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

    SystemStatus {
        platform,
        hostname,
        home_dir,
        temp_dir,
        disks,
        user_dirs,
        version: VERSION.into(),
    }
}
