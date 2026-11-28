//! Container & WSL2 Virtual Disk auditor (`scan_container_virtual_disks`) — virtual disks stay `blocked`.

#![allow(dead_code)]

use crate::engine::{CustomCandidate, ScanEngine};
use crate::{insights::is_cloud_placeholder, model::ScanEntry, safety};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, UNIX_EPOCH};
use std::{borrow::Borrow, collections::BTreeSet, sync::mpsc};

const VHDX_REG_OFF: u64 = 192 * 1024;
const VHDX_META_GUID: u128 = 0x6e88_0f05_5f57_feb8_4b9a_4790_8b7c_a206;
const VHDX_VSIZE_GUID: u128 = 0xb8f4_3bd8_be5d_11b2_4876_cd1b_2fa5_4224;
const RUNTIMES: &str = "orbstack|rancher-desktop|podman|colima|lima|docker";
const HOME_VM_RAW: &str = "Library/Containers/com.docker.docker/Data/vms|.orbstack/data|\
.local/share/containers/podman/machine|.docker/desktop/vms|.local/share/docker/desktop/vms";

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, rename_all = "camelCase")]
pub struct ContainerScanParams {
    pub custom_roots: Option<Vec<String>>,
    pub custom_roots_only: Option<bool>,
    pub include_docker_df: Option<bool>,
    pub min_log_age_hours: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VirtualDiskItem {
    pub path: String,
    pub runtime: String,
    pub disk_format: String,
    pub allocated_bytes: u64,
    pub apparent_bytes: u64,
    pub modified: Option<i64>,
    pub verdict: String,
    pub deletable_via_mcp: bool,
    pub compaction_commands: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DockerDfCategory {
    pub category_type: String,
    pub total_count: u64,
    pub active_count: u64,
    pub size: String,
    pub reclaimable: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContainerReport {
    pub scan_id: String,
    pub duration_ms: u64,
    pub total_virtual_disks: usize,
    pub total_allocated_bytes: u64,
    pub total_apparent_bytes: u64,
    pub reclaimable_log_bytes: u64,
    pub virtual_disks: Vec<VirtualDiskItem>,
    pub docker_df: Vec<DockerDfCategory>,
    pub docker_df_status: String,
    pub disposable_logs: Vec<ScanEntry>,
    pub warnings: Vec<String>,
}

#[derive(Default)]
struct ScanAcc {
    now_secs: i64,
    min_age_secs: u64,
    alloc_sum: u64,
    apparent_sum: u64,
    seen: BTreeSet<PathBuf>,
    vdisks: Vec<VirtualDiskItem>,
    cands: Vec<CustomCandidate>,
}

pub fn scan_container_virtual_disks(
    engine: &ScanEngine,
    params: impl Borrow<ContainerScanParams>,
) -> ContainerReport {
    let (params, started) = (params.borrow(), Instant::now());
    let custom_only = params.custom_roots_only.unwrap_or(false);
    let mut warnings = Vec::new();
    let mut acc = ScanAcc {
        now_secs: UNIX_EPOCH.elapsed().unwrap_or_default().as_secs() as i64,
        min_age_secs: params.min_log_age_hours.unwrap_or(24).saturating_mul(3_600),
        ..Default::default()
    };
    if !custom_only {
        scan_os_roots(&mut acc);
    }
    let roots = params.custom_roots.as_deref().unwrap_or(&[]);
    for s in roots.iter().map(|r| r.trim()).filter(|r| !r.is_empty()) {
        let root = PathBuf::from(s);
        if root.is_dir() {
            scan_tree(&mut acc, &root, 5, false, false);
            scan_tree(&mut acc, &root.join("Docker/log"), 5, true, false);
        } else {
            warnings.push(format!("Custom root does not exist: {s}"));
        }
    }
    acc.vdisks.sort_by_key(|d| u64::MAX - d.allocated_bytes);
    let want_df = params.include_docker_df.unwrap_or(true) && !custom_only;
    let (docker_df, docker_df_status) = probe_docker_df(want_df, &mut warnings);
    // HARD INVARIANT: Virtual disks MUST NEVER enter `cands` / `register_custom_session`.
    let mut cands = acc.cands;
    cands.retain(|c| classify_vdisk(&c.path, true).is_none());
    let (dur, w) = (started.elapsed().as_millis() as u64, warnings.clone());
    let sess = engine.register_custom_session("container_cache", cands, w, dur, true);
    ContainerReport {
        scan_id: sess.scan_id.clone(),
        duration_ms: dur,
        total_virtual_disks: acc.vdisks.len(),
        total_allocated_bytes: acc.alloc_sum,
        total_apparent_bytes: acc.apparent_sum,
        reclaimable_log_bytes: sess.summary.reclaimable_bytes,
        virtual_disks: acc.vdisks,
        docker_df,
        docker_df_status,
        disposable_logs: sess.entries.clone(),
        warnings,
    }
}

pub fn parse_docker_system_df_jsonl(stdout: &str) -> Vec<DockerDfCategory> {
    stdout.lines().filter_map(parse_df).collect()
}

fn parse_df(line: &str) -> Option<DockerDfCategory> {
    let m: Map<String, Value> = serde_json::from_str(line.trim()).ok()?;
    let kind = m.get("Type")?.as_str()?.trim();
    let num = |k| {
        let x = m.get(k)?;
        x.as_u64().or_else(|| x.as_str()?.trim().parse().ok())
    };
    let txt = |k| m.get(k).and_then(Value::as_str).unwrap_or("0B").trim();
    (!kind.is_empty()).then(|| DockerDfCategory {
        category_type: kind.into(),
        total_count: num("TotalCount").unwrap_or(0),
        active_count: num("Active").unwrap_or(0),
        size: txt("Size").into(),
        reclaimable: txt("Reclaimable").into(),
    })
}

pub fn compaction_runbook_for(path: &Path, runtime: &str, disk_format: &str) -> Vec<String> {
    let p = path.to_string_lossy();
    let vhd = format!(
        "wsl --shutdown\nOptimize-VHD -Path \"{p}\" -Mode Full\n\
         diskpart -> select vdisk file=\"{p}\" -> compact vdisk"
    );
    let q = format!("qemu-img convert -O qcow2 \"{p}\" \"{p}.c\"");
    let joined = match (disk_format, runtime) {
        ("vhdx", "docker") => format!("docker system prune -f && docker builder prune -f\n{vhd}"),
        ("vhdx", _) => vhd,
        (_, "orbstack") => "docker builder prune -f\nOrbStack: orbctl restart".into(),
        (_, "lima" | "colima") => format!("Lima: limactl shell default sudo fstrim -av\n{q}"),
        (_, "podman") => format!("podman system prune -af\n{q}"),
        _ => "docker builder prune -f\nOrbStack/Lima: sudo fstrim -av".into(),
    };
    joined.lines().map(Into::into).collect()
}

fn scan_os_roots(acc: &mut ScanAcc) {
    if let Some(local) = dirs::data_local_dir() {
        for r in "Docker/wsl|rancher-desktop|containers/podman".split('|') {
            scan_tree(acc, &local.join(r), 6, false, false);
        }
        let pkgs = fs::read_dir(local.join("Packages"));
        for e in pkgs.into_iter().flatten().flatten() {
            scan_tree(acc, &e.path().join("LocalState"), 1, false, false);
        }
        scan_tree(acc, &local.join("Docker/log"), 6, true, false);
    }
    if let Some(h) = dirs::home_dir() {
        for r in ".wsl|.colima|.lima".split('|') {
            scan_tree(acc, &h.join(r), 6, false, false);
        }
        for r in HOME_VM_RAW.split('|') {
            scan_tree(acc, &h.join(r), 6, false, true);
        }
        for r in "Library/Containers/com.docker.docker/Data/log|.docker/desktop/log".split('|') {
            scan_tree(acc, &h.join(r), 6, true, false);
        }
    }
}

fn scan_tree(acc: &mut ScanAcc, root: &Path, max_depth: usize, logs_mode: bool, allow_raw: bool) {
    let blocked_root = safety::sensitive_never_touch_reason(root).is_some();
    if !root.is_dir() || blocked_root || (logs_mode && safety::is_protected(root)) {
        return;
    }
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            let path = entry.path();
            if !ft.is_symlink() && ft.is_dir() && depth < max_depth {
                let n = entry.file_name().to_string_lossy().to_ascii_lowercase();
                let skip = n == ".git" || n == "node_modules" || (!logs_mode && n == "log");
                if !skip && safety::sensitive_never_touch_reason(&path).is_none() {
                    stack.push((path, depth + 1));
                }
            } else if !ft.is_symlink() && ft.is_file() {
                if let Ok(m) = path.symlink_metadata() {
                    if !m.file_type().is_symlink() && m.is_file() && !is_cloud_placeholder(&m) {
                        let _ = match logs_mode {
                            true => record_log(acc, path, &m),
                            false => record_vdisk(acc, &path, &m, allow_raw),
                        };
                    }
                }
            }
        }
    }
}

fn record_vdisk(acc: &mut ScanAcc, path: &Path, meta: &fs::Metadata, raw_ok: bool) -> Option<()> {
    let (fmt, rt) = classify_vdisk(path, raw_ok)?;
    acc.seen.insert(safety::normalize(path)).then_some(())?;
    let (allocated_bytes, apparent_bytes) = measure_disk_sizes(path, meta, fmt);
    acc.alloc_sum = acc.alloc_sum.saturating_add(allocated_bytes);
    acc.apparent_sum = acc.apparent_sum.saturating_add(apparent_bytes);
    acc.vdisks.push(VirtualDiskItem {
        path: path.to_string_lossy().into(),
        runtime: rt.into(),
        disk_format: fmt.into(),
        allocated_bytes,
        apparent_bytes,
        modified: mtime(meta),
        verdict: "blocked".into(),
        deletable_via_mcp: false,
        compaction_commands: compaction_runbook_for(path, rt, fmt),
    });
    Some(())
}

fn record_log(acc: &mut ScanAcc, path: PathBuf, meta: &fs::Metadata) -> Option<()> {
    let n = path.file_name()?.to_str()?.to_ascii_lowercase();
    let is_log = n.ends_with(".log") || n.ends_with(".old") || n.contains(".log.");
    let bad = safety::is_protected(&path) || safety::sensitive_never_touch_reason(&path).is_some();
    (is_log && !bad && classify_vdisk(&path, true).is_none() && !meta.permissions().readonly())
        .then_some(())?;
    let mod_secs = mtime(meta)?;
    let age = acc.now_secs.saturating_sub(mod_secs).max(0) as u64;
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::share_mode(opts.write(true), 0);
    (age >= acc.min_age_secs && opts.open(&path).is_ok()).then_some(())?;
    acc.seen.insert(safety::normalize(&path)).then_some(())?;
    acc.cands.push(CustomCandidate {
        kind: "file".into(),
        path,
        size: meta.len(),
        modified: Some(mod_secs),
        category: "container_cache".into(),
        verdict: "safe_to_delete".into(),
        importance_score: 10,
        risk_level: "safe".into(),
        reasons: vec![format!("Container log ({}h old)", age / 3_600)],
    });
    Some(())
}

fn classify_vdisk(path: &Path, allow_raw: bool) -> Option<(&'static str, &'static str)> {
    let name = path.file_name()?.to_string_lossy();
    let raw = path.to_string_lossy().to_ascii_lowercase();
    let s = raw.replace('\\', "/");
    let vm_dirs = "/orbstack/|/podman/machine/|/docker/desktop/vms/";
    let in_vm = allow_raw || vm_dirs.split('|').any(|p| s.contains(p));
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let fmt = match (name.as_ref(), ext.to_ascii_lowercase().as_str()) {
        (n, _) if n.eq_ignore_ascii_case("docker.raw") => "raw",
        (n, _) if n.eq_ignore_ascii_case("diffdisk") => "diffdisk",
        (_, "vhdx") => "vhdx",
        (_, "qcow2") => "qcow2",
        (_, "raw") if in_vm => "raw",
        (_, "img") if in_vm => "img",
        _ => return None,
    };
    let is_wsl = fmt == "vhdx" || s.contains("/.wsl/") || s.contains("/packages/");
    let def_rt = if is_wsl { "wsl2" } else { "container-vm" };
    let rt = RUNTIMES.split('|').find(|k| s.contains(k));
    Some((fmt, rt.unwrap_or(def_rt)))
}

fn measure_disk_sizes(path: &Path, meta: &fs::Metadata, fmt: &str) -> (u64, u64) {
    #[cfg(unix)]
    let alloc = std::os::unix::fs::MetadataExt::blocks(meta).saturating_mul(512);
    #[cfg(windows)]
    let alloc = win_alloc(path, meta.len());
    #[cfg(not(any(unix, windows)))]
    let alloc = meta.len();
    let len = meta.len();
    let base = if cfg!(windows) { len.max(alloc) } else { len };
    let v = (fmt == "vhdx").then(|| read_vhdx_vsize(path)).flatten();
    (alloc, base.max(v.unwrap_or(0)))
}

#[cfg(windows)]
fn win_alloc(path: &Path, fallback: u64) -> u64 {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCompressedFileSizeW(name: *const u16, high: *mut u32) -> u32;
        fn GetLastError() -> u32;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut high = 0u32;
    // SAFETY: `wide` is null-terminated UTF-16 valid for the call; `&mut high` is stack-aligned.
    let low = unsafe { GetCompressedFileSizeW(wide.as_ptr(), &mut high) };
    // SAFETY: `GetLastError` reads thread-local Win32 error state with no pointer arguments.
    if low == u32::MAX && unsafe { GetLastError() } != 0 {
        return fallback;
    }
    ((high as u64) << 32) | (low as u64)
}

fn read_vhdx_vsize(path: &Path) -> Option<u64> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::share_mode(&mut opts, 7);
    let mut f = opts.open(path).ok()?;
    let mut buf = vec![0u8; 4_096];
    fn find_g(b: &[u8], g: u128) -> Option<&[u8]> {
        b.chunks_exact(32).find(|e| e[..16] == g.to_le_bytes())
    }
    rd_at(&mut f, 0, &mut buf[..8]).filter(|_| &buf[..8] == b"vhdxfile")?;
    rd_at(&mut f, VHDX_REG_OFF, &mut buf[..16]).filter(|_| buf.starts_with(b"regi"))?;
    let rlen = (u32::from_le_bytes(buf[8..12].try_into().ok()?).min(64) as usize) * 32;
    f.read_exact(&mut buf[..rlen]).ok()?;
    let rent = find_g(&buf[..rlen], VHDX_META_GUID)?;
    let rstart = u64::from_le_bytes(rent[16..24].try_into().ok()?);
    rd_at(&mut f, rstart, &mut buf[..32]).filter(|_| &buf[..8] == b"metadata")?;
    let ilen = (u16::from_le_bytes(buf[10..12].try_into().ok()?).min(128) as usize) * 32;
    f.read_exact(&mut buf[..ilen]).ok()?;
    let ient = find_g(&buf[..ilen], VHDX_VSIZE_GUID)?;
    (u32::from_le_bytes(ient[20..24].try_into().ok()?) >= 8).then_some(())?;
    let rel = u32::from_le_bytes(ient[16..20].try_into().ok()?) as u64;
    rd_at(&mut f, rstart.checked_add(rel)?, &mut buf[..8])?;
    let vsize = u64::from_le_bytes(buf[..8].try_into().ok()?);
    (vsize > 0).then_some(vsize)
}

fn rd_at(f: &mut fs::File, off: u64, buf: &mut [u8]) -> Option<()> {
    f.seek(SeekFrom::Start(off))
        .and_then(|_| f.read_exact(buf))
        .ok()
}

fn mtime(meta: &fs::Metadata) -> Option<i64> {
    let d = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    Some(d.as_secs() as i64)
}

fn probe_docker_df(want: bool, warnings: &mut Vec<String>) -> (Vec<DockerDfCategory>, String) {
    if !want {
        return (Vec::new(), "skipped".into());
    }
    let mut cmd = Command::new("docker");
    cmd.args(["system", "df", "--format", "{{json .}}"]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    let Ok(mut child) = cmd.spawn() else {
        return (Vec::new(), "unavailable".into());
    };
    let (tx, rx) = mpsc::channel();
    if let Some(s) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut b = String::new();
            let _ = (s.take(262_144).read_to_string(&mut b), tx.send(b));
        });
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(st)) if st.success() => {
                let out = rx.recv_timeout(Duration::from_secs(1)).unwrap_or_default();
                return (parse_docker_system_df_jsonl(&out), "ok".into());
            }
            Ok(Some(_)) => return (Vec::new(), "unavailable".into()),
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => break,
        }
    }
    let (_k, _w) = (child.kill(), child.wait());
    warnings.push("docker system df timed out after 3s".into());
    (Vec::new(), "timeout".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, fs::FileTimes, io::Write, time::SystemTime};

    fn setup(tag: &str, spec: &str) -> (PathBuf, ContainerScanParams) {
        let ns = UNIX_EPOCH.elapsed().unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("dcm-{tag}-{ns}"));
        fs::create_dir_all(&root).unwrap();
        for (rel, h) in spec.split('|').filter_map(|s| s.split_once(':')) {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            let mut f = File::create(&p).unwrap();
            f.write_all(&[1u8; 512]).unwrap();
            let ts = SystemTime::now() - Duration::from_secs(h.parse::<u64>().unwrap() * 3_600);
            f.set_times(FileTimes::new().set_modified(ts)).unwrap();
        }
        let p = ContainerScanParams {
            custom_roots: Some(vec![root.to_string_lossy().into()]),
            custom_roots_only: Some(true),
            ..Default::default()
        };
        (root, p)
    }

    #[test]
    fn virtual_disks_never_in_scan_session_while_old_logs_are() {
        let spec = "Docker/wsl/ext4.vhdx:72|vms/0/Docker.raw:72|lima/diffdisk:72|\
                    podman/vm.qcow2:72|Docker/log/host.log:48|Docker/log/fresh.log:0";
        let (root, params) = setup("inv", spec);
        let engine = ScanEngine::new();
        let r = scan_container_virtual_disks(&engine, &params);
        assert!(r.virtual_disks.iter().all(|v| v.verdict == "blocked"));
        assert!(r.virtual_disks.iter().all(|v| !v.deletable_via_mcp));
        let s = engine.get_session(&r.scan_id).unwrap();
        assert_eq!((r.virtual_disks.len(), s.entries.len()), (4, 1));
        let e = &s.entries[0];
        assert!(e.path.ends_with("host.log") && e.verdict == "safe_to_delete");
        assert_eq!(e.category, "container_cache");
        assert!(safety::verify_token(&s.salt, &e.path, &e.approval_token));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sneaky_vdisk_in_log_folder_is_blocked_from_session() {
        let spec = "Docker/log/ext4.vhdx:96|Docker/log/Docker.raw:96|Docker/log/a.old:36|Docker/log/b.log.1:36";
        let (root, params) = setup("snk", spec);
        let engine = ScanEngine::new();
        let r = scan_container_virtual_disks(&engine, params);
        let s = engine.get_session(&r.scan_id).unwrap();
        assert_eq!(s.entries.len(), 2);
        assert!(s.entries.iter().all(|e| !e.path.ends_with(".vhdx")));
        assert!(s.entries.iter().all(|e| !e.path.ends_with(".raw")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn parse_docker_df_jsonl_parses_all_categories_and_ignores_junk() {
        let raw = "{\"Active\":\"2\",\"Reclaimable\":\"1GB\",\"Size\":\"3GB\",\"TotalCount\":\"5\",\"Type\":\"Images\"}\n\
                   bad\n{\"Type\":\"\"}\n\
                   {\"Active\":1,\"Reclaimable\":\"0B\",\"Size\":\"9MB\",\"TotalCount\":3,\"Type\":\"Containers\"}\n\
                   {\"Active\":\"0\",\"Reclaimable\":\"5MB\",\"Size\":\"5MB\",\"TotalCount\":\"2\",\"Type\":\"Local Volumes\"}\n\
                   {\"Active\":\"0\",\"Reclaimable\":\"4GB\",\"Size\":\"4GB\",\"TotalCount\":\"8\",\"Type\":\"Build Cache\"}";
        let out = parse_docker_system_df_jsonl(raw);
        assert_eq!((out.len(), out[0].total_count), (4, 5));
        assert!(out[0].category_type == "Images" && out[3].category_type == "Build Cache");
    }

    #[test]
    fn compaction_runbook_covers_vhdx_and_raw_qcow2_runtimes() {
        let s = compaction_runbook_for(Path::new(r"C:\wsl\ext4.vhdx"), "docker", "vhdx").join(" ");
        assert!(s.contains("wsl --shutdown") && s.contains("Optimize-VHD"));
        assert!(s.contains("diskpart"));
        let o = compaction_runbook_for(Path::new("/orbstack/d.raw"), "orbstack", "raw").join(" ");
        assert!(o.contains("docker builder prune") && o.contains("OrbStack"));
        let l = compaction_runbook_for(Path::new("/lima/vm.qcow2"), "lima", "qcow2").join(" ");
        assert!(l.contains("Lima") && l.contains("qemu-img"));
    }

    #[test]
    fn vhdx_virtual_size_header_parsed_even_when_shared_open() {
        let vhdx = std::env::temp_dir().join(format!("dcm-v-{}.vhdx", std::process::id()));
        let (m, r, vs) = (200_704usize, VHDX_REG_OFF as usize, 256u64 << 30);
        let mut b = vec![0u8; m + 136];
        b[..8].copy_from_slice(b"vhdxfile");
        b[r..r + 12].copy_from_slice(b"regi\0\0\0\0\x01\0\0\0");
        b[r + 16..r + 32].copy_from_slice(&VHDX_META_GUID.to_le_bytes());
        b[r + 32..r + 40].copy_from_slice(&(m as u64).to_le_bytes());
        b[m..m + 12].copy_from_slice(b"metadata\0\0\x01\0");
        b[m + 32..m + 48].copy_from_slice(&VHDX_VSIZE_GUID.to_le_bytes());
        b[m + 48..m + 56].copy_from_slice(&[128, 0, 0, 0, 8, 0, 0, 0]);
        b[m + 128..m + 136].copy_from_slice(&vs.to_le_bytes());
        fs::write(&vhdx, &b).unwrap();
        let _held = File::open(&vhdx).unwrap();
        assert_eq!(read_vhdx_vsize(&vhdx), Some(vs));
        let _ = fs::remove_file(&vhdx);
    }
}
