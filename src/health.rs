//! Cross-platform Hardware, Battery & SSD SMART Health + Agent I/O Guardrails.
#![allow(dead_code)]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{path::Path, process::Command, time::UNIX_EPOCH};
use sysinfo::Disks;

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatteryHealthInfo {
    pub present: bool,
    pub status: Option<String>,
    pub ac_power: Option<bool>,
    pub charge_percent: Option<f64>,
    pub health_percent: Option<f64>,
    pub cycle_count: Option<u32>,
    pub condition: Option<String>,
    pub unavailable_reason: Option<String>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PhysicalDiskHealth {
    pub index: usize,
    pub model: Option<String>,
    pub media_type: Option<String>,
    pub bus_type: Option<String>,
    pub size_bytes: Option<u64>,
    pub health_status: Option<String>,
    pub temperature_c: Option<f64>,
    pub wear_percent: Option<f64>,
    pub power_on_hours: Option<u64>,
    pub smart_available: bool,
    pub unavailable_reason: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VolumeSpaceHealth {
    pub mount_point: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub free_percent: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentIoGuardrails {
    pub io_safety_level: String,
    pub avoid_heavy_disk_hash: bool,
    pub minimize_write_churn: bool,
    pub disk_pressure_action: String,
    pub reasons: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HardwareHealthReport {
    pub platform: String,
    pub collected_at: i64,
    pub battery: BatteryHealthInfo,
    pub disks: Vec<PhysicalDiskHealth>,
    pub disks_unavailable_reason: Option<String>,
    pub volumes: Vec<VolumeSpaceHealth>,
    pub agent_guardrails: AgentIoGuardrails,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    Many(Vec<T>),
    One(T),
}
type Bat = BatteryHealthInfo;
type Disk = PhysicalDiskHealth;

fn bat_na(reason: &str) -> Bat {
    Bat {
        unavailable_reason: Some(reason.into()),
        ..Default::default()
    }
}
fn nvme_disk(index: usize, model: Option<&str>, na: Option<&str>) -> Disk {
    Disk {
        index,
        model: model.and_then(sanitize_model_name),
        media_type: Some("SSD".into()),
        bus_type: Some("NVMe".into()),
        unavailable_reason: na.map(Into::into),
        ..Default::default()
    }
}
fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}
fn na_if(cond: bool, msg: &str) -> Option<String> {
    cond.then(|| msg.into())
}
fn bat_status(full: bool, chg: bool, ac: Option<bool>) -> Option<String> {
    match (full, chg, ac) {
        (true, _, _) => Some("full".into()),
        (_, true, _) => Some("charging".into()),
        (_, _, Some(v)) => Some(if v { "ac_attached" } else { "discharging" }.into()),
        _ => None,
    }
}
fn sanitize_model_name(raw: &str) -> Option<String> {
    const PFX: [&str; 5] = ["sn:", "serial:", "uuid:", "eui.", "nvme."];
    let ok = |t: &&str| !PFX.iter().any(|p| t.to_ascii_lowercase().starts_with(p));
    let parts: Vec<&str> = raw.split_whitespace().filter(ok).collect();
    (!parts.is_empty()).then(|| parts.join(" "))
}
fn j_str(v: &Value, ptr: &str) -> Option<String> {
    let s = v.pointer(ptr)?.as_str()?.trim();
    (!s.is_empty()).then(|| s.to_string())
}
fn j_u64(v: &Value, ptr: &str) -> Option<u64> {
    v.pointer(ptr)?.as_u64()
}
fn j_f64(v: &Value, ptr: &str) -> Option<f64> {
    v.pointer(ptr)?.as_f64()
}
fn run_stdout(prog: &str, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new(prog);
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    let o = cmd.args(args).output().ok()?;
    let s = String::from_utf8_lossy(&o.stdout);
    o.status.success().then(|| s.into_owned())
}
pub fn get_hardware_health() -> HardwareHealthReport {
    let now = UNIX_EPOCH.elapsed().unwrap_or_default().as_secs() as i64;
    let os = std::env::consts::OS;
    let p = ["windows", "macos", "linux"]
        .into_iter()
        .find(|&x| x == os)
        .unwrap_or("unknown");
    let (battery, disks, disks_unavailable_reason) = collect_os_hardware();
    let mut volumes = Vec::new();
    let list = Disks::new_with_refreshed_list();
    for d in list.list().iter().filter(|d| d.total_space() > 0) {
        let (tot, avail) = (d.total_space(), d.available_space());
        volumes.push(VolumeSpaceHealth {
            mount_point: d.mount_point().to_string_lossy().into_owned(),
            total_bytes: tot,
            available_bytes: avail,
            free_percent: round1((avail as f64 / tot as f64) * 100.0),
        });
    }
    let min_free = volumes.iter().map(|v| v.free_percent).reduce(f64::min);
    let agent_guardrails = compute_agent_guardrails(&battery, &disks, min_free);
    HardwareHealthReport {
        platform: p.into(),
        collected_at: now,
        battery,
        disks,
        disks_unavailable_reason,
        volumes,
        agent_guardrails,
    }
}
macro_rules! chk {
    ($g:ident, $r:ident, $c:expr, $m:expr, $($t:tt)*) => {
        if $c {
            $g |= $m;
            $r.push(format!($($t)*));
        }
    };
}
pub fn compute_agent_guardrails(bat: &Bat, disks: &[Disk], free: Option<f64>) -> AgentIoGuardrails {
    let (mut g, mut r, mut act) = (0u8, Vec::new(), "none");
    if bat.present && bat.ac_power == Some(false) {
        let p = bat.charge_percent.unwrap_or(50.0);
        chk!(g, r, p < 15.0, 14, "Battery critical ({p:.1}%)");
        chk!(g, r, (15.0..35.0).contains(&p), 5, "Low battery ({p:.1}%)");
        chk!(g, r, p >= 35.0, 1, "On battery power; prefer bounded scans");
    }
    for d in disks {
        let (i, w) = (d.index, d.wear_percent.unwrap_or(0.0));
        let t = d.temperature_c.unwrap_or(0.0);
        let raw = d.health_status.as_deref().unwrap_or("");
        let st = raw.to_ascii_lowercase();
        let bad = st.contains("unhealthy") || st.contains("fail") || st == "bad";
        let warn = !bad && (st.contains("warn") || st.contains("degraded"));
        let (whi, thi) = ((80.0..95.0).contains(&w), (65.0..75.0).contains(&t));
        chk!(g, r, bad, 14, "Disk #{i} unhealthy");
        chk!(g, r, warn, 9, "Disk #{i} warning");
        chk!(g, r, w >= 95.0, 14, "Disk #{i} wear critical ({w:.0}%)");
        chk!(g, r, whi, 9, "Disk #{i} wear high ({w:.0}%)");
        chk!(g, r, t >= 75.0, 14, "Disk #{i} temp critical ({t:.0} C)");
        chk!(g, r, thi, 9, "Disk #{i} temp high ({t:.0} C)");
    }
    if let Some(f) = free {
        let low = (5.0..12.0).contains(&f);
        chk!(g, r, f < 5.0, 10, "Free space critical ({f:.1}%)");
        chk!(g, r, low, 1, "Free space low ({f:.1}%)");
        let idx = usize::from(f < 12.0) + usize::from(f < 5.0);
        act = ["none", "run_smart_scan", "urgent_cleanup_safe_only"][idx];
    }
    if r.is_empty() {
        r.push("Power, thermal, SMART, and free-space within safe bounds".into());
    }
    AgentIoGuardrails {
        io_safety_level: ["green", "caution", "critical", "critical"][(g & 3) as usize].into(),
        avoid_heavy_disk_hash: (g & 4) != 0,
        minimize_write_churn: (g & 8) != 0,
        disk_pressure_action: act.into(),
        reasons: r,
    }
}
fn xml_tag<'a>(b: &'a str, tag: &str) -> Option<&'a str> {
    let s = b.find(&format!("<{tag}>"))? + tag.len() + 2;
    let v = b[s..s + b[s..].find(&format!("</{tag}>"))?].trim();
    (!v.is_empty()).then_some(v)
}
fn xml_u64(b: &str, tag: &str) -> Option<u64> {
    xml_tag(b, tag)?.parse().ok()
}
pub fn parse_windows_battery_xml(xml: &str, pct: Option<f64>, ac: Option<bool>) -> Bat {
    let (mut d_sum, mut f_sum, mut found) = (0u64, 0u64, false);
    let mut b = Bat::default();
    let parts = xml.split("<Battery>").skip(1);
    for (blk, _) in parts.filter_map(|p| p.split_once("</Battery>")) {
        found = true;
        d_sum += xml_u64(blk, "DesignCapacity").unwrap_or(0);
        f_sum += xml_u64(blk, "FullChargeCapacity").unwrap_or(0);
        if let Some(c) = xml_u64(blk, "CycleCount").filter(|&c| c > 0) {
            b.cycle_count = Some(b.cycle_count.map_or(c as u32, |p| p.max(c as u32)));
        }
    }
    if !found && pct.is_none() {
        return bat_na("No battery detected (desktop or VM)");
    }
    b.present = true;
    b.ac_power = ac;
    b.charge_percent = pct.map(round1);
    if d_sum > 0 && f_sum > 0 {
        let h = round1((f_sum as f64 / d_sum as f64) * 100.0);
        b.health_percent = Some(h);
        let c = if h >= 80.0 {
            "Normal"
        } else {
            "Service Recommended"
        };
        b.condition = Some(c.into());
    }
    b.status = bat_status(ac == Some(true) && pct.unwrap_or(0.0) >= 99.5, false, ac);
    b.unavailable_reason = na_if(b.cycle_count.is_none(), "Cycle count unavailable");
    b
}
pub fn parse_windows_disks_json(json: &str) -> Result<Vec<Disk>, String> {
    let t = json.trim();
    if t.is_empty() || t == "null" {
        return Ok(Vec::new());
    }
    let items = match serde_json::from_str::<OneOrMany<Value>>(t).map_err(|e| e.to_string())? {
        OneOrMany::One(v) => vec![v],
        OneOrMany::Many(v) => v,
    };
    let def_na = "SMART counters unavailable (non-admin or unsupported bus)";
    let mut out = Vec::with_capacity(items.len());
    for (index, r) in items.iter().enumerate() {
        let wear = j_f64(r, "/Wear");
        let temp = j_f64(r, "/Temperature").filter(|&v| v > 0.0 && v < 150.0);
        let sa = r.pointer("/SmartAvailable").and_then(Value::as_bool);
        let smart = sa.unwrap_or(wear.is_some() || temp.is_some());
        let ur = j_str(r, "/UnavailableReason").unwrap_or_else(|| def_na.into());
        out.push(Disk {
            index,
            model: j_str(r, "/FriendlyName")
                .as_deref()
                .and_then(sanitize_model_name),
            media_type: j_str(r, "/MediaType"),
            bus_type: j_str(r, "/BusType"),
            size_bytes: j_u64(r, "/Size"),
            health_status: j_str(r, "/HealthStatus"),
            temperature_c: temp,
            wear_percent: wear,
            power_on_hours: j_u64(r, "/PowerOnHours"),
            smart_available: smart,
            unavailable_reason: (!smart).then_some(ur),
        });
    }
    Ok(out)
}
fn mac_bytes(v: &str) -> Option<u64> {
    let (raw, _) = v.split_once('(')?.1.split_once("bytes")?;
    raw.chars()
        .filter(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}
pub fn parse_macos_power_output(sp: &str, ioreg: Option<&str>) -> (Bat, Vec<Disk>) {
    let mut has_bat = sp.contains("Battery Information:");
    let mut b = Bat::default();
    let (mut chg, mut full, mut disks) = (false, false, Vec::<Disk>::new());
    let mac_na = Some("Detailed NVMe counters require smartctl on macOS");
    for (rk, rv) in sp.lines().filter_map(|l| l.trim().split_once(':')) {
        let (k, v) = (rk.trim(), rv.trim());
        match (k, disks.last_mut()) {
            ("State of Charge (%)", _) => b.charge_percent = v.parse().ok(),
            ("Maximum Capacity", _) => {
                b.health_percent = v.trim_end_matches('%').trim().parse().ok()
            }
            ("Cycle Count", _) => b.cycle_count = v.parse().ok(),
            ("Condition", _) => b.condition = Some(v.into()),
            ("Connected", _) => b.ac_power = Some(v.eq_ignore_ascii_case("yes")),
            ("Charging", _) => chg |= v.eq_ignore_ascii_case("yes"),
            ("Fully Charged", _) => full |= v.eq_ignore_ascii_case("yes"),
            ("Model", _) => disks.push(nvme_disk(disks.len(), Some(v), mac_na)),
            ("Capacity", Some(d)) => d.size_bytes = mac_bytes(v),
            ("S.M.A.R.T. status", Some(d)) => d.health_status = Some(v.into()),
            _ => {}
        }
    }
    if let Some(io) = ioreg {
        has_bat |= io.contains("AppleSmartBattery");
        if let (None, Some(p)) = (b.cycle_count, io.find("<key>CycleCount</key>")) {
            b.cycle_count = xml_u64(&io[p..], "integer").map(|c| c as u32);
        }
        if let (None, Some(p)) = (b.ac_power, io.find("<key>ExternalConnected</key>")) {
            let tail = &io[p..p.saturating_add(80).min(io.len())];
            let tr = tail.contains("<true/>").then_some(true);
            b.ac_power = tr.or_else(|| tail.contains("<false/>").then_some(false));
        }
    }
    if !has_bat {
        return (bat_na("No battery reported on macOS"), disks);
    }
    b.present = true;
    b.status = bat_status(full, chg, b.ac_power);
    b.unavailable_reason = na_if(b.health_percent.is_none(), "Maximum Capacity % unavailable");
    (b, disks)
}
fn read_str(dir: &Path, name: &str) -> Option<String> {
    let s = std::fs::read_to_string(dir.join(name)).ok()?;
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}
fn read_u64(dir: &Path, name: &str) -> Option<u64> {
    read_str(dir, name)?.parse().ok()
}
pub fn parse_linux_power_supply(bat_dir: &Path, ac_online: Option<bool>) -> Bat {
    if !bat_dir.is_dir() {
        return bat_na("Linux battery sysfs directory not found");
    }
    let st_lc = read_str(bat_dir, "status").map(|s| s.to_ascii_lowercase());
    let cyc = read_u64(bat_dir, "cycle_count").filter(|&c| c > 0);
    let ed_ef = read_u64(bat_dir, "energy_full_design").zip(read_u64(bat_dir, "energy_full"));
    let cd_cf = read_u64(bat_dir, "charge_full_design").zip(read_u64(bat_dir, "charge_full"));
    let pair = ed_ef.or(cd_cf).filter(|&(d, f)| d > 0 && f > 0);
    let hp = pair.map(|(d, f)| round1((f as f64 / d as f64) * 100.0));
    let ac = ac_online.or(match st_lc.as_deref() {
        Some("discharging") => Some(false),
        Some("charging" | "full") => Some(true),
        _ => None,
    });
    Bat {
        present: true,
        status: st_lc,
        ac_power: ac,
        charge_percent: read_str(bat_dir, "capacity").and_then(|s| s.parse().ok()),
        health_percent: hp,
        cycle_count: cyc.map(|c| c as u32),
        condition: hp.map(|h| if h >= 80.0 { "Normal" } else { "Degraded" }.into()),
        unavailable_reason: None,
    }
}
pub fn parse_smartctl_json(json: &str, index: usize) -> Result<Disk, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("Bad smartctl JSON: {e}"))?;
    let nv = "/nvme_smart_health_information_log";
    let mut d = nvme_disk(index, j_str(&v, "/model_name").as_deref(), None);
    d.bus_type = j_str(&v, "/device/protocol").or_else(|| j_str(&v, "/device/type"));
    d.size_bytes = j_u64(&v, "/user_capacity/bytes");
    let passed = v.pointer("/smart_status/passed").and_then(Value::as_bool);
    d.health_status = passed.map(|ok| if ok { "Healthy" } else { "Unhealthy" }.into());
    let nv_t = j_f64(&v, &format!("{nv}/temperature"));
    d.temperature_c = nv_t.or_else(|| j_f64(&v, "/temperature/current"));
    d.wear_percent = j_f64(&v, &format!("{nv}/percentage_used"));
    let nv_h = j_u64(&v, &format!("{nv}/power_on_hours"));
    d.power_on_hours = nv_h.or_else(|| j_u64(&v, "/power_on_time/hours"));
    d.smart_available = passed.is_some() || d.temperature_c.is_some() || d.wear_percent.is_some();
    d.unavailable_reason = na_if(!d.smart_available, "smartctl returned no SMART data");
    Ok(d)
}
fn run_smart(dev: &str, idx: usize) -> Option<Disk> {
    let s = run_stdout("smartctl", &["-a", "-j", dev])?;
    parse_smartctl_json(&s, idx)
        .ok()
        .filter(|d| d.smart_available)
}
fn collect_os_hardware() -> (Bat, Vec<Disk>, Option<String>) {
    #[cfg(windows)]
    {
        let ps = "$ErrorActionPreference='SilentlyContinue';$bat=@(Get-CimInstance Win32_Battery|Select-Object EstimatedChargeRemaining,BatteryStatus);$disks=@(Get-PhysicalDisk|ForEach-Object{$d=$_;$r=$null;$e=$null;try{$r=$d|Get-StorageReliabilityCounter -ErrorAction Stop}catch{$e='SMART reliability counters require elevated privileges on Windows'};[pscustomobject]@{FriendlyName=[string]$d.FriendlyName;MediaType=[string]$d.MediaType;BusType=[string]$d.BusType;HealthStatus=[string]$d.HealthStatus;Size=$d.Size;Wear=if($r){$r.Wear}else{$null};Temperature=if($r){$r.Temperature}else{$null};PowerOnHours=if($r){$r.PowerOnHours}else{$null};SmartAvailable=[bool]($null -ne $r -and ($null -ne $r.Temperature -or $null -ne $r.Wear));UnavailableReason=$e}});[pscustomobject]@{Battery=$bat;Disks=$disks}|ConvertTo-Json -Depth 4 -Compress";
        let (mut pct, mut ac, mut disks) = (None, None, Vec::new());
        let args = ["-NoProfile", "-NonInteractive", "-Command", ps];
        let out = run_stdout("powershell", &args);
        if let Some(v) = out.and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
            pct = j_f64(&v, "/Battery/0/EstimatedChargeRemaining");
            ac = j_u64(&v, "/Battery/0/BatteryStatus").map(|s| !matches!(s, 1 | 4 | 5));
            let dv = v.get("Disks").map(ToString::to_string);
            let ok = dv.and_then(|s| parse_windows_disks_json(&s).ok());
            disks = ok.unwrap_or_default();
        }
        let tmp = std::env::temp_dir().join(format!("dcm-bat-{}.xml", std::process::id()));
        let ts = tmp.to_string_lossy();
        let _ = run_stdout("powercfg", &["/batteryreport", "/xml", "/output", &ts]);
        let xml = std::fs::read_to_string(&tmp).unwrap_or_default();
        let _ = std::fs::remove_file(&tmp);
        let miss = disks.iter().any(|d| !d.smart_available);
        let r = na_if(miss, "SMART counters require admin");
        (parse_windows_battery_xml(&xml, pct, ac), disks, r)
    }
    #[cfg(target_os = "macos")]
    {
        let sp = run_stdout("system_profiler", &["SPPowerDataType", "SPNVMeDataType"]);
        let io = run_stdout("ioreg", &["-rn", "AppleSmartBattery", "-a"]);
        let (bat, mut disks) = parse_macos_power_output(&sp.unwrap_or_default(), io.as_deref());
        if let Some(mut sd) = run_smart("disk0", 0) {
            if let Some(d0) = disks.first_mut() {
                sd.model = d0.model.take().or(sd.model);
                sd.size_bytes = d0.size_bytes.or(sd.size_bytes);
                *d0 = sd;
            } else {
                disks.push(sd);
            }
        }
        let r = na_if(disks.is_empty(), "SMART disk inventory unavailable");
        (bat, disks, r)
    }
    #[cfg(target_os = "linux")]
    {
        let rd = |p| std::fs::read_dir(p).into_iter().flatten().flatten();
        let (mut ac, mut bat_dir, mut disks) = (None, None, Vec::new());
        for e in rd("/sys/class/power_supply") {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("AC") || n.starts_with("ADP") || n.starts_with("Mains") {
                ac = read_str(&e.path(), "online").map(|v| v == "1");
            } else if n.starts_with("BAT") && bat_dir.is_none() {
                bat_dir = Some(e.path());
            }
        }
        let bd = bat_dir.as_deref().unwrap_or(Path::new(""));
        let bat = parse_linux_power_supply(bd, ac);
        for (idx, e) in rd("/sys/class/nvme").enumerate() {
            let (model, state) = (read_str(&e.path(), "model"), read_str(&e.path(), "state"));
            let dev = format!("/dev/{}n1", e.file_name().to_string_lossy());
            let mut fb = nvme_disk(idx, model.as_deref(), Some("smartctl needs root"));
            fb.health_status = state.map(|s| if s == "live" { "Healthy".into() } else { s });
            disks.push(run_smart(&dev, idx).unwrap_or(fb));
        }
        let r = na_if(disks.is_empty(), "No /sys/class/nvme or smartctl access");
        (bat, disks, r)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let r = Some("Unsupported OS".into());
        (bat_na("Unsupported OS"), Vec::new(), r)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fx(r: &str) -> String {
        std::fs::read_to_string(format!("tests/fixtures/health/{r}")).unwrap()
    }
    fn js<T: Serialize>(v: &T) -> String {
        serde_json::to_string(v).unwrap()
    }
    #[test]
    fn test_cross_os_parsers_and_guardrails() {
        let bat = parse_windows_battery_xml(&fx("windows_battery.xml"), Some(82.0), Some(false));
        assert!(bat.health_percent == Some(86.0) && bat.cycle_count == Some(215));
        assert!(!js(&bat).contains("REDACTED-WIN-BAT-SERIAL"));
        let disks = parse_windows_disks_json(&fx("windows_disks.json")).unwrap();
        assert!(disks.len() == 2 && disks[0].smart_available && !disks[1].smart_available);
        assert!(!js(&disks).contains("REDACTED-WIN-DISK-SN") && !js(&disks).contains("eui.000"));
        let one = parse_windows_disks_json(r#"{"FriendlyName":"X","SerialNumber":"SEC"}"#).unwrap();
        assert!(one.len() == 1 && !js(&one).contains("SEC"));
        let (mbat, mdisks) = parse_macos_power_output(&fx("macos_power.txt"), None);
        assert!(mbat.health_percent == Some(91.0) && mbat.cycle_count == Some(142));
        assert!(mdisks.len() == 1 && !js(&(&mbat, &mdisks)).contains("REDACTED-MAC"));
        let io = "<key>AppleSmartBattery</key><key>Raw</key><integer>9</integer>";
        assert!(parse_macos_power_output("", Some(io))
            .0
            .health_percent
            .is_none());
        let lbat = parse_linux_power_supply(Path::new("tests/fixtures/health/linux_bat0"), None);
        assert!(lbat.health_percent == Some(97.0) && !js(&lbat).contains("REDACTED-LINUX-BAT-SN"));
        let sd = parse_smartctl_json(&fx("smartctl_nvme.json"), 0).unwrap();
        assert!(sd.wear_percent == Some(6.0) && !js(&sd).contains("REDACTED-SMARTCTL-SN"));
        let mut gb = bat_na("desktop");
        assert!(compute_agent_guardrails(&gb, &[], Some(45.0)).io_safety_level == "green");
        (gb.present, gb.ac_power, gb.charge_percent) = (true, Some(false), Some(10.0));
        let crit = compute_agent_guardrails(&gb, &[], Some(4.0));
        assert!(crit.io_safety_level == "critical" && crit.avoid_heavy_disk_hash);
        assert!(crit.minimize_write_churn);
        let live = get_hardware_health().agent_guardrails.io_safety_level;
        assert!(["green", "caution", "critical"].contains(&live.as_str()));
    }
}
