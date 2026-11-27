//! Cross-platform orphaned application leftover scanner (`safe_leftovers` vs `user_data`).

use crate::engine::{CustomCandidate, ScanEngine};
use crate::safety;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

const VENDOR_IGNORE_CSV: &str = "microsoft|windows|apple|google|mozilla|nvidia|amd|intel|realtek|\
freedesktop|systemd|gnome|kde|gtk|qt|fontconfig|mesa|pulse|pipewire|dconf|ibus|fcitx|cargo|rustup|\
npm|pnpm|yarn|bun|pip|uv|poetry|git|ssh|gnupg|docker|kubernetes|python|node|go|gradle|maven|nuget|\
openmausbot|claude|anthropic|cursor|opencode|antigravity|windsurf|code|vscode|packages|programs|\
temp|caches|cache|logs|crashdumps|crashreports|savedapplicationstate|preferences|\
applicationsupport|containers|groupcontainers|d3dscache|connecteddevicesplatform|comms|publishers|\
chromium|bravesoftware|brave|vivaldi|opera|operasoftware|arc";
const SKIP_WORDS_CSV: &str =
    "com|org|net|app|apps|inc|corp|ltd|desktop|client|cache|caches|logs|crash|savedstate";
const SAFE_ROOTS_CSV: &str =
    "cache|caches|.cache|logs|log|crashdumps|crashreports|diagnosticreports|saved application state";

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LeftoversParams {
    pub min_age_days: Option<u64>,
    pub custom_scan_roots: Option<Vec<String>>,
    #[serde(default, alias = "installed_hints", alias = "installed_Hints")]
    pub installed_hints: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LeftoverItem {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size_bytes: u64,
    pub age_days: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<i64>,
    pub category: String,
    pub verdict: String,
    pub risk_level: String,
    pub approval_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LeftoversReport {
    pub scan_id: String,
    pub duration_ms: u64,
    pub min_age_days: u64,
    pub installed_apps_count: usize,
    pub total_safe_leftover_bytes: u64,
    pub total_user_data_bytes: u64,
    pub safe_leftovers: Vec<LeftoverItem>,
    pub user_data: Vec<LeftoverItem>,
    pub warnings: Vec<String>,
}

struct ScanCtx {
    min_age: u64,
    now: i64,
    ignore: HashSet<&'static str>,
    installed: HashSet<String>,
}

#[allow(dead_code)]
pub fn scan_app_leftovers(engine: &ScanEngine, params: &LeftoversParams) -> LeftoversReport {
    let started = Instant::now();
    let mut warnings = Vec::new();
    let roots = resolve_roots(params, &mut warnings);
    let now_dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ctx = ScanCtx {
        min_age: params.min_age_days.unwrap_or(30),
        now: now_dur.as_secs() as i64,
        ignore: VENDOR_IGNORE_CSV.split('|').collect(),
        installed: build_installed_set(params),
    };

    let (mut seen, mut cands) = (BTreeSet::new(), Vec::new());
    let (mut safe_v, mut data_v) = (Vec::new(), Vec::new());
    for (root, root_safe) in &roots {
        for p in dir_paths(root) {
            if let Some((c, it, safe)) = eval_dir(&p, *root_safe, &ctx, &mut seen) {
                cands.push(c);
                if safe { &mut safe_v } else { &mut data_v }.push(it);
            }
        }
    }
    safe_v.sort_by_key(|b| std::cmp::Reverse(b.size_bytes));
    data_v.sort_by_key(|b| std::cmp::Reverse(b.size_bytes));

    let dur = started.elapsed().as_millis() as u64;
    let warn_c = warnings.clone();
    let sess = engine.register_custom_session("app_leftovers", cands, warn_c, dur, true);
    let tmap: HashMap<&str, _> = sess.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let sync = |v: &mut [LeftoverItem]| -> u64 {
        v.iter_mut().fold(0u64, |acc, it| {
            if let Some(e) = tmap.get(it.path.as_str()) {
                it.approval_token.clone_from(&e.approval_token);
                it.verdict.clone_from(&e.verdict);
                it.risk_level.clone_from(&e.risk_level);
            }
            acc.saturating_add(it.size_bytes)
        })
    };
    let (safe_bytes, data_bytes) = (sync(&mut safe_v), sync(&mut data_v));
    LeftoversReport {
        scan_id: sess.scan_id.clone(),
        duration_ms: dur,
        min_age_days: ctx.min_age,
        installed_apps_count: ctx.installed.len(),
        total_safe_leftover_bytes: safe_bytes,
        total_user_data_bytes: data_bytes,
        safe_leftovers: safe_v,
        user_data: data_v,
        warnings,
    }
}

fn resolve_roots(params: &LeftoversParams, warnings: &mut Vec<String>) -> Vec<(PathBuf, bool)> {
    let Some(custom) = &params.custom_scan_roots else {
        return default_roots();
    };
    let mut out = Vec::new();
    for raw in custom {
        let pb = PathBuf::from(raw.trim());
        if is_safe_dir(&pb) {
            let fnm = pb.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let low = fnm.to_ascii_lowercase();
            out.push((pb, SAFE_ROOTS_CSV.split('|').any(|x| x == low)));
        } else {
            warnings.push(format!("Skipped unsafe or missing custom scan root: {raw}"));
        }
    }
    out
}

fn build_installed_set(params: &LeftoversParams) -> HashSet<String> {
    let mut set = if params.custom_scan_roots.is_some() && params.installed_hints.is_some() {
        HashSet::new()
    } else {
        let mut s = collect_installed_inventory();
        if let Ok(mut sys) = System::new() {
            sys.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::nothing(),
            );
            for p in sys.processes().values() {
                let n = p.name().to_string_lossy();
                add_tokens(&mut s, n.strip_suffix(".exe").unwrap_or(&n));
            }
        }
        s
    };
    for h in params.installed_hints.as_deref().unwrap_or_default() {
        add_tokens(&mut set, h);
    }
    set
}

type EvalOut = (CustomCandidate, LeftoverItem, bool);

fn eval_dir(
    p: &Path,
    safe_rt: bool,
    ctx: &ScanCtx,
    seen: &mut BTreeSet<PathBuf>,
) -> Option<EvalOut> {
    (!safety::is_protected(p) && is_safe_dir(p)).then_some(())?;
    let name = p.file_name()?.to_str()?.to_string();
    let skip = name.starts_with('.')
        || is_ignored(&name, &ctx.ignore)
        || is_installed(&name, &ctx.installed);
    (!skip && seen.insert(safety::normalize(p))).then_some(())?;
    let (size, mtime) = measure_dir(p);
    let age_days = mtime.map_or(0, |m| (ctx.now.saturating_sub(m).max(0) as u64) / 86_400);
    (size > 0 && age_days >= ctx.min_age).then_some(())?;

    let kind = classify_kind(&name, safe_rt);
    let safe = kind != "app_data";
    let (verd, sc, rk) = match safe {
        true => ("review", 40, "caution"),
        false => ("keep", 75, "dangerous"),
    };
    let cand = CustomCandidate {
        kind: "dir".into(),
        path: p.to_path_buf(),
        size,
        modified: mtime,
        category: "app_leftover".into(),
        verdict: verd.into(),
        importance_score: sc,
        risk_level: rk.into(),
        reasons: vec![format!("Orphaned {kind} for '{name}' ({age_days}d old)")],
    };
    let item = LeftoverItem {
        name,
        path: p.to_string_lossy().into_owned(),
        kind,
        size_bytes: size,
        age_days,
        modified: mtime,
        category: "app_leftover".into(),
        verdict: verd.into(),
        risk_level: rk.into(),
        approval_token: String::new(),
    };
    Some((cand, item, safe))
}

fn default_roots() -> Vec<(PathBuf, bool)> {
    let mut r = Vec::new();
    if cfg!(windows) {
        if let Some(ld) = dirs::data_local_dir() {
            r.extend([(ld.join("CrashDumps"), true), (ld, false)]);
        }
        r.extend(dirs::data_dir().map(|rd| (rd, false)));
    } else if cfg!(target_os = "macos") {
        if let Some(h) = dirs::home_dir() {
            for s in [
                "Library/Caches",
                "Library/Logs",
                "Library/Saved Application State",
            ] {
                r.push((h.join(s), true));
            }
            r.push((h.join("Library/Application Support"), false));
        }
    } else if let Some(h) = dirs::home_dir() {
        r.push((dirs::cache_dir().unwrap_or_else(|| h.join(".cache")), true));
        r.push((
            dirs::config_dir().unwrap_or_else(|| h.join(".config")),
            false,
        ));
        r.push((
            dirs::data_dir().unwrap_or_else(|| h.join(".local/share")),
            false,
        ));
        r.push((h.join(".var/app"), false));
    }
    r.into_iter().filter(|(p, _)| is_safe_dir(p)).collect()
}

fn classify_kind(name: &str, parent_safe: bool) -> String {
    let l = name.to_ascii_lowercase();
    if l.ends_with(".savedstate") || l.contains("saved state") {
        "saved_state".into()
    } else if l.contains("crash") {
        "crash_reports".into()
    } else if l.ends_with("logs") || l.ends_with("-log") || l.ends_with("_log") || l == "logs" {
        "logs".into()
    } else if parent_safe || l.contains("cache") {
        "cache".into()
    } else {
        "app_data".into()
    }
}

fn normalize_token(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn add_tokens(set: &mut HashSet<String>, raw: &str) {
    let full = normalize_token(raw.trim());
    if full.len() >= 3 {
        set.insert(full);
    }
    for t in raw
        .split(|c: char| !c.is_ascii_alphanumeric())
        .map(normalize_token)
    {
        if t.len() >= 4 && !SKIP_WORDS_CSV.split('|').any(|w| w == t) {
            set.insert(t);
        }
    }
}

fn is_ignored(name: &str, ignore: &HashSet<&str>) -> bool {
    let low = name.to_ascii_lowercase();
    let mut parts = name.split(|c: char| !c.is_ascii_alphanumeric());
    let tok_ign = parts.any(|p| {
        let s = normalize_token(p);
        s.len() >= 3 && ignore.contains(s.as_str())
    });
    low.starts_with("com.apple.")
        || low.starts_with("com.microsoft.")
        || ignore.contains(normalize_token(name).as_str())
        || tok_ign
}

fn is_installed(name: &str, installed: &HashSet<String>) -> bool {
    let full = normalize_token(name);
    if full.len() < 3 {
        return true;
    }
    let sfx = ["savedstate", "caches", "cache", "logs"];
    let base = sfx
        .iter()
        .find_map(|s| full.strip_suffix(s))
        .unwrap_or(&full);
    let mut parts = name.split(|c: char| !c.is_ascii_alphanumeric());
    let tok_hit = parts.any(|p| {
        let t = normalize_token(p);
        t.len() >= 4 && !SKIP_WORDS_CSV.split('|').any(|w| w == t) && installed.contains(&t)
    });
    installed.contains(&full) || (base.len() >= 3 && installed.contains(base)) || tok_hit
}

fn collect_installed_inventory() -> HashSet<String> {
    let (mut set, mut dv) = (HashSet::new(), Vec::new());
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
        use winreg::RegKey;
        let u1 = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        let u2 = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
        let u3 = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
        for (h, sub) in [
            (HKEY_LOCAL_MACHINE, u1),
            (HKEY_LOCAL_MACHINE, u2),
            (HKEY_CURRENT_USER, u3),
        ] {
            if let Ok(k) = RegKey::predef(h).open_subkey_with_flags(sub, KEY_READ) {
                for skn in k.enum_keys().flatten() {
                    add_tokens(&mut set, &skn);
                    if let Ok(sk) = k.open_subkey_with_flags(&skn, KEY_READ) {
                        for vn in ["DisplayName", "Publisher", "InstallLocation"] {
                            if let Ok(v) = sk.get_value::<String, _>(vn) {
                                add_tokens(&mut set, &v);
                            }
                        }
                    }
                }
            }
        }
        dv.extend([
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)"),
        ]);
        if let Some(ld) = dirs::data_local_dir() {
            dv.extend([ld.join("Programs"), ld.join("Packages")]);
        }
    }
    #[cfg(target_os = "macos")]
    {
        dv.extend([
            PathBuf::from("/Applications"),
            PathBuf::from("/System/Applications"),
        ]);
        dv.extend(dirs::home_dir().map(|h| h.join("Applications")));
    }
    #[cfg(target_os = "linux")]
    {
        for s in ["/usr/share/applications", "/var/lib/flatpak/app", "/snap"] {
            dv.push(PathBuf::from(s));
        }
        if let Some(h) = dirs::home_dir() {
            dv.extend([
                h.join(".local/share/applications"),
                h.join(".local/share/flatpak/app"),
            ]);
        }
    }
    for p in dv.iter().flat_map(dir_paths) {
        if let Some(s) = p.file_stem().and_then(|x| x.to_str()) {
            add_tokens(&mut set, s);
        }
        #[cfg(target_os = "macos")]
        if let Ok(xml) = fs::read_to_string(p.join("Contents/Info.plist")) {
            for k in ["CFBundleIdentifier", "CFBundleName"] {
                if let Some(a) = xml.split(&format!("<key>{k}</key>")).nth(1) {
                    if let Some(v) = a
                        .split("<string>")
                        .nth(1)
                        .and_then(|b| b.split("</string>").next())
                    {
                        add_tokens(&mut set, v.trim());
                    }
                }
            }
        }
        #[cfg(target_os = "linux")]
        if p.extension().is_some_and(|x| x == "desktop") {
            for l in fs::read_to_string(&p).unwrap_or_default().lines() {
                if let Some(v) = l.strip_prefix("Name=").or_else(|| l.strip_prefix("Exec=")) {
                    add_tokens(&mut set, v.split_whitespace().next().unwrap_or(v));
                }
            }
        }
    }
    set
}

fn dir_paths(d: impl AsRef<Path>) -> Vec<PathBuf> {
    let rd = fs::read_dir(d).into_iter().flatten();
    rd.flatten().map(|e| e.path()).collect()
}

fn is_safe_dir(p: &Path) -> bool {
    !p.components().any(|c| matches!(c, Component::ParentDir))
        && safety::sensitive_never_touch_reason(p).is_none()
        && fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() && !is_reparse_or_link(&m))
}

fn is_reparse_or_link(m: &fs::Metadata) -> bool {
    #[cfg(windows)]
    if std::os::windows::fs::MetadataExt::file_attributes(m) & 0x400 != 0 {
        return true;
    }
    m.file_type().is_symlink()
}

fn measure_dir(root: &Path) -> (u64, Option<i64>) {
    let mt = |m: &fs::Metadata| {
        let d = m.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
        Some(d.as_secs() as i64)
    };
    let mut total = 0u64;
    let mut latest = fs::symlink_metadata(root).ok().and_then(|m| mt(&m));
    let walker = jwalk::WalkDir::new(root)
        .follow_links(false)
        .process_read_dir(|_, _, _, ch| {
            ch.retain(|r| {
                r.as_ref().is_ok_and(|e| {
                    let p = e.path();
                    let ok_nt = safety::sensitive_never_touch_reason(&p).is_none();
                    ok_nt && fs::symlink_metadata(&p).is_ok_and(|m| !is_reparse_or_link(&m))
                })
            });
        });
    for e in walker.into_iter().flatten() {
        if let Ok(m) = fs::symlink_metadata(e.path()) {
            if !is_reparse_or_link(&m) {
                latest = mt(&m).map_or(latest, |s| Some(latest.map_or(s, |p| p.max(s))));
                total += if m.is_file() { m.len() } else { 0 };
            }
        }
    }
    (total, latest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leftovers_tiering_vendor_ignore_and_installed_skip() {
        let tmp = std::env::temp_dir().join(format!("dcm-leftovers-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let mk = |rel: &str, b: &[u8]| {
            let f = tmp.join(rel);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, b).unwrap();
        };
        mk("Caches/com.phantomvideo.player/blob.bin", &[1u8; 1024]);
        mk("Roaming/PhantomVideo/settings.json", b"{}");
        mk("Caches/SuperNote/index.db", b"active");
        mk("Roaming/Microsoft/state.dat", b"sys");

        let eng = ScanEngine::new();
        let (c_s, r_s) = (
            tmp.join("Caches").to_string_lossy().into(),
            tmp.join("Roaming").to_string_lossy().into(),
        );
        let mut p = LeftoversParams {
            min_age_days: Some(0),
            custom_scan_roots: Some(vec![c_s, r_s]),
            installed_hints: Some(vec!["SuperNote Desktop".into()]),
        };
        let rep = scan_app_leftovers(&eng, &p);
        assert_eq!((rep.safe_leftovers.len(), rep.user_data.len()), (1, 1));
        assert!(rep.safe_leftovers[0].verdict == "review" && rep.user_data[0].verdict == "keep");
        p.min_age_days = Some(30);
        assert!(scan_app_leftovers(&eng, &p).safe_leftovers.is_empty());
        let _ = fs::remove_dir_all(&tmp);
    }
}
