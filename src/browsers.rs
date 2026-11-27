//! Cross-platform per-browser & per-profile cache, on-device AI model, and
//! opt-in website storage scanner (10 Chromium browsers + Firefox).

use crate::engine::{CustomCandidate, ScanEngine};
use crate::leveldb_ro as ldb;
use crate::safety;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf as Pb};
use std::time::{Instant, UNIX_EPOCH};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const CHROMIUM_CSV: &str = "Cache|Code Cache|GPUCache|ShaderCache|GrShaderCache|\
GraphiteDawnCache|DawnCache|DawnGraphiteCache|DawnWebGPUCache";
const SHADERS_CSV: &str = "ShaderCache|GrShaderCache|GraphiteDawnCache";
const FF_CSV: &str = "cache2|startupCache|shader-cache";
const FF_SKIP_CSV: &str = "crash reports|pending pings|profile groups";
const AI_MODELS_CSV: &str = "OptGuideOnDeviceModel|OptGuideOnDeviceClassifierModel|\
OptGuidePredictionModels|optimization_guide_model_store|OnDeviceHeadSuggestModel|screen_ai|SODA|\
SODALanguagePacks|AutofillAiModelCache";
const NEVER_TOUCH_CSV: &str = "cookies|cookies-journal|login data|login data-journal|\
login data for account|web data|web data-journal|history|history-journal|bookmarks|bookmarks.bak|\
favicons|favicons-journal|local storage|session storage|extensions|preferences|\
secure preferences|local state|key4.db|logins.json|places.sqlite|cookies.sqlite";

const BROWSER_TABLE: &[&str] = &[
    "Chrome|c|chrome,chrome.exe,google chrome|Google/Chrome/User Data||Google/Chrome|Google/Chrome|google-chrome|google-chrome",
    "Chrome Beta|c|google chrome beta,chrome-beta|Google/Chrome Beta/User Data||Google/Chrome Beta|Google/Chrome Beta|google-chrome-beta|google-chrome-beta",
    "Chrome Canary|c|google chrome canary,chrome-canary|Google/Chrome SxS/User Data||Google/Chrome Canary|Google/Chrome Canary|google-chrome-unstable|google-chrome-unstable",
    "Edge|c|msedge,msedge.exe,microsoft edge,microsoft-edge|Microsoft/Edge/User Data||Microsoft Edge|Microsoft Edge|microsoft-edge|microsoft-edge",
    "Brave|c|brave,brave.exe,brave browser,brave-browser|BraveSoftware/Brave-Browser/User Data||BraveSoftware/Brave-Browser|BraveSoftware/Brave-Browser|BraveSoftware/Brave-Browser|BraveSoftware/Brave-Browser",
    "Arc|c|arc,arc.exe|Arc/User Data||Arc/User Data|company.thebrowser.Browser|arc|arc",
    "Vivaldi|c|vivaldi,vivaldi.exe,vivaldi-bin|Vivaldi/User Data||Vivaldi|Vivaldi|vivaldi|vivaldi",
    "Opera|c|opera,opera.exe|Opera Software/Opera Stable|Opera Software/Opera Stable|com.operasoftware.Opera|com.operasoftware.Opera|opera|opera",
    "Opera GX|c|opera,opera.exe|Opera Software/Opera GX Stable|Opera Software/Opera GX Stable|com.operasoftware.OperaGX|com.operasoftware.OperaGX|opera-gx|opera-gx",
    "Chromium|c|chromium,chromium.exe,chromium-browser|Chromium/User Data||Chromium|Chromium|chromium|chromium",
    "Firefox|f|firefox,firefox.exe,firefox-bin|Mozilla/Firefox/Profiles|Mozilla/Firefox/Profiles|Firefox/Profiles|Firefox/Profiles|.mozilla/firefox|mozilla/firefox",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BrowserScanParams {
    pub browsers: Option<Vec<String>>,
    pub include_origins: Option<bool>,
    pub custom_browser_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BrowserAudit {
    pub browser: String,
    pub running: bool,
    pub profiles_detected: Vec<String>,
    pub disposable_cache_bytes: u64,
    pub ai_models_bytes: u64,
    pub website_storage_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BrowserItem {
    pub browser: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub group: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_kind: Option<String>,
    pub path: String,
    pub size_bytes: u64,
    pub running: bool,
    pub category: String,
    pub verdict: String,
    pub risk_level: String,
    pub approval_token: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BrowserScanReport {
    pub scan_id: String,
    pub duration_ms: u64,
    pub include_origins: bool,
    pub total_reclaimable_bytes: u64,
    pub total_review_bytes: u64,
    pub total_blocked_bytes: u64,
    pub browsers: Vec<BrowserAudit>,
    pub disposable_cache: Vec<BrowserItem>,
    pub ai_models: Vec<BrowserItem>,
    pub website_storage: Vec<BrowserItem>,
    pub warnings: Vec<String>,
}

type HitMeta<'a> = (&'a str, Option<&'a str>, &'a str, &'a str);
type Orig<'a> = Option<(&'a str, &'a str)>;
type RunOv<'a> = Option<&'a HashSet<String>>;

#[derive(Default)]
struct ScanAcc {
    seen: BTreeSet<Pb>,
    candidates: Vec<CustomCandidate>,
    items: Vec<BrowserItem>,
}

impl ScanAcc {
    fn csv(&mut self, c: (&str, Option<&str>, bool), g: &str, csv: &str, d: &Path) -> u64 {
        let mut s = 0u64;
        for n in csv.split('|') {
            s += self
                .add((c.0, c.1, g, n), None, &d.join(n), c.2)
                .unwrap_or(0);
        }
        s
    }
    fn site(&mut self, c: (&str, &str, bool), o: &str, k: &str, p: &Path) -> u64 {
        let m = (c.0, Some(c.1), "website_storage", o);
        self.add(m, Some((o, k)), p, c.2).unwrap_or(0)
    }
    fn add(&mut self, m: HitMeta<'_>, orig: Orig<'_>, p: &Path, r: bool) -> Option<u64> {
        let ok = p.is_dir() && is_safe_path(p) && !is_never_touch(p);
        (ok && self.seen.insert(safety::normalize(p))).then_some(())?;
        let (size, modified) = dir_size_safe(p);
        (size > 0).then_some(())?;
        let (b, prof, grp, nm) = m;
        let cat = match grp {
            "ai_models" => "browser_ai_model",
            "website_storage" => "browser_site_data",
            _ => "browser_cache",
        };
        let (verd, sc, rk) = match (grp, r) {
            (_, true) => ("blocked", 100, "blocked"),
            ("ai_models", _) => ("review", 45, "caution"),
            ("website_storage", _) => ("review", 55, "caution"),
            _ => ("safe_to_delete", 10, "safe"),
        };
        self.candidates.push(CustomCandidate {
            kind: "dir".into(),
            path: p.to_path_buf(),
            size,
            modified,
            category: cat.into(),
            verdict: verd.into(),
            importance_score: sc,
            risk_level: rk.into(),
            reasons: vec![format!("{b} {grp} ({nm})")],
        });
        self.items.push(BrowserItem {
            browser: b.into(),
            profile: prof.map(Into::into),
            group: grp.into(),
            name: nm.into(),
            origin: orig.map(|(o, _)| o.into()),
            storage_kind: orig.map(|(_, k)| k.into()),
            path: p.to_string_lossy().into_owned(),
            size_bytes: size,
            running: r,
            category: cat.into(),
            verdict: verd.into(),
            risk_level: rk.into(),
            approval_token: String::new(),
        });
        Some(size)
    }
}

#[allow(dead_code)]
pub fn scan_browsers(engine: &ScanEngine, params: &BrowserScanParams) -> BrowserScanReport {
    scan_inner(engine, params, None)
}

fn scan_inner(eng: &ScanEngine, p: &BrowserScanParams, ov: RunOv<'_>) -> BrowserScanReport {
    let (started, inc_orig) = (Instant::now(), p.include_origins.unwrap_or(false));
    let (mut warnings, mut c_root) = (Vec::new(), None);
    let raw_rt = p.custom_browser_root.as_deref().unwrap_or("").trim();
    if !raw_rt.is_empty() {
        match is_safe_path(Path::new(raw_rt)) {
            true => c_root = Some(Pb::from(raw_rt)),
            false => warnings.push(format!("Rejected unsafe customBrowserRoot: {raw_rt}")),
        }
    }

    let (mut acc, mut audits) = (ScanAcc::default(), Vec::new());
    let parse_row = |&l: &&'static str| l.split('|').collect::<Vec<_>>().try_into().ok();
    let mut rows: Vec<[&str; 9]> = BROWSER_TABLE.iter().filter_map(parse_row).collect();
    if !warnings.is_empty() {
        rows.clear();
    }
    let live = if rows.is_empty() {
        HashSet::new()
    } else {
        detect_running(&rows, c_root.as_deref())
    };
    let run_set = ov.unwrap_or(&live);
    let raw_flt = p.browsers.iter().flatten();
    let mut flt: Vec<_> = raw_flt.map(|s| s.trim().to_ascii_lowercase()).collect();
    flt.retain(|s| !s.is_empty());

    for r in &rows {
        let (bn, is_ff, low_b) = (r[0], r[1] == "f", r[0].to_ascii_lowercase());
        if !flt.is_empty() && !flt.contains(&low_b) {
            continue;
        }
        let run = run_set.contains(&low_b);
        let c_csv = if is_ff { FF_CSV } else { CHROMIUM_CSV };
        let (mut profs, mut cb, mut mb, mut ob) = (BTreeSet::new(), 0u64, 0u64, 0u64);
        for root in resolve_roots(r, c_root.as_deref()) {
            if !is_ff {
                mb += acc.csv((bn, None, run), "ai_models", AI_MODELS_CSV, &root);
                cb += acc.csv((bn, None, run), "disposable_cache", SHADERS_CSV, &root);
            }
            for (pn, pd) in discover_profiles(bn, is_ff, &root) {
                profs.insert(pn.clone());
                let ctx = (bn, Some(pn.as_str()), run);
                cb += acc.csv(ctx, "disposable_cache", c_csv, &pd);
                if !is_ff {
                    mb += acc.csv(ctx, "ai_models", AI_MODELS_CSV, &pd);
                }
                if inc_orig {
                    ob += scan_origins(&mut acc, (bn, &pn, run), is_ff, &pd);
                }
            }
        }
        if !profs.is_empty() || cb > 0 || mb > 0 {
            audits.push(BrowserAudit {
                browser: bn.into(),
                running: run,
                profiles_detected: profs.into_iter().collect(),
                disposable_cache_bytes: cb,
                ai_models_bytes: mb,
                website_storage_bytes: ob,
            });
        }
    }

    let (ms, warn_c) = (started.elapsed().as_millis() as u64, warnings.clone());
    let sess = eng.register_custom_session("browsers", acc.candidates, warn_c, ms, !inc_orig);
    let tmap: HashMap<&str, _> = sess.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let (mut reclaimable, mut review, mut blocked) = (0u64, 0u64, 0u64);
    let (mut cache_v, mut model_v, mut origin_v) = (Vec::new(), Vec::new(), Vec::new());
    for mut it in acc.items {
        if let Some(e) = tmap.get(it.path.as_str()) {
            it.approval_token.clone_from(&e.approval_token);
            it.verdict.clone_from(&e.verdict);
            it.risk_level.clone_from(&e.risk_level);
        }
        match it.verdict.as_str() {
            "safe_to_delete" => reclaimable += it.size_bytes,
            "blocked" => blocked += it.size_bytes,
            _ => review += it.size_bytes,
        }
        match it.group.as_str() {
            "disposable_cache" => cache_v.push(it),
            "ai_models" => model_v.push(it),
            _ => origin_v.push(it),
        }
    }
    BrowserScanReport {
        scan_id: sess.scan_id.clone(),
        duration_ms: ms,
        include_origins: inc_orig,
        total_reclaimable_bytes: reclaimable,
        total_review_bytes: review,
        total_blocked_bytes: blocked,
        browsers: audits,
        disposable_cache: cache_v,
        ai_models: model_v,
        website_storage: origin_v,
        warnings,
    }
}

fn resolve_roots(r: &[&str; 9], custom_root: Option<&Path>) -> Vec<Pb> {
    let mut raw = Vec::new();
    if let Some(b) = custom_root {
        let bd = b.join(r[0]);
        raw.extend([b.join(r[3]), bd.join("User Data"), bd.join("Profiles"), bd]);
        raw.extend((!r[4].is_empty()).then(|| b.join(r[4])));
    } else if cfg!(windows) {
        raw.extend(dirs::data_local_dir().map(|d| d.join(r[3])));
        if !r[4].is_empty() {
            raw.extend(dirs::data_dir().map(|d| d.join(r[4])));
        }
    } else if cfg!(target_os = "macos") {
        if let Some(h) = dirs::home_dir() {
            raw.push(h.join("Library/Application Support").join(r[5]));
            raw.push(h.join("Library/Caches").join(r[6]));
        }
    } else if let Some(h) = dirs::home_dir() {
        let cfg = dirs::config_dir().unwrap_or_else(|| h.join(".config"));
        let ch = dirs::cache_dir().unwrap_or_else(|| h.join(".cache"));
        let base = if r[7].starts_with('.') { &h } else { &cfg };
        raw.extend([base.join(r[7]), ch.join(r[8])]);
    }
    let mut seen = BTreeSet::new();
    let ok = |p: &Pb| p.is_dir() && is_safe_path(p) && seen.insert(safety::normalize(p));
    raw.into_iter().filter(ok).collect()
}

fn safe_subdirs(dir: impl AsRef<Path>) -> Vec<(String, Pb)> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() && is_safe_path(&p) && !is_never_touch(&p) {
            let nm = p.file_name().and_then(|n| n.to_str()).map(String::from);
            out.extend(nm.map(|s| (s, p)));
        }
    }
    out
}

fn discover_profiles(bname: &str, is_ff: bool, root: &Path) -> Vec<(String, Pb)> {
    let is_num = |d: &str| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit());
    let mut out = safe_subdirs(root);
    out.retain(|(n, p)| match is_ff {
        true => {
            let skip = FF_SKIP_CSV.split('|').any(|s| n.eq_ignore_ascii_case(s));
            !skip && (n.contains('.') || p.join("cache2").is_dir() || p.join("storage").is_dir())
        }
        false => {
            matches!(n.as_str(), "Default" | "Profile" | "Guest Profile")
                || n.strip_prefix("Profile ").is_some_and(is_num)
        }
    });
    if !is_ff && out.is_empty() && (bname.starts_with("Opera") || root.join("GPUCache").is_dir()) {
        out.push(("Default".into(), root.to_path_buf()));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn detect_running(rows: &[[&str; 9]], custom_root: Option<&Path>) -> HashSet<String> {
    let (mut running, mut sys) = (HashSet::new(), System::new());
    let rk = ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet);
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, rk);
    let c_norm = custom_root.map(safety::normalize);
    for proc in sys.processes().values() {
        let ex = proc.exe();
        let in_root = |cr: &Pb| ex.is_some_and(|x| safety::normalize(x).starts_with(cr));
        if c_norm.as_ref().is_some_and(|cr| !in_root(cr)) {
            continue;
        }
        let pname = proc.name().to_string_lossy().to_ascii_lowercase();
        let ex_s = ex.map(|x| x.to_string_lossy().to_ascii_lowercase());
        let exe = ex_s.unwrap_or_default().replace('\\', "/");
        for r in rows.iter().filter(|r| r[2].split(',').any(|x| x == pname)) {
            let b = exe.contains("chrome beta") || exe.contains("chrome-beta");
            let c = exe.contains("chrome sxs") || exe.contains("chrome canary");
            let ch1 = (r[0] != "Chrome Beta" || b) && (r[0] != "Chrome Canary" || c);
            let ch_ok = ch1 && (r[0] != "Chrome" || (!b && !c));
            let op_ok =
                !pname.starts_with("opera") || (r[0] == "Opera GX") == exe.contains("opera gx");
            if exe.is_empty() || ((!pname.starts_with("chrome") || ch_ok) && op_ok) {
                running.insert(r[0].to_ascii_lowercase());
            }
        }
    }
    running
}

fn scan_origins(acc: &mut ScanAcc, ctx: (&str, &str, bool), is_ff: bool, pdir: &Path) -> u64 {
    let mut bytes = 0u64;
    if is_ff {
        for (nm, p) in safe_subdirs(pdir.join("storage/default")) {
            if let Some((sc, r)) = nm.to_ascii_lowercase().split_once("+++") {
                let u = format!(
                    "{sc}://{}",
                    r.split('^').next().unwrap_or(r).replace('+', ":")
                );
                if matches!(sc, "http" | "https") {
                    if let Some(orig) = ldb::normalize_web_origin(&u) {
                        bytes += acc.site(ctx, &orig, "indexeddb", &p);
                    }
                }
            }
        }
        return bytes;
    }
    let ext_p = ["chrome-extension_", "moz-extension", "devtools_"];
    for (nm, p) in safe_subdirs(pdir.join("IndexedDB")) {
        let l = nm.to_ascii_lowercase();
        if !ext_p.iter().any(|x| l.starts_with(x)) && l.contains(".indexeddb.") {
            let fb = || ldb::extract_origins_from_leveldb_dir(&p).into_iter().next();
            if let Some(orig) = ldb::parse_idb_origin(&l).or_else(fb) {
                bytes += acc.site(ctx, &orig, "indexeddb", &p);
            }
        }
    }
    for (_, p) in safe_subdirs(pdir.join("Service Worker/CacheStorage")) {
        if let Some(o) = ldb::extract_cs_owner(&p) {
            bytes += acc.site(ctx, &o, "cache_storage", &p);
        }
    }
    let fs_root = pdir.join("File System");
    let origins = ldb::extract_origins_from_leveldb_dir(&fs_root.join("Origins"));
    if let Some(f) = origins.first() {
        let sfx = format!(" (+{} more)", origins.len() - 1);
        let lbl = format!("{f}{}", if origins.len() == 1 { "" } else { &sfx });
        bytes += acc.site(ctx, &lbl, "file_system", &fs_root);
    }
    bytes
}

fn is_safe_path(path: &Path) -> bool {
    !path.components().any(|c| matches!(c, Component::ParentDir))
        && fs::symlink_metadata(path).is_ok_and(|m| is_safe_meta(&m))
}

fn is_safe_meta(m: &fs::Metadata) -> bool {
    #[cfg(windows)]
    if std::os::windows::fs::MetadataExt::file_attributes(m) & 0x400 != 0 {
        return false;
    }
    !m.file_type().is_symlink()
}

fn is_never_touch(path: &Path) -> bool {
    let fnm = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let csv = NEVER_TOUCH_CSV;
    csv.split('|').any(|x| fnm.eq_ignore_ascii_case(x))
        || safety::sensitive_never_touch_reason(path).is_some()
}

fn dir_size_safe(root: &Path) -> (u64, Option<i64>) {
    let keep = |p: &Path| is_safe_path(p) && !is_never_touch(p);
    let (mut total, mut latest) = (0u64, None::<i64>);
    let w = jwalk::WalkDir::new(root).follow_links(false);
    let walker = w.process_read_dir(move |_, _, _, ch| {
        ch.retain(|r| r.as_ref().is_ok_and(|e| keep(&e.path())));
    });
    for e in walker.into_iter().flatten() {
        if let Ok(m) = fs::symlink_metadata(e.path()) {
            if is_safe_meta(&m) {
                let mt = m.modified().ok();
                if let Some(d) = mt.and_then(|t| t.duration_since(UNIX_EPOCH).ok()) {
                    let ts = d.as_secs() as i64;
                    latest = Some(latest.map_or(ts, |p| p.max(ts)));
                }
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
    fn test_browser_groups_never_touch_and_live_process_lock() {
        let tmp = std::env::temp_dir().join(format!("dcm-browsers-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let ud = tmp.join("Google/Chrome/User Data");
        const RELS: &str = "Profile 1/GPUCache/data_0|OptGuideOnDeviceModel/weights.bin|\
Profile 1/Cookies|Profile 1/Login Data|Profile 1/Local Storage/leveldb/01.log|\
Profile 1/IndexedDB/https_example.com_0.indexeddb.leveldb/03.ldb|\
Profile 1/IndexedDB/chrome-extension_a_0.indexeddb.leveldb/03.ldb|\
Profile 1/Service Worker/CacheStorage/h1/index.txt";
        for rel in RELS.split('|') {
            let f = ud.join(rel);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, b"https://docs.rs/tokio ").unwrap();
        }

        let (eng, empty) = (ScanEngine::new(), HashSet::new());
        let mut p = BrowserScanParams {
            browsers: Some(vec!["Chrome".into()]),
            custom_browser_root: Some(tmp.to_string_lossy().into()),
            ..Default::default()
        };
        let r1 = scan_inner(&eng, &p, Some(&empty));
        assert_eq!((r1.disposable_cache.len(), r1.ai_models.len()), (1, 1));
        assert_eq!(r1.disposable_cache[0].verdict, "safe_to_delete");
        let bad = ["cookies", "login data", "local storage"];
        for e in &eng.get_session(&r1.scan_id).unwrap().entries {
            let l = e.path.to_ascii_lowercase();
            assert!(bad.iter().all(|s| !l.contains(s)));
        }
        let live = HashSet::from(["chrome".to_string()]);
        let r_blk = scan_inner(&eng, &p, Some(&live));
        assert_eq!(r_blk.disposable_cache[0].verdict, "blocked");
        assert_eq!(r_blk.ai_models[0].verdict, "blocked");
        p.include_origins = Some(true);
        let r_orig = scan_inner(&eng, &p, Some(&empty));
        assert!(r_orig.website_storage.len() == 2 && r_orig.website_storage[0].origin.is_some());
        p.custom_browser_root = Some(format!("{}/../etc", tmp.to_string_lossy()));
        assert!(!scan_browsers(&eng, &p).warnings.is_empty());
        let _ = fs::remove_dir_all(&tmp);
    }
}
