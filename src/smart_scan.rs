//! Cross-Platform Allowlist Smart Scan + Target Reclaim Planner (`v0.6.0`).

use crate::ai_stack::{
    self, is_symlink_or_junction, mtime_secs, rd_vec, safe_meta, ActiveAiProcesses, RawCleanupUnit,
    Units,
};
use crate::engine::{CustomCandidate, ScanEngine};
use crate::safety;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const BRIEF_MAX_UNITS: usize = 25;
const TEMP_MIN_AGE_SECS: i64 = 86_400;
const TEMP_MIN_BYTES: u64 = 65_536;

/// `"bases|prefix|group|label|category|rel"` (`L`=local, `C`=cache, `H`=home, `R`=roam, `!`=review).
const HOTSPOTS: &[&str] = &[
    "L|crash|os_temp_logs|Windows CrashDumps|crash_dump|CrashDumps",
    "H|logs|os_temp_logs|macOS User Logs|log|Library/Logs",
    "L|d3d|shader_thumb_cache|Direct3D Shader Cache|cache|D3DSCache",
    "L|nv-dx|shader_thumb_cache|NVIDIA DXCache|cache|NVIDIA/DXCache",
    "L|nv-gl|shader_thumb_cache|NVIDIA GLCache|cache|NVIDIA/GLCache",
    "L|amd-dx|shader_thumb_cache|AMD DxCache|cache|AMD/DxCache",
    "H|mesa|shader_thumb_cache|Mesa Shader Cache|cache|.cache/mesa_shader_cache",
    "H|thumb|shader_thumb_cache|XDG Thumbnails|thumbnail|.cache/thumbnails",
    "H|ql|shader_thumb_cache|QuickLook Cache|thumbnail|Library/Caches/com.apple.QuickLook.thumbnailcache",
    "LR|npm|dev_pkg_cache|npm cache|node_cache|npm-cache",
    "H|npm-h|dev_pkg_cache|npm _cacache|node_cache|.npm/_cacache",
    "L|pnpm-w|dev_pkg_cache|pnpm store|node_cache|pnpm/store",
    "H|pnpm-m|dev_pkg_cache|pnpm store (macOS)|node_cache|Library/pnpm/store",
    "H|pnpm-l|dev_pkg_cache|pnpm store (XDG)|node_cache|.local/share/pnpm/store",
    "L|yarn-w|dev_pkg_cache|Yarn cache|node_cache|Yarn/Cache",
    "C|yarn-c|dev_pkg_cache|Yarn cache|node_cache|yarn",
    "H|yarn-m|dev_pkg_cache|Yarn cache (macOS)|node_cache|Library/Caches/Yarn",
    "H|bun|dev_pkg_cache|Bun install cache|dev_cache|.bun/install/cache",
    "L|pip-w|dev_pkg_cache|pip cache|python_cache|pip/Cache",
    "C|pip-c|dev_pkg_cache|pip cache|python_cache|pip",
    "L|uv-w|dev_pkg_cache|uv cache|dev_cache|uv/cache",
    "C|uv-c|dev_pkg_cache|uv cache|dev_cache|uv",
    "L|poetry-w|dev_pkg_cache|Poetry cache|python_cache|pypoetry/Cache",
    "C|poetry-c|dev_pkg_cache|Poetry cache|python_cache|pypoetry",
    "LC|go|dev_pkg_cache|Go build cache|dev_cache|go-build",
    "L|nuget-v3|dev_pkg_cache|NuGet v3-cache|dev_cache|NuGet/v3-cache",
    "H|nuget-pkg|dev_pkg_cache|NuGet packages|dev_cache|.nuget/packages",
    "H|xcode|dev_pkg_cache|Xcode DerivedData|dev_cache|Library/Developer/Xcode/DerivedData",
    "G|cargo-reg|dev_pkg_cache|Cargo registry cache|dev_cache|registry/cache",
    "D|gradle|dev_pkg_cache|Gradle caches|dev_cache|caches",
    "H!|maven|dev_pkg_cache|Maven .m2 repository|dev_cache|.m2/repository",
];

#[derive(Debug, Clone, Copy, Default)]
pub struct DirStats {
    pub bytes: u64,
    pub files: u64,
    pub mtime: Option<i64>,
    pub sensitive: bool,
}

pub fn bump_mtime(cur: &mut Option<i64>, m: &std::fs::Metadata) {
    if let Some(t) = mtime_secs(m) {
        *cur = Some(cur.map_or(t, |c| c.max(t)));
    }
}

pub fn measure_dir_safe(root: &Path, max_files: usize) -> DirStats {
    let (mut st, mut stack) = (DirStats::default(), vec![root.to_path_buf()]);
    while let Some(dir) = stack.pop() {
        for e in rd_vec(&dir) {
            let p = e.path();
            if safety::sensitive_never_touch_reason(&p).is_some() || safety::is_protected(&p) {
                st.sensitive = true;
                continue;
            }
            let Ok(m) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if is_symlink_or_junction(&m) {
                continue;
            }
            if m.is_dir() && (st.files as usize) < max_files {
                stack.push(p);
            } else if m.is_file() {
                (st.bytes, st.files) = (st.bytes.saturating_add(m.len()), st.files + 1);
                bump_mtime(&mut st.mtime, &m);
                if (st.files as usize) >= max_files {
                    break;
                }
            }
        }
    }
    st
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SmartScanParams {
    pub target_free_bytes: Option<u64>,
    pub include_ai_stack: Option<bool>,
    pub detail_level: Option<String>,
    pub custom_roots_override: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupUnit {
    pub unit_id: String,
    pub group: String,
    pub label: String,
    pub category: String,
    pub kind: String,
    pub path: String,
    pub size_bytes: u64,
    pub file_count: u64,
    pub in_use: bool,
    pub verdict: String,
    pub risk_level: String,
    pub approval_token: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedUnit {
    pub unit_id: String,
    pub group: String,
    pub category: String,
    pub path: String,
    pub size_bytes: u64,
    pub cumulative_bytes: u64,
    pub verdict: String,
    pub risk_level: String,
    pub confirm_risk_required: bool,
    pub approval_token: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupSummary {
    pub group: String,
    pub unit_count: usize,
    pub size_bytes: u64,
    pub safe_bytes: u64,
    pub blocked_units: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SmartScanReport {
    pub scan_id: String,
    pub detail_level: String,
    pub duration_ms: u64,
    pub total_bytes: u64,
    pub safe_reclaimable_bytes: u64,
    pub review_reclaimable_bytes: u64,
    pub blocked_bytes: u64,
    pub total_units: usize,
    pub returned_units: usize,
    pub truncated: bool,
    pub groups: Vec<GroupSummary>,
    pub units: Vec<CleanupUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_free_bytes: Option<u64>,
    pub recommended_plan: Vec<PlannedUnit>,
    pub plan_total_bytes: u64,
    pub target_met: bool,
    pub warnings: Vec<String>,
}

#[allow(dead_code)]
pub fn run_smart_scan(engine: &ScanEngine, params: &SmartScanParams) -> SmartScanReport {
    let started = Instant::now();
    let inc_ai = params.include_ai_stack.unwrap_or(true);
    let full = params
        .detail_level
        .as_deref()
        .is_some_and(|d| d.eq_ignore_ascii_case("full"));
    let (mut warnings, mut raw_units) = (Vec::new(), Vec::new());

    if let Some(roots) = &params.custom_roots_override {
        let pbs: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();
        let act = ActiveAiProcesses::detect_scoped(&pbs);
        pbs.iter()
            .for_each(|r| scan_sandbox(r, inc_ai, &act, &mut warnings, &mut raw_units));
    } else {
        let act = ActiveAiProcesses::detect_live();
        collect_host_hotspots(&act, &mut raw_units);
        if inc_ai {
            raw_units.extend(ai_stack::scan_host_ai_stack(&act, &mut warnings));
        }
    }

    let mut seen = HashSet::new();
    raw_units.retain(|u| {
        safety::sensitive_never_touch_reason(&u.cand.path).is_none()
            && !safety::is_protected(&u.cand.path)
            && seen.insert(safety::normalize(&u.cand.path))
    });

    let dur = started.elapsed().as_millis() as u64;
    let cands: Vec<CustomCandidate> = raw_units.iter().map(|u| u.cand.clone()).collect();
    let sess = engine.register_custom_session("smart_scan", cands, warnings.clone(), dur, true);

    let mut all: Vec<(u8, CleanupUnit)> = raw_units
        .into_iter()
        .zip(sess.entries.iter())
        .map(|(raw, e)| {
            let u = CleanupUnit {
                unit_id: raw.unit_id,
                group: raw.group,
                label: raw.label,
                category: e.category.clone(),
                kind: e.kind.clone(),
                path: e.path.clone(),
                size_bytes: e.size,
                file_count: raw.file_count,
                in_use: raw.in_use || e.verdict == "blocked",
                verdict: e.verdict.clone(),
                risk_level: e.risk_level.clone(),
                approval_token: e.approval_token.clone(),
                reasons: if full { e.reasons.clone() } else { Vec::new() },
            };
            (e.importance_score, u)
        })
        .collect();

    let (mut total_bytes, mut safe_bytes, mut review_bytes, mut blocked_bytes) =
        (0u64, 0u64, 0u64, 0u64);
    let mut groups: BTreeMap<String, GroupSummary> = BTreeMap::new();
    for (_, u) in &all {
        total_bytes = total_bytes.saturating_add(u.size_bytes);
        let g = groups.entry(u.group.clone()).or_default();
        g.group.clone_from(&u.group);
        (g.unit_count, g.size_bytes) =
            (g.unit_count + 1, g.size_bytes.saturating_add(u.size_bytes));
        if u.in_use || u.verdict == "blocked" {
            blocked_bytes = blocked_bytes.saturating_add(u.size_bytes);
            g.blocked_units += 1;
        } else if u.verdict == "safe_to_delete" {
            safe_bytes = safe_bytes.saturating_add(u.size_bytes);
            g.safe_bytes = g.safe_bytes.saturating_add(u.size_bytes);
        } else if u.verdict == "review" {
            review_bytes = review_bytes.saturating_add(u.size_bytes);
        }
    }

    let (recommended_plan, plan_total_bytes, target_met) =
        build_plan(&all, params.target_free_bytes);
    all.sort_by(|a, b| {
        b.1.size_bytes
            .cmp(&a.1.size_bytes)
            .then_with(|| a.1.path.cmp(&b.1.path))
    });
    let total_units = all.len();
    let truncated = !full && total_units > BRIEF_MAX_UNITS;
    let units: Vec<CleanupUnit> = all
        .into_iter()
        .take(if full { usize::MAX } else { BRIEF_MAX_UNITS })
        .map(|x| x.1)
        .collect();

    SmartScanReport {
        scan_id: sess.scan_id.clone(),
        detail_level: if full { "full" } else { "brief" }.into(),
        duration_ms: dur,
        total_bytes,
        safe_reclaimable_bytes: safe_bytes,
        review_reclaimable_bytes: review_bytes,
        blocked_bytes,
        total_units,
        returned_units: units.len(),
        truncated,
        groups: groups.into_values().collect(),
        units,
        target_free_bytes: params.target_free_bytes,
        recommended_plan,
        plan_total_bytes,
        target_met,
        warnings,
    }
}

fn build_plan(units: &[(u8, CleanupUnit)], target: Option<u64>) -> (Vec<PlannedUnit>, u64, bool) {
    let Some(goal) = target else {
        return (Vec::new(), 0, false);
    };
    if goal == 0 {
        return (Vec::new(), 0, true);
    }
    let ok = |u: &CleanupUnit| {
        !u.in_use && u.size_bytes > 0 && matches!(u.verdict.as_str(), "safe_to_delete" | "review")
    };
    let mut pool: Vec<&(u8, CleanupUnit)> = units.iter().filter(|(_, u)| ok(u)).collect();
    pool.sort_by(|(sa, a), (sb, b)| {
        let (ta, tb) = (
            u8::from(a.verdict != "safe_to_delete"),
            u8::from(b.verdict != "safe_to_delete"),
        );
        ta.cmp(&tb)
            .then_with(|| b.size_bytes.cmp(&a.size_bytes))
            .then_with(|| sa.cmp(sb))
            .then_with(|| a.path.cmp(&b.path))
    });
    let (mut plan, mut acc) = (Vec::new(), 0u64);
    for (_, u) in pool {
        if acc >= goal {
            break;
        }
        acc = acc.saturating_add(u.size_bytes);
        plan.push(PlannedUnit {
            unit_id: u.unit_id.clone(),
            group: u.group.clone(),
            category: u.category.clone(),
            path: u.path.clone(),
            size_bytes: u.size_bytes,
            cumulative_bytes: acc,
            verdict: u.verdict.clone(),
            risk_level: u.risk_level.clone(),
            confirm_risk_required: u.verdict != "safe_to_delete",
            approval_token: u.approval_token.clone(),
        });
    }
    (plan, acc, acc >= goal)
}

fn collect_host_hotspots(act: &ActiveAiProcesses, out: &mut Units) {
    scan_os_temp_children(act, out);
    let (home, local, cache, roam) = (
        dirs::home_dir(),
        dirs::data_local_dir(),
        dirs::cache_dir(),
        dirs::config_dir(),
    );
    let env_or = |v: &str, rel: &str| {
        std::env::var(v)
            .ok()
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|h| h.join(rel)))
    };
    let (cargo, gradle) = (
        env_or("CARGO_HOME", ".cargo"),
        env_or("GRADLE_USER_HOME", ".gradle"),
    );
    for row in HOTSPOTS {
        let p: Vec<&str> = row.splitn(6, '|').collect();
        for ch in p[0].trim_end_matches('!').chars() {
            let base_opt = match ch {
                'L' => local.as_ref(),
                'C' => cache.as_ref(),
                'H' => home.as_ref(),
                'G' => cargo.as_ref(),
                'D' => gradle.as_ref(),
                _ => roam.as_ref(),
            };
            let Some(base) = base_opt else { continue };
            let path = base.join(p[5]);
            if safe_meta(&path).is_some_and(|m| m.is_dir()) {
                let st = measure_dir_safe(&path, 60_000);
                if !st.sensitive && st.bytes > 0 {
                    let spec = format!("{}-{ch}|{}|{}", p[1], p[2], p[4]);
                    let mut u = RawCleanupUnit::dir(&spec, p[3].into(), path.clone(), st, p[3]);
                    if p[0].ends_with('!') {
                        u = u.into_review(40);
                    }
                    out.push(u.with_lock(act.is_path_in_use(&path), "Anti-Suicide: cache in use"));
                }
            }
        }
    }
}

fn scan_os_temp_children(act: &ActiveAiProcesses, out: &mut Units) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let mut items = Vec::new();
    for e in rd_vec(&std::env::temp_dir()) {
        let fname = e.file_name().to_string_lossy().into_owned();
        let low = fname.to_lowercase();
        if low.starts_with('.')
            || "systemd-private|ssh-|gpg-|tmux-"
                .split('|')
                .any(|p| low.starts_with(p))
        {
            continue;
        }
        let p = e.path();
        let Some(m) = safe_meta(&p) else { continue };
        if let Some(u) = build_entry(
            "os-temp|os_temp_logs|temp",
            format!("Stale temp ({fname})"),
            &p,
            &m,
        ) {
            if u.cand.size >= TEMP_MIN_BYTES
                && u.cand
                    .modified
                    .is_some_and(|t| now - t >= TEMP_MIN_AGE_SECS)
            {
                items.push(u.with_lock(act.is_path_in_use(&p), "Anti-Suicide: temp in use"));
            }
        }
    }
    items.sort_by_key(|b| std::cmp::Reverse(b.cand.size));
    items.truncate(25);
    out.extend(items);
}

fn build_entry(s: &str, lbl: String, p: &Path, m: &std::fs::Metadata) -> Option<RawCleanupUnit> {
    if m.is_dir() {
        let st = measure_dir_safe(p, 25_000);
        (!st.sensitive && st.bytes > 0)
            .then(|| RawCleanupUnit::dir(s, lbl, p.into(), st, "Allowlist"))
    } else {
        (m.is_file() && m.len() > 0).then(|| RawCleanupUnit::file(s, lbl, p.into(), m, "Allowlist"))
    }
}

fn scan_sandbox(
    r: &Path,
    inc_ai: bool,
    act: &ActiveAiProcesses,
    warns: &mut Vec<String>,
    out: &mut Units,
) {
    if !r.exists() || safety::is_protected(r) || safety::sensitive_never_touch_reason(r).is_some() {
        return warns.push(format!("Custom root skipped/blocked: {}", r.display()));
    }
    if !std::fs::symlink_metadata(r).is_ok_and(|rm| !is_symlink_or_junction(&rm) && rm.is_dir()) {
        return warns.push(format!("Custom root invalid: {}", r.display()));
    }
    let mut cov = Vec::new();
    if inc_ai {
        let (ai_u, c) = ai_stack::scan_custom_ai_root(r, act, warns);
        out.extend(ai_u);
        cov = c.into_iter().map(|p| safety::normalize(&p)).collect();
    }
    if cov.contains(&safety::normalize(r)) {
        return;
    }
    for entry in rd_vec(r) {
        let p = entry.path();
        let Some(m) = safe_meta(&p) else { continue };
        let pn = safety::normalize(&p);
        if cov.iter().any(|c| pn.starts_with(c) || c.starts_with(&pn)) {
            continue;
        }
        let fname = entry.file_name().to_string_lossy().into_owned();
        let (spec, rev) = classify_sandbox(&fname, m.is_dir());
        if let Some(mut u) = build_entry(spec, format!("Allowlist ({fname})"), &p, &m) {
            if let Some(sc) = rev {
                u = u.into_review(sc);
            }
            out.push(u.with_lock(act.is_path_in_use(&p), "Anti-Suicide: unit in use"));
        }
    }
}

fn classify_sandbox(name: &str, is_dir: bool) -> (&'static str, Option<u8>) {
    let l = name.to_lowercase();
    for &(keys, spec, rev) in &[
        ("npm|pnpm|yarn", "custom|dev_pkg_cache|node_cache", None),
        (
            "pip|poetry|pycache",
            "custom|dev_pkg_cache|python_cache",
            None,
        ),
        (
            "cargo|gradle|uv|bun|go-build|nuget",
            "custom|dev_pkg_cache|dev_cache",
            None,
        ),
        ("maven|.m2", "custom|dev_pkg_cache|dev_cache", Some(40)),
        ("log", "custom|os_temp_logs|log", None),
        ("tmp|temp", "custom|os_temp_logs|temp", None),
        ("cache|shader", "custom|shader_thumb_cache|cache", None),
    ] {
        if keys.split('|').any(|k| l.contains(k)) || (keys == "maven|.m2" && l == "m2") {
            return (spec, rev);
        }
    }
    if is_dir {
        ("custom|dev_pkg_cache|cache", Some(45))
    } else {
        ("custom|os_temp_logs|other", Some(50))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DeleteItemRequest, DeleteRequest};

    fn sbx(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("dcm-ss-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn wr(p: PathBuf, data: &[u8]) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    fn mk_params(root: &Path, goal: u64, level: &str) -> SmartScanParams {
        SmartScanParams {
            target_free_bytes: Some(goal),
            include_ai_stack: Some(true),
            detail_level: Some(level.into()),
            custom_roots_override: Some(vec![root.to_string_lossy().into_owned()]),
        }
    }

    #[test]
    fn test_smart_scan_never_touch_and_delete_roundtrip() {
        let root = sbx("e2e");
        wr(root.join("npm-cache/pkg.tgz"), &[1u8; 4096]);
        wr(root.join("stale.tmp"), &[2u8; 1024]);
        wr(root.join(".ssh/id_ed25519"), b"secret");
        wr(root.join(".env"), b"TOKEN=secret");
        let engine = ScanEngine::new();
        let rep = run_smart_scan(&engine, &mk_params(&root, 4000, "full"));
        assert_eq!(rep.total_units, 2);
        assert!(rep
            .units
            .iter()
            .all(|u| !u.path.contains(".ssh") && !u.path.ends_with(".env")));
        assert!(rep.target_met && rep.recommended_plan.len() == 1);
        let p0 = &rep.recommended_plan[0];
        let items = vec![DeleteItemRequest {
            path: p0.path.clone(),
            approval_token: p0.approval_token.clone(),
        }];
        let del = engine.delete(&DeleteRequest {
            scan_id: rep.scan_id,
            items,
            permanent: true,
            confirm_permanent: true,
            confirm_risk: false,
            dry_run: true,
        });
        assert!(del.dry_run == 1 && del.rejected == 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_planner_tiers_safe_before_review_and_brief_cap() {
        let root = sbx("planner");
        wr(root.join("a.tmp"), &[1u8; 1000]);
        wr(root.join("b.log"), &[2u8; 2000]);
        wr(
            root.join("huggingface/hub/models--org--big/snapshots/v1/w.bin"),
            &[3u8; 5000],
        );
        let engine = ScanEngine::new();
        let r1 = run_smart_scan(&engine, &mk_params(&root, 2500, "brief"));
        assert!(r1.target_met && r1.recommended_plan.len() == 2);
        assert!(r1.recommended_plan.iter().all(|p| !p.confirm_risk_required));
        assert!(r1.units.iter().all(|u| u.reasons.is_empty()));
        let r2 = run_smart_scan(&engine, &mk_params(&root, 6000, "full"));
        assert!(
            r2.target_met
                && r2.recommended_plan.len() == 3
                && r2.recommended_plan[2].confirm_risk_required
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
