//! Cross-platform Startup & Launch Agents scanner with unquoted path parsing,
//! script-host unwrapping, CLI secret redaction, and user-writable orphan tokens.

use crate::engine::{CustomCandidate, ScanEngine};
use crate::safety;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Component, Path, PathBuf as Pb};
use std::time::{Instant, UNIX_EPOCH};

const SECRET_FLAGS_CSV: &str = "--token|--access-token|--auth-token|--api-key|--apikey|--key|\
--password|--passwd|--secret|--client-secret|-token|-apikey|-api-key|-password|-passwd|-secret|-key";
const SCRIPT_SKIP_CSV: &str =
    "/c|/k|//b|//nologo|-noprofile|-nop|-noni|-noninteractive|-sta|-file|-f|-c";
const HOSTS_CSV: &str = "wscript|cscript|cmd|powershell|pwsh|sh|bash|env";
const WIN_EXE_EXTS: &[&str] = &[".exe", ".com", ".bat", ".cmd", ".vbs", ".ps1", ".msc"];

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartupParams {
    pub orphans_only: Option<bool>,
    pub custom_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartupItem {
    pub name: String,
    pub source: String,
    pub location: String,
    pub command_redacted: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    pub orphaned: bool,
    pub read_only: bool,
    pub category: String,
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_token: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartupReport {
    pub scan_id: String,
    pub duration_ms: u64,
    pub total_items: usize,
    pub orphaned_count: usize,
    pub deletable_orphans_count: usize,
    pub items: Vec<StartupItem>,
    pub warnings: Vec<String>,
}

type RawEntry = (String, String, Pb, String, String, Option<String>, bool);
type Parsed = (String, String, Option<String>);

#[allow(dead_code)]
pub fn scan_startup_items(engine: &ScanEngine, params: &StartupParams) -> StartupReport {
    let (started, orphans_only) = (Instant::now(), params.orphans_only.unwrap_or(false));
    let (mut warnings, mut raws) = (Vec::new(), Vec::new());
    let cd = params.custom_dir.as_deref().unwrap_or("").trim();
    if cd.is_empty() {
        collect_os_entries(&mut raws);
    } else if is_safe(Path::new(cd), true) {
        collect_dir(&mut raws, cd, "custom_dir", false);
    } else {
        warnings.push(format!("Skipped unsafe or missing customDir: {cd}"));
    }

    let (mut cands, mut items, mut orphaned_count) = (Vec::new(), Vec::new(), 0usize);
    for (name, source, path, location, cmd, exp_target, read_only) in raws {
        let target_path = exp_target.or_else(|| extract_command_target(&cmd));
        let orphaned = target_path.as_deref().is_some_and(is_missing_abs);
        orphaned_count += usize::from(orphaned);
        if orphans_only && !orphaned {
            continue;
        }
        let can_del =
            orphaned && !read_only && is_safe(&path, false) && !safety::is_protected(&path);
        if can_del {
            let m = fs::symlink_metadata(&path).ok();
            let mt = m.as_ref().and_then(|x| x.modified().ok());
            let d = mt.and_then(|t| t.duration_since(UNIX_EPOCH).ok());
            cands.push(CustomCandidate {
                kind: "file".into(),
                path,
                size: m.map_or(0, |x| x.len()),
                modified: d.map(|x| x.as_secs() as i64),
                category: "startup_orphan".into(),
                verdict: "review".into(),
                importance_score: 50,
                risk_level: "caution".into(),
                reasons: vec![format!("Orphaned startup '{name}'")],
            });
        }
        items.push(StartupItem {
            name,
            source,
            location,
            command_redacted: redact_command_secrets(&cmd),
            target_path,
            orphaned,
            read_only,
            category: if orphaned { "startup_orphan" } else { "other" }.into(),
            verdict: if can_del { "review" } else { "keep" }.into(),
            approval_token: None,
        });
    }

    let (dur, warn_c) = (started.elapsed().as_millis() as u64, warnings.clone());
    let sess = engine.register_custom_session("startup_items", cands, warn_c, dur, true);
    let tmap: HashMap<&str, _> = sess.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let mut del_cnt = 0usize;
    for it in items.iter_mut().filter(|i| !i.read_only && i.orphaned) {
        if let Some(e) = tmap.get(it.location.as_str()) {
            it.verdict.clone_from(&e.verdict);
            if e.verdict != "blocked" {
                it.approval_token = Some(e.approval_token.clone());
                del_cnt += 1;
            }
        }
    }
    StartupReport {
        scan_id: sess.scan_id.clone(),
        duration_ms: dur,
        total_items: items.len(),
        orphaned_count,
        deletable_orphans_count: del_cnt,
        items,
        warnings,
    }
}

fn collect_os_entries(out: &mut Vec<RawEntry>) {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER as HKCU, HKEY_LOCAL_MACHINE as HKLM, KEY_READ};
        use winreg::RegKey;
        for spec in [
            r"HKCU|hkcu_run|Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU|hkcu_run_once|Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM|hklm_run|SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM|hklm_wow64_run|SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ] {
            let pts: Vec<&str> = spec.splitn(3, '|').collect();
            let hive = if pts[0] == "HKCU" { HKCU } else { HKLM };
            if let Ok(k) = RegKey::predef(hive).open_subkey_with_flags(pts[2], KEY_READ) {
                for (vn, v) in k.enum_values().flatten() {
                    let cmd = v.to_string();
                    if !cmd.trim().is_empty() {
                        let loc = format!("{}\\{}\\{vn}", pts[0], pts[2]);
                        out.push((vn, pts[1].into(), Pb::new(), loc, cmd, None, true));
                    }
                }
            }
        }
        let rel = r"Microsoft\Windows\Start Menu\Programs\Startup";
        if let Some(r) = dirs::data_dir() {
            collect_dir(out, r.join(rel), "startup_folder", false);
        }
        let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
        collect_dir(out, Pb::from(pd).join(rel), "common_startup_folder", true);
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(h) = dirs::home_dir() {
            let u = h.join("Library/LaunchAgents");
            collect_dir(out, u, "user_launch_agent", false);
        }
        collect_dir(out, "/Library/LaunchAgents", "system_launch_agent", true);
        collect_dir(out, "/Library/LaunchDaemons", "system_launch_daemon", true);
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(h) = dirs::home_dir() {
            let cfg = dirs::config_dir().unwrap_or_else(|| h.join(".config"));
            collect_dir(out, cfg.join("autostart"), "xdg_autostart", false);
            collect_dir(out, cfg.join("systemd/user"), "systemd_user", false);
        }
        collect_dir(out, "/etc/xdg/autostart", "system_xdg_autostart", true);
    }
}

fn collect_dir(out: &mut Vec<RawEntry>, dir: impl AsRef<Path>, source: &str, ro: bool) {
    let dir = dir.as_ref();
    if !is_safe(dir, true) {
        return;
    }
    let rd_str = |p: &Path| fs::read_to_string(p).ok();
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        let fnm = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let bad = fnm.is_empty() || fnm.starts_with('.') || fnm.eq_ignore_ascii_case("desktop.ini");
        if bad || !is_safe(&p, false) {
            continue;
        }
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
        let loc = p.to_string_lossy().into_owned();
        let parsed = match ext.to_ascii_lowercase().as_str() {
            "plist" => fs::read(&p).ok().and_then(|b| parse_macos_plist(&b, fnm)),
            "desktop" => rd_str(&p).and_then(|s| parse_ini(&s, fnm, false)),
            "service" => rd_str(&p).and_then(|s| parse_ini(&s, fnm, true)),
            "lnk" => fs::read(&p).ok().and_then(|b| parse_lnk(&b, fnm)),
            "bat" | "cmd" | "vbs" | "ps1" | "sh" => {
                let s = rd_str(&p).unwrap_or_default();
                let pfx = |l: &str| l.starts_with(['#', '@', ':']) || l.starts_with("REM ");
                let cmd = s.lines().map(str::trim).find(|l| !l.is_empty() && !pfx(l));
                Some((fnm.into(), cmd.unwrap_or(&loc).into(), None))
            }
            _ => None,
        };
        if let Some((name, cmd, target)) = parsed {
            out.push((name, source.into(), p, loc, cmd, target, ro));
        }
    }
}

fn parse_macos_plist(bytes: &[u8], fb: &str) -> Option<Parsed> {
    let xml = (!bytes.starts_with(b"bplist00")).then(|| std::str::from_utf8(bytes).ok())??;
    let first = |k| plist_tags(xml, k, false).and_then(|v| v.into_iter().next());
    let label = first("Label").unwrap_or_else(|| fb.into());
    let prog = first("Program");
    let args = plist_tags(xml, "ProgramArguments", true).unwrap_or_default();
    let a_cmd = (!args.is_empty()).then(|| args.join(" "));
    let cmd = a_cmd.or_else(|| prog.clone())?;
    let head = prog.or_else(|| args.first().cloned())?;
    let (sh, h_exp) = (is_script_host(&head), Some(expand_env(&head)));
    let target = if sh {
        extract_command_target(&cmd)
    } else {
        h_exp
    };
    Some((label, cmd, target))
}

fn plist_tags(xml: &str, key: &str, is_arr: bool) -> Option<Vec<String>> {
    let after = xml.split(&format!("<key>{key}</key>")).nth(1)?;
    let scope = match is_arr {
        true => after.get(after.find("<array>")? + 7..after.find("</array>")?)?,
        false => after.split("</string>").next()?,
    };
    let clean = |s: &str| {
        let t = s.split("</string>").next().unwrap_or("").trim();
        let a = t.replace("&amp;", "&").replace("&lt;", "<");
        let b = a.replace("&gt;", ">").replace("&quot;", "\"");
        b.replace("&apos;", "'")
    };
    Some(scope.split("<string>").skip(1).map(clean).collect())
}

fn parse_ini(content: &str, fb: &str, is_service: bool) -> Option<Parsed> {
    let mut kv = BTreeMap::new();
    for (k, v) in content.lines().filter_map(|l| l.trim().split_once('=')) {
        kv.insert(k.trim(), v.trim());
    }
    if is_service {
        let raw = (*kv.get("ExecStart").filter(|v| !v.is_empty())?).to_string();
        let nm = kv.get("Description").copied().unwrap_or(fb).into();
        return Some((nm, raw.clone(), extract_command_target(&raw)));
    }
    let hid = kv.get("Hidden").copied().unwrap_or("");
    (!hid.eq_ignore_ascii_case("true")).then_some(())?;
    let ex: Vec<_> = kv.get("Exec").unwrap_or(&"").split_whitespace().collect();
    let ex_t: Vec<_> = ex.into_iter().filter(|t| !t.starts_with('%')).collect();
    let (try_ex, ex_s) = (
        kv.get("TryExec").copied(),
        (!ex_t.is_empty()).then(|| ex_t.join(" ")),
    );
    let cmd = ex_s.or_else(|| try_ex.map(Into::into))?;
    let t_ex = try_ex.map(expand_env);
    let target = t_ex.or_else(|| extract_command_target(&cmd));
    Some((kv.get("Name").copied().unwrap_or(fb).into(), cmd, target))
}

fn parse_lnk(bytes: &[u8], fb: &str) -> Option<Parsed> {
    let u32_at =
        |o: usize| Some(u32::from_le_bytes(bytes.get(o..o + 4)?.try_into().ok()?) as usize);
    (bytes.len() >= 76 && bytes[0..4] == [0x4c, 0x00, 0x00, 0x00]).then_some(())?;
    let (flags, mut pos) = (u32_at(0x14)?, 76usize);
    if flags & 0x01 != 0 {
        let n = u16::from_le_bytes(bytes.get(pos..pos + 2)?.try_into().ok()?) as usize;
        pos = pos.checked_add(2 + n)?;
    }
    (flags & 0x02 != 0 && u32_at(pos + 8)? & 0x01 != 0).then_some(())?;
    let info = bytes.get(pos..u32_at(pos)?.checked_add(pos)?)?;
    let target = if u32_at(pos + 4)? >= 0x24 {
        let raw = info.get(u32_at(pos + 28)?..)?;
        let f16 = |c: &[u8]| u16::from_le_bytes([c[0], c[1]]);
        let it = raw.chunks_exact(2).map(f16);
        let u: Vec<u16> = it.take_while(|&x| x != 0).collect();
        (!u.is_empty()).then(|| String::from_utf16_lossy(&u))?
    } else {
        let s = info.get(u32_at(pos + 16)?..)?;
        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
        (end > 0).then(|| String::from_utf8_lossy(&s[..end]).into_owned())?
    };
    Some((fb.into(), target.clone(), Some(target)))
}

fn extract_command_target(raw_cmd: &str) -> Option<String> {
    let is_pre = |c: char| c.is_whitespace() || "-@+!:".contains(c);
    let stripped = raw_cmd.trim_start_matches(is_pre).trim_end();
    let exp = (!stripped.is_empty()).then(|| expand_env(stripped))?;
    let (primary, rest) = split_head(&exp)?;
    let (sh, p) = (is_script_host(&primary), Some(primary));
    if sh {
        extract_script_arg(rest)
    } else {
        p
    }
}

fn split_head(cmd: &str) -> Option<(String, &str)> {
    let s = cmd.trim_start();
    if let Some(q) = s.chars().next().filter(|&c| c == '"' || c == '\'') {
        let inner = &s[q.len_utf8()..];
        let end = inner.find(q)?;
        return Some((inner[..end].trim().into(), &inner[end + q.len_utf8()..]));
    }
    let low = s.to_ascii_lowercase();
    for ext in WIN_EXE_EXTS {
        for (i, _) in low.match_indices(ext) {
            let end = i + ext.len();
            if end == s.len() || s[end..].starts_with(char::is_whitespace) {
                return Some((s[..end].trim().into(), &s[end..]));
            }
        }
    }
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    (end > 0).then(|| (s[..end].into(), &s[end..]))
}

fn is_script_host(bin: &str) -> bool {
    let fnm = Path::new(bin).file_name().and_then(|n| n.to_str());
    let stem = fnm.unwrap_or(bin).to_ascii_lowercase();
    let st = stem.trim_end_matches(".exe");
    HOSTS_CSV.split('|').any(|h| h == st)
}

fn extract_script_arg(rest: &str) -> Option<String> {
    let mut skip = false;
    for (i, rt) in tokenize_quotes(rest).into_iter().enumerate() {
        let tok = rt.trim_matches(['"', '\'']);
        if std::mem::take(&mut skip) {
            continue;
        }
        let l = tok.to_ascii_lowercase();
        if matches!(l.as_str(), "-command" | "-encodedcommand" | "-enc") || (l == "-c" && i > 0) {
            return None;
        }
        skip = matches!(l.as_str(), "-windowstyle" | "-executionpolicy" | "-ep");
        let is_fl = skip || SCRIPT_SKIP_CSV.split('|').any(|x| x == l) || tok.starts_with('-');
        if !(is_fl || (tok.starts_with('/') && tok.len() <= 4)) {
            let cand = expand_env(tok);
            if is_win_abs(&cand) || cand.starts_with('/') {
                return Some(cand);
            }
        }
    }
    None
}

fn redact_command_secrets(cmd: &str) -> String {
    let is_fl = |f: &str| {
        let fc = f.trim_start_matches('-');
        SECRET_FLAGS_CSV
            .split('|')
            .any(|x| x.eq_ignore_ascii_case(f))
            || (!fc.is_empty()
                && ["_token", "_key", "_secret", "_password", "_passwd"]
                    .iter()
                    .any(|s| fc.to_ascii_lowercase().ends_with(s)))
    };
    let (mut out, mut redact_next) = (Vec::new(), false);
    for tok in tokenize_quotes(cmd) {
        if std::mem::take(&mut redact_next) {
            out.push("[REDACTED]".into());
            continue;
        }
        let unq = tok.trim_matches(['"', '\'']);
        if unq.eq_ignore_ascii_case("bearer") || is_fl(unq) {
            out.push(tok);
            redact_next = true;
        } else if let Some((fp, _)) = unq.split_once('=').filter(|(f, _)| is_fl(f)) {
            out.push(format!("{fp}=[REDACTED]"));
        } else {
            out.push(redact_inline_secrets(&tok));
        }
    }
    redact_inline_secrets(&out.join(" "))
}

fn redact_inline_secrets(input: &str) -> String {
    // 1. Redact <scheme>://<userinfo>@<host> -> <scheme>://[REDACTED]@<host>
    let mut s = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find("://") {
        let has_scheme = pos > 0 && rest.as_bytes()[pos - 1].is_ascii_alphanumeric();
        let auth_start = pos + 3;
        let tail = &rest[auth_start..];
        let auth_end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\''))
            .unwrap_or(tail.len());
        if has_scheme {
            if let Some(at) = tail[..auth_end].rfind('@').filter(|&i| i > 0) {
                s.push_str(&rest[..auth_start]);
                s.push_str("[REDACTED]@");
                rest = &tail[at + 1..];
                continue;
            }
        }
        s.push_str(&rest[..auth_start + auth_end]);
        rest = &tail[auth_end..];
    }
    s.push_str(rest);

    // 2. Redact inline "Bearer <secret>" / "Basic <secret>" (including inside quotes/headers)
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let (mut i, mut last) = (0usize, 0usize);
    while i < bytes.len() {
        let matched = ["bearer", "basic"].into_iter().find(|kw| {
            i + kw.len() < bytes.len()
                && s.is_char_boundary(i)
                && s.is_char_boundary(i + kw.len())
                && s[i..i + kw.len()].eq_ignore_ascii_case(kw)
                && (i == 0
                    || bytes[i - 1].is_ascii_whitespace()
                    || matches!(bytes[i - 1], b'"' | b'\'' | b':' | b'='))
                && matches!(bytes[i + kw.len()], b' ' | b'\t')
        });
        if let Some(kw) = matched {
            let mut ts = i + kw.len();
            while ts < bytes.len() && matches!(bytes[ts], b' ' | b'\t') {
                ts += 1;
            }
            let mut te = ts;
            while te < bytes.len()
                && !bytes[te].is_ascii_whitespace()
                && !matches!(bytes[te], b'"' | b'\'' | b';' | b',')
            {
                te += 1;
            }
            if te > ts && s.is_char_boundary(ts) && s.is_char_boundary(te) {
                out.push_str(&s[last..ts]);
                out.push_str("[REDACTED]");
                i = te;
                last = te;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);

    // 3. Redact URL query secrets (?token=..., &api_key=..., &password=..., &secret=...)
    let mut final_out = String::with_capacity(out.len());
    let mut qrest = out.as_str();
    while let Some(idx) = qrest.find(['?', '&']) {
        final_out.push_str(&qrest[..=idx]);
        let after = &qrest[idx + 1..];
        let seg_end = after
            .find(|c: char| c.is_whitespace() || matches!(c, '&' | '#' | '"' | '\''))
            .unwrap_or(after.len());
        let seg = &after[..seg_end];
        if let Some((k, _)) = seg.split_once('=') {
            let kl = k.to_ascii_lowercase();
            if matches!(
                kl.as_str(),
                "token"
                    | "access_token"
                    | "auth_token"
                    | "api_key"
                    | "apikey"
                    | "key"
                    | "password"
                    | "passwd"
                    | "secret"
                    | "client_secret"
            ) {
                final_out.push_str(k);
                final_out.push_str("=[REDACTED]");
                qrest = &after[seg_end..];
                continue;
            }
        }
        final_out.push_str(seg);
        qrest = &after[seg_end..];
    }
    final_out.push_str(qrest);
    final_out
}

fn tokenize_quotes(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut q) = (Vec::new(), String::new(), None::<char>);
    for c in s.chars() {
        if q.is_none() && c.is_whitespace() {
            out.extend((!cur.is_empty()).then(|| std::mem::take(&mut cur)));
            continue;
        }
        q = match (q, c) {
            (Some(x), y) if x == y => None,
            (None, '"' | '\'') => Some(c),
            _ => q,
        };
        cur.push(c);
    }
    out.extend((!cur.is_empty()).then_some(cur));
    out
}

fn expand_env(input: &str) -> String {
    let rest = input.strip_prefix("~/");
    let hr = rest.or_else(|| input.strip_prefix("$HOME/"));
    if let Some((r, h)) = hr.zip(dirs::home_dir()) {
        return h.join(r).to_string_lossy().into_owned();
    }
    let mut s = input.to_string();
    while let Some(a) = s.find('%') {
        let r = s[a + 1..].find('%');
        let v = r.and_then(|n| std::env::var(&s[a + 1..a + 1 + n]).ok());
        match (r, v) {
            (Some(n), Some(val)) => s.replace_range(a..=a + 1 + n, &val),
            _ => break,
        }
    }
    s
}

fn is_win_abs(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/')
}

fn is_missing_abs(target: &str) -> bool {
    if is_win_abs(target) {
        let root = format!("{}:\\", target.as_bytes()[0] as char);
        return Path::new(&root).exists() && !Path::new(target).exists();
    }
    cfg!(unix) && target.starts_with('/') && Path::new("/").exists() && !Path::new(target).exists()
}

fn is_safe(path: &Path, want_dir: bool) -> bool {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return false;
    }
    fs::symlink_metadata(path).is_ok_and(|m| {
        #[cfg(windows)]
        if std::os::windows::fs::MetadataExt::file_attributes(&m) & 0x400 != 0 {
            return false;
        }
        !m.file_type().is_symlink() && if want_dir { m.is_dir() } else { m.is_file() }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_startup_parsing_redaction_and_orphan_tokens() {
        for spec in [
            r"C:\Program Files\Acme Tools\Updater.exe --silent|C:\Program Files\Acme Tools\Updater.exe",
            r#"powershell.exe -NoProfile -WindowStyle Hidden -File "C:\Ghost\sync.ps1"|C:\Ghost\sync.ps1"#,
            r#"wscript.exe //B "D:\Scripts\orphan.vbs"|D:\Scripts\orphan.vbs"#,
            "-@/opt/acme/daemon --port 9|/opt/acme/daemon",
            "powershell.exe -Command Get-Date|",
        ] {
            let (cmd, exp) = spec.split_once('|').unwrap();
            let got = extract_command_target(cmd);
            let want = (!exp.is_empty()).then_some(exp);
            assert_eq!(got.as_deref(), want);
        }
        let raw = r#""C:\App\a.exe" --api-key=sk-123 --password pw9 -token t9 Bearer jwt99 -H "Authorization: Bearer qjwt88" https://admin:urlpw77@host.local/cb?token=qtok66&ok=1 --ok"#;
        let red = redact_command_secrets(raw);
        let bad = [
            "sk-123", "pw9", "t9", "jwt99", "qjwt88", "urlpw77", "admin:", "qtok66",
        ];
        assert!(bad.iter().all(|s| !red.contains(s)), "leaked in: {red}");
        assert!(
            red.contains("https://[REDACTED]@host.local/cb?token=[REDACTED]&ok=1")
                && red.contains("--ok")
        );
        let tmp = std::env::temp_dir().join(format!("dcm-startup-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let (alive, missing) = (tmp.join("alive_helper.exe"), tmp.join("deleted_app.exe"));
        fs::write(&alive, b"MZ").unwrap();
        let (a_s, m_s) = (alive.to_string_lossy(), missing.to_string_lossy());
        let plist = format!("<plist><dict><key>Label</key><string>com.del</string><key>ProgramArguments</key><array><string>{m_s}</string><string>--secret</string><string>topsec</string></array></dict></plist>");
        fs::write(tmp.join("com.del.plist"), plist).unwrap();
        let dsk = format!("[Desktop Entry]\nName=Alive\nExec=\"{a_s}\" --min\n");
        fs::write(tmp.join("alive.desktop"), dsk).unwrap();
        let p = StartupParams {
            custom_dir: Some(tmp.to_string_lossy().into()),
            ..Default::default()
        };
        let r = scan_startup_items(&ScanEngine::new(), &p);
        let c = (r.total_items, r.orphaned_count, r.deletable_orphans_count);
        assert_eq!(c, (2, 1, 1));
        let orph = r.items.iter().find(|i| i.orphaned).unwrap();
        assert!(orph.approval_token.is_some() && !orph.command_redacted.contains("topsec"));
        for i in &r.items {
            assert!(i.orphaned || i.approval_token.is_none());
        }
        let _ = fs::remove_dir_all(&tmp);
    }
}
