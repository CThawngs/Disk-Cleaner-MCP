//! Pure-Rust read-only LevelDB `.log` (WAL) and `.ldb`/`.sst` (SSTable) string
//! and web-origin extractor (ZERO `LOCK` acquisition, ZERO writes, 16 MiB cap).

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

/// Hard upper bound (16 MiB) for Snappy decompression and per-directory reads.
pub const MAX_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;

const LOG_BLOCK_SIZE: usize = 32_768;
const LOG_HEADER_SIZE: usize = 7;
const SST_FOOTER_SIZE: usize = 48;
const SST_TABLE_MAGIC: u64 = 0xdb47_7524_8b80_fb57;

/// Decompress a raw Snappy block while enforcing `MAX_DECOMPRESSED_BYTES`
/// before allocating the output buffer.
#[allow(dead_code)]
pub fn decompress_snappy_capped(compressed: &[u8]) -> Result<Vec<u8>, String> {
    decompress_snappy_with_budget(compressed, MAX_DECOMPRESSED_BYTES)
}

fn decompress_snappy_with_budget(compressed: &[u8], budget: usize) -> Result<Vec<u8>, String> {
    let expected_len =
        snap::raw::decompress_len(compressed).map_err(|e| format!("Invalid Snappy header: {e}"))?;
    let cap = budget.min(MAX_DECOMPRESSED_BYTES);
    if expected_len > cap {
        return Err(format!("Snappy size {expected_len} exceeds cap {cap}"));
    }
    let mut out = vec![0u8; expected_len];
    let n = snap::raw::Decoder::new()
        .decompress(compressed, &mut out)
        .map_err(|e| format!("Snappy decompression failed: {e}"))?;
    out.truncate(n);
    Ok(out)
}

/// Extract normalized `http(s)://host[:port]` origins from a LevelDB directory.
pub fn extract_origins_from_leveldb_dir(dir: &Path) -> Vec<String> {
    let mut origins = BTreeSet::new();
    visit_leveldb_payloads(dir, |slice| collect_origins_into(slice, &mut origins));
    origins.into_iter().collect()
}

/// Extract normalized `http(s)://host[:port]` origins from arbitrary bytes.
pub fn extract_origins_from_bytes(data: &[u8]) -> Vec<String> {
    let mut set = BTreeSet::new();
    collect_origins_into(data, &mut set);
    set.into_iter().collect()
}

/// Parse Chromium IndexedDB directory naming (`https_example.com_0.indexeddb.leveldb`).
pub fn parse_idb_origin(lower_name: &str) -> Option<String> {
    let parts: Vec<&str> = lower_name.split(".indexeddb.").next()?.split('_').collect();
    (parts.len() >= 2 && matches!(parts[0], "http" | "https")).then_some(())?;
    let has_port = parts.len() >= 3 && parts.last()?.bytes().all(|b| b.is_ascii_digit());
    let end = parts.len() - usize::from(has_port);
    let (h, port) = (
        parts[1..end].join("_"),
        if has_port { parts[end] } else { "0" },
    );
    let url = if port == "0" {
        format!("{}://{h}", parts[0])
    } else {
        format!("{}://{h}:{port}", parts[0])
    };
    normalize_web_origin(&url)
}

/// Extract non-extension web origin owner from a Chromium CacheStorage bucket directory.
pub fn extract_cs_owner(hash_dir: &Path) -> Option<String> {
    for f in ["index.txt", "index"] {
        if let Ok(b) = fs::read(hash_dir.join(f)) {
            let t = String::from_utf8_lossy(&b).to_ascii_lowercase();
            if t.contains("chrome-extension://") || t.contains("moz-extension://") {
                return None;
            }
            if let Some(o) = extract_origins_from_bytes(&b).into_iter().next() {
                return Some(o);
            }
        }
    }
    extract_origins_from_leveldb_dir(hash_dir)
        .into_iter()
        .next()
}

fn visit_leveldb_payloads(dir: &Path, mut on_payload: impl FnMut(&[u8])) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut budget = MAX_DECOMPRESSED_BYTES;
    for entry in rd.flatten() {
        if budget == 0 {
            break;
        }
        if let Some((ext, raw)) = read_safe_leveldb_file(&entry.path(), budget) {
            if ext == "log" {
                parse_wal(&raw, &mut budget, &mut on_payload);
            } else {
                parse_sst(&raw, &mut budget, &mut on_payload);
            }
        }
    }
}

fn read_safe_leveldb_file(path: &Path, max_bytes: usize) -> Option<(String, Vec<u8>)> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.file_type().is_symlink() {
        return None;
    }
    #[cfg(windows)]
    if std::os::windows::fs::MetadataExt::file_attributes(&meta) & 0x400 != 0 {
        return None;
    }
    if path.file_name()?.to_str()?.eq_ignore_ascii_case("LOCK") {
        return None;
    }
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    (!matches!(ext.as_str(), "log" | "ldb" | "sst"))
        .then_some(())
        .is_none()
        .then_some(())?;
    let mut buf = Vec::new();
    let cap = max_bytes.min(MAX_DECOMPRESSED_BYTES) as u64;
    File::open(path)
        .ok()?
        .take(cap)
        .read_to_end(&mut buf)
        .ok()?;
    Some((ext, buf))
}

fn parse_wal(raw: &[u8], budget: &mut usize, on_payload: &mut impl FnMut(&[u8])) {
    let mut fragment = Vec::new();
    for chunk in raw.chunks(LOG_BLOCK_SIZE) {
        let mut pos = 0usize;
        while pos + LOG_HEADER_SIZE <= chunk.len() {
            let len = u16::from_le_bytes([chunk[pos + 4], chunk[pos + 5]]) as usize;
            let rec_type = chunk[pos + 6];
            if (rec_type == 0 && len == 0) || pos + LOG_HEADER_SIZE + len > chunk.len() {
                break;
            }
            let payload = &chunk[pos + LOG_HEADER_SIZE..pos + LOG_HEADER_SIZE + len];
            match rec_type {
                1 => {
                    fragment.clear();
                    *budget = budget.saturating_sub(payload.len());
                    on_payload(payload);
                }
                2 => {
                    fragment.clear();
                    if payload.len() <= *budget {
                        fragment.extend_from_slice(payload);
                    }
                }
                3 if !fragment.is_empty()
                    && fragment.len().saturating_add(payload.len()) <= *budget =>
                {
                    fragment.extend_from_slice(payload);
                }
                4 => {
                    if !fragment.is_empty()
                        && fragment.len().saturating_add(payload.len()) <= *budget
                    {
                        fragment.extend_from_slice(payload);
                        *budget = budget.saturating_sub(fragment.len());
                        on_payload(&fragment);
                    }
                    fragment.clear();
                }
                3 => fragment.clear(),
                _ => break,
            }
            pos += LOG_HEADER_SIZE + len;
        }
    }
}

fn parse_sst(raw: &[u8], budget: &mut usize, on_payload: &mut impl FnMut(&[u8])) {
    let magic = raw
        .len()
        .checked_sub(8)
        .and_then(|i| raw[i..].try_into().ok())
        .map(u64::from_le_bytes);
    if raw.len() < SST_FOOTER_SIZE || magic != Some(SST_TABLE_MAGIC) {
        *budget = budget.saturating_sub(raw.len());
        on_payload(raw);
        return;
    }
    let Some(index_block) = read_sst_index(raw, budget) else {
        return;
    };
    let mut handles = Vec::new();
    let _ = parse_block_entries(&index_block, |_k, val| {
        if let Some((d_off, d_sz, _)) = decode_block_handle(val) {
            handles.push((d_off, d_sz));
        }
    });
    for (d_off, d_sz) in handles {
        if *budget == 0 {
            break;
        }
        if let Some(data_block) = read_sst_block(raw, d_off, d_sz, budget) {
            let _ = parse_block_entries(&data_block, |k, v| {
                on_payload(k);
                on_payload(v);
            });
            on_payload(&data_block);
        }
    }
}

fn read_sst_index(raw: &[u8], budget: &mut usize) -> Option<Vec<u8>> {
    let footer_handles = &raw[raw.len() - SST_FOOTER_SIZE..raw.len() - 8];
    let (_, _, n1) = decode_block_handle(footer_handles)?;
    let (idx_off, idx_sz, _) = decode_block_handle(&footer_handles[n1..])?;
    read_sst_block(raw, idx_off, idx_sz, budget)
}

fn read_sst_block(raw: &[u8], offset: u64, size: u64, budget: &mut usize) -> Option<Vec<u8>> {
    let (off, sz) = (usize::try_from(offset).ok()?, usize::try_from(size).ok()?);
    if off.checked_add(sz)?.checked_add(5)? > raw.len() || *budget == 0 {
        return None;
    }
    let payload = &raw[off..off + sz];
    match raw[off + sz] {
        0 if payload.len() <= *budget => {
            *budget = budget.saturating_sub(payload.len());
            Some(payload.to_vec())
        }
        1 => {
            let dec = decompress_snappy_with_budget(payload, *budget).ok()?;
            *budget = budget.saturating_sub(dec.len());
            Some(dec)
        }
        _ => None,
    }
}

fn parse_block_entries(block: &[u8], mut on_entry: impl FnMut(&[u8], &[u8])) -> Option<()> {
    let tail_pos = block.len().checked_sub(4)?;
    let num_restarts = u32::from_le_bytes(block[tail_pos..].try_into().ok()?) as usize;
    let entries_end = block
        .len()
        .checked_sub(num_restarts.checked_mul(4)?.checked_add(4)?)?;
    let (mut pos, mut last_key) = (0usize, Vec::new());
    while pos < entries_end {
        let (shared, n1) = decode_varint64(&block[pos..entries_end])?;
        pos += n1;
        let (non_shared, n2) = decode_varint64(&block[pos..entries_end])?;
        pos += n2;
        let (val_len, n3) = decode_varint64(&block[pos..entries_end])?;
        pos += n3;
        let (sh, ns, vl) = (shared as usize, non_shared as usize, val_len as usize);
        let end = pos.checked_add(ns)?.checked_add(vl)?;
        if end > entries_end || sh > last_key.len() {
            break;
        }
        last_key.truncate(sh);
        last_key.extend_from_slice(&block[pos..pos + ns]);
        on_entry(&last_key, &block[pos + ns..end]);
        pos = end;
    }
    Some(())
}

fn decode_varint64(buf: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    for (i, &b) in buf.iter().take(10).enumerate() {
        result |= u64::from(b & 0x7f).checked_shl((i as u32) * 7)?;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
    }
    None
}

fn decode_block_handle(buf: &[u8]) -> Option<(u64, u64, usize)> {
    let (offset, n1) = decode_varint64(buf)?;
    let (size, n2) = decode_varint64(&buf[n1..])?;
    Some((offset, size, n1 + n2))
}

fn collect_candidate_strings(data: &[u8]) -> Vec<String> {
    let (mut res, mut start) = (Vec::new(), None);
    for (i, &b) in data.iter().enumerate() {
        if (0x21..=0x7e).contains(&b) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take().filter(|&s| i - s >= 6) {
            if let Ok(txt) = std::str::from_utf8(&data[s..i]) {
                res.push(txt.to_string());
            }
        }
    }
    if let Some(s) = start.filter(|&s| data.len() - s >= 6) {
        if let Ok(txt) = std::str::from_utf8(&data[s..]) {
            res.push(txt.to_string());
        }
    }
    for align in [0usize, 1usize] {
        let (mut u16_buf, mut idx) = (String::new(), align);
        while idx + 1 < data.len() {
            if data[idx + 1] == 0 && (0x21..=0x7e).contains(&data[idx]) {
                u16_buf.push(data[idx] as char);
            } else if u16_buf.len() >= 8 {
                res.push(std::mem::take(&mut u16_buf));
            } else {
                u16_buf.clear();
            }
            idx += 2;
        }
        if u16_buf.len() >= 8 {
            res.push(u16_buf);
        }
    }
    res
}

fn collect_origins_into(data: &[u8], out: &mut BTreeSet<String>) {
    for token in collect_candidate_strings(data) {
        let lower = token.to_ascii_lowercase();
        for scheme in ["https://", "http://"] {
            let mut from = 0usize;
            while let Some(rel) = lower[from..].find(scheme) {
                let start = from + rel;
                if start == 0 || !lower.as_bytes()[start - 1].is_ascii_alphabetic() {
                    if let Some(o) = normalize_web_origin(&lower[start..]) {
                        out.insert(o);
                    }
                }
                from = start + scheme.len();
            }
        }
    }
}

/// Normalize a candidate URL prefix into `http(s)://host[:port]`.
pub fn normalize_web_origin(raw: &str) -> Option<String> {
    let lower = raw.trim().to_ascii_lowercase();
    let (scheme, rest) = lower
        .strip_prefix("https://")
        .map(|r| ("https", r))
        .or_else(|| lower.strip_prefix("http://").map(|r| ("http", r)))?;
    let is_delim = |c: char| "/?#\"'\\<>;,)]@".contains(c) || c.is_whitespace() || c.is_control();
    let authority = &rest[..rest.find(is_delim).unwrap_or(rest.len())];
    let (host, port_opt) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p.parse::<u16>().ok().filter(|&p| p > 0)?)),
        None => (authority, None),
    };
    is_valid_origin_host(host).then_some(())?;
    match port_opt {
        Some(80) if scheme == "http" => Some(format!("http://{host}")),
        Some(443) if scheme == "https" => Some(format!("https://{host}")),
        Some(port) => Some(format!("{scheme}://{host}:{port}")),
        None => Some(format!("{scheme}://{host}")),
    }
}

fn is_valid_origin_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host == "localhost" {
        return true;
    }
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        let parts: Vec<&str> = host.split('.').collect();
        return parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok());
    }
    let valid_ch = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-';
    let valid_tld =
        |(_, t): (&str, &str)| t.len() >= 2 && t.chars().all(|c| c.is_ascii_lowercase());
    !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host.chars().all(valid_ch)
        && host.rsplit_once('.').is_some_and(valid_tld)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varint(mut n: u64, out: &mut Vec<u8>) {
        while n >= 0x80 {
            out.push(((n as u8) & 0x7f) | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
    }

    fn build_block(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (k, v) in entries {
            encode_varint(0, &mut buf);
            encode_varint(k.len() as u64, &mut buf);
            encode_varint(v.len() as u64, &mut buf);
            buf.extend_from_slice(k);
            buf.extend_from_slice(v);
        }
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf
    }

    #[test]
    fn test_wal_fragment_utf16_and_query_redaction() {
        let dir = std::env::temp_dir().join(format!("dcm-ldb-wal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("LOCK"), b"locked").unwrap();

        let p1 = b"meta:https://app.linear.app/team/secret?token=xyz987 ";
        let p2: Vec<u8> = "https://chat.openai.com:8443/c/123"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut wal = Vec::new();
        for (rtype, payload) in [(2u8, &p1[..]), (4u8, &p2[..])] {
            wal.extend_from_slice(&0u32.to_le_bytes());
            wal.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            wal.push(rtype);
            wal.extend_from_slice(payload);
        }
        fs::write(dir.join("000003.log"), &wal).unwrap();

        let origins = extract_origins_from_leveldb_dir(&dir);
        assert!(origins.contains(&"https://app.linear.app".to_string()));
        assert!(origins.contains(&"https://chat.openai.com:8443".to_string()));
        assert!(origins.iter().all(|o| !o.contains("xyz987")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sst_snappy_extraction_and_bomb_guard() {
        let dir = std::env::temp_dir().join(format!("dcm-ldb-sst-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let data_raw = build_block(&[
            (b"o1", b"https://github.com/CThawngs/Disk-Cleaner-MCP"),
            (
                b"o2",
                b"chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn/home",
            ),
        ]);
        let comp = snap::raw::Encoder::new().compress_vec(&data_raw).unwrap();
        let mut sst = Vec::new();
        sst.extend_from_slice(&comp);
        sst.push(1);
        sst.extend_from_slice(&0u32.to_le_bytes());

        let mut h = Vec::new();
        encode_varint(0, &mut h);
        encode_varint(comp.len() as u64, &mut h);
        let idx = build_block(&[(b"z", &h)]);
        let (idx_off, idx_sz) = (sst.len() as u64, idx.len() as u64);
        sst.extend_from_slice(&idx);
        sst.push(0);
        sst.extend_from_slice(&0u32.to_le_bytes());

        let mut footer = vec![0u8, 0u8];
        encode_varint(idx_off, &mut footer);
        encode_varint(idx_sz, &mut footer);
        footer.resize(40, 0);
        footer.extend_from_slice(&SST_TABLE_MAGIC.to_le_bytes());
        sst.extend_from_slice(&footer);
        fs::write(dir.join("000005.ldb"), &sst).unwrap();

        assert_eq!(
            extract_origins_from_leveldb_dir(&dir),
            vec!["https://github.com".to_string()]
        );
        let oversized = vec![b'A'; MAX_DECOMPRESSED_BYTES + 1024];
        let bomb = snap::raw::Encoder::new().compress_vec(&oversized).unwrap();
        assert!(decompress_snappy_capped(&bomb).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
