//! Two-level data manifest (GDAT2ROOT + 256 GDAT2SHARD files).
//!
//! This process hashes the bytes it serves and writes the unsigned documents.
//! The operator signs only the root, offline. Startup verifies `root.sig`
//! with the release public key and never needs the seed.

use crate::client::Client;
use crate::grf::{FLAG_ENCRYPT_HEADER, FLAG_ENCRYPT_MIXED, FLAG_ENCRYPT_MIXED_ALT, FLAG_FILE};
use crate::paths;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use walkdir::WalkDir;

pub const RELEASE_PUBLIC_KEY_HEX: &str =
    "fb3dd3d6b9e1955ee03a4786596f7d5562b7d96d7b6c177e6d38cf7abca7de18";

const MAX_PATH_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Install {
    Kept,
    Linked,
    Wrote,
}

enum Source {
    File(PathBuf),
    Grf {
        grf_index: usize,
        entry_index: usize,
    },
}

struct Pending {
    source: Source,
    cache_key: String,
}

pub struct PublishReport {
    pub files: usize,
    pub cache_hits: usize,
    pub shards_written: usize,
    pub shards_reused: usize,
    pub root_written: bool,
}

pub fn canonical_asset_root(first: &str) -> Option<&'static str> {
    if first.eq_ignore_ascii_case("data") {
        Some("data")
    } else if first.eq_ignore_ascii_case("system") {
        Some("System")
    } else if first.eq_ignore_ascii_case("systemen") {
        Some("SystemEN")
    } else if first.eq_ignore_ascii_case("bgm") {
        Some("BGM")
    } else if first.eq_ignore_ascii_case("ai") {
        Some("AI")
    } else {
        None
    }
}

pub fn is_grf_payload(flags: u8) -> bool {
    matches!(
        flags,
        FLAG_FILE | FLAG_ENCRYPT_HEADER | FLAG_ENCRYPT_MIXED | FLAG_ENCRYPT_MIXED_ALT
    )
}

/// Directories under `root` whose names are served asset roots.
/// The prefix is the canonical server spelling (`System`, `BGM`, ...).
pub fn loose_asset_dirs(root: &Path) -> Vec<(PathBuf, &'static str)> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(root) else {
        return out;
    };
    for ent in rd.flatten() {
        if ent.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
            continue;
        }
        let Ok(ft) = ent.file_type() else {
            continue;
        };
        if !ft.is_dir() {
            continue;
        }
        let name = ent.file_name();
        let Some(prefix) = canonical_asset_root(&name.to_string_lossy()) else {
            continue;
        };
        out.push((ent.path(), prefix));
    }
    out.sort_by(|a, b| a.1.cmp(b.1).then_with(|| a.0.cmp(&b.0)));
    out
}

/// `NormalizeManifestPath`. `None` means REJECT.
pub fn normalize_manifest_path(input: &str) -> Option<String> {
    if input.chars().any(|c| {
        let u = c as u32;
        u <= 0x1f || u == 0x7f
    }) {
        return None;
    }
    let mut path = input.to_lowercase().replace('\\', "/");
    if path.starts_with('/') {
        path.remove(0);
    }
    while path.contains("//") {
        path = path.replace("//", "/");
    }
    while path.starts_with("./") {
        path = path[2..].to_string();
    }
    if path.ends_with('/') {
        path.pop();
    }
    if path == "data" {
        path.clear();
    } else if let Some(rest) = path.strip_prefix("data/") {
        path = rest.to_string();
    }
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return None;
    }
    if path.contains('\\') || path.contains(':') {
        return None;
    }
    if path
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return None;
    }
    Some(path)
}

/// Percent-decode when the input contains `%`, then normalize.
/// The exporter sees filesystem paths, which are already decoded. The
/// fixture test covers this entry point.
#[allow(dead_code)]
pub fn decode_then_normalize(input: &str) -> Option<String> {
    if !input.contains('%') {
        return normalize_manifest_path(input);
    }
    let decoded = percent_decode_strict(input)?;
    normalize_manifest_path(&decoded)
}

#[allow(dead_code)]
pub fn shard_id(normalized: &str) -> String {
    format!("{:02x}", shard_byte(normalized))
}

fn shard_byte(normalized: &str) -> u8 {
    Sha256::digest(normalized.as_bytes())[0]
}

pub fn encode_shard(version: u64, id: &str, entries: &[(String, String, u64)]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("GDAT2SHARD\n");
    out.push_str(&format!("{version}\n{id}\n{}\n", entries.len()));
    for (path, sha, size) in entries {
        out.push_str(path);
        out.push('\n');
        out.push_str(sha);
        out.push('\n');
        out.push_str(&format!("{size}\n"));
    }
    out.into_bytes()
}

pub fn encode_root(version: u64, previous: u64, created: u64, shards: &[(String, u64)]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("GDAT2ROOT\n");
    out.push_str(&format!("{version}\n{previous}\n{created}\n256\n"));
    for (i, (sha, size)) in shards.iter().enumerate() {
        out.push_str(&format!("{i:02x} {sha} {size}\n"));
    }
    out.into_bytes()
}

pub fn short_etag(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("\"{}\"", hex_encode(&digest[..8]))
}

pub fn signature_valid(root: &[u8], sig_file: &[u8]) -> bool {
    let Some(key) = decode_hex_array(RELEASE_PUBLIC_KEY_HEX) else {
        return false;
    };
    verify_with_keys(root, sig_file, &[key])
}

pub fn verify_with_keys(root: &[u8], sig_file: &[u8], keys: &[[u8; 32]]) -> bool {
    let Some(sig) = parse_detached_sig(sig_file) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig);
    for key in keys {
        if key.iter().all(|b| *b == 0) {
            continue;
        }
        let Ok(vk) = VerifyingKey::from_bytes(key) else {
            continue;
        };
        if vk.verify(root, &signature).is_ok() {
            return true;
        }
    }
    false
}

pub fn parse_detached_sig(bytes: &[u8]) -> Option<[u8; 64]> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = if let Some(stripped) = text.strip_suffix('\n') {
        stripped
    } else {
        text
    };
    if text.len() != 128 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    decode_hex_array(text)
}

/// Hash every file this process would serve and write the unsigned v2 tree
/// for `version`. Identical shard bytes are kept or hard-linked.
pub fn publish(
    client: &Client,
    state_dir: &Path,
    manifest_dir: &Path,
    version: u64,
    previous_version: u64,
) -> Result<PublishReport, String> {
    if version == 0 {
        return Err("data manifest version must be positive".into());
    }
    let pending = enumerate_served(client);
    let cache_path = state_dir.join("manifest-v2-hash-cache.jsonl");
    let mut cache = load_cache(&cache_path);
    let mut used: HashMap<String, (String, u64)> = HashMap::new();
    let mut files: BTreeMap<String, (String, u64)> = BTreeMap::new();
    let mut cache_hits = 0usize;
    let mut skipped = 0usize;
    let total = pending.len();
    for (n, (path, item)) in pending.iter().enumerate() {
        if n > 0 && n % 50_000 == 0 {
            info!(hashed = n, total, "data manifest v2 hash progress");
        }
        let (sha, size) = if let Some((sha, size)) = cache.get(&item.cache_key) {
            cache_hits += 1;
            (sha.clone(), *size)
        } else {
            let Some((sha, size)) = hash_source(client, &item.source) else {
                skipped += 1;
                if skipped <= 20 {
                    warn!(path, "skipping unreadable served file");
                }
                continue;
            };
            cache.insert(item.cache_key.clone(), (sha.clone(), size));
            (sha, size)
        };
        used.insert(item.cache_key.clone(), (sha.clone(), size));
        files.insert(path.clone(), (sha, size));
    }
    if skipped > 20 {
        warn!(skipped, "additional served files were unreadable");
    }
    save_cache(&cache_path, &used)?;

    let mut groups: Vec<Vec<(String, String, u64)>> = (0..256).map(|_| Vec::new()).collect();
    for (path, (sha, size)) in files {
        let id = shard_byte(&path) as usize;
        groups[id].push((path, sha, size));
    }

    let version_dir = manifest_dir.join(version.to_string());
    let shard_dir = version_dir.join("shards");
    fs::create_dir_all(&shard_dir).map_err(|e| e.to_string())?;
    let mut table: Vec<(String, u64)> = Vec::with_capacity(256);
    let mut shards_written = 0usize;
    let mut shards_reused = 0usize;
    // The shard version line is part of the hashed bytes and must equal the
    // root version, so a new version cannot reuse the previous file's digest.
    // Hard-link only when the full canonical bytes already match.
    for (i, entries) in groups.iter().enumerate() {
        let id = format!("{i:02x}");
        let bytes = encode_shard(version, &id, entries);
        let digest = hex_encode(Sha256::digest(&bytes).as_slice());
        let size = bytes.len() as u64;
        let dest = shard_dir.join(&id);
        let previous = if previous_version > 0 && previous_version != version {
            Some(
                manifest_dir
                    .join(previous_version.to_string())
                    .join("shards")
                    .join(&id),
            )
        } else {
            None
        };
        match install_bytes(&dest, &bytes, previous.as_deref())? {
            Install::Wrote => shards_written += 1,
            Install::Kept | Install::Linked => shards_reused += 1,
        }
        table.push((digest, size));
    }

    let root_path = version_dir.join("root");
    let root_written = match fs::read(&root_path) {
        Ok(existing) if root_shard_table_matches(&existing, version, &table) => false,
        _ => {
            let body = encode_root(version, previous_version, unix_now(), &table);
            write_atomic(&root_path, &body)?;
            true
        }
    };
    let report = PublishReport {
        files: pending.len().saturating_sub(skipped),
        cache_hits,
        shards_written,
        shards_reused,
        root_written,
    };
    info!(
        version,
        files = report.files,
        cache_hits = report.cache_hits,
        shards_written = report.shards_written,
        shards_reused = report.shards_reused,
        root_written = report.root_written,
        "data manifest v2 exported"
    );
    Ok(report)
}

fn enumerate_served(client: &Client) -> BTreeMap<String, Pending> {
    let mut map = BTreeMap::new();
    if let Some(root) = &client.config.data_version_loose_root {
        for (dir, _) in loose_asset_dirs(root) {
            let name = dir
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            walk_files(&dir, &format!("{name}/"), false, &mut map);
        }
    }
    if let Some(root) = &client.config.overlay_path {
        walk_files(root, "", true, &mut map);
    }
    if let Some(root) = &client.config.data_override_path {
        walk_files(root, "data/", false, &mut map);
    }
    for (gi, grf) in client.grfs.iter().enumerate() {
        let meta = fs::metadata(&grf.path).ok();
        let mtime = meta
            .as_ref()
            .map(mtime_string)
            .unwrap_or_else(|| "0".into());
        let alen = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let apath = grf.path.display().to_string();
        for (ei, entry) in grf.entries.iter().enumerate() {
            if !is_grf_payload(entry.flags) {
                continue;
            }
            let name = paths::decode_cp949(&entry.original_bytes);
            if !servable_request(&name) {
                continue;
            }
            let Some(key) = normalize_manifest_path(&name) else {
                continue;
            };
            if map.contains_key(&key) {
                continue;
            }
            let cache_key = json!([
                "grf",
                apath,
                mtime,
                alen,
                entry.position,
                entry.pack_size,
                entry.real_size,
                entry.flags,
                name
            ])
            .to_string();
            map.insert(
                key,
                Pending {
                    source: Source::Grf {
                        grf_index: gi,
                        entry_index: ei,
                    },
                    cache_key,
                },
            );
        }
    }
    map
}

fn walk_files(
    dir: &Path,
    request_prefix: &str,
    overlay_lookup: bool,
    map: &mut BTreeMap<String, Pending>,
) {
    if !dir.exists() {
        return;
    }
    for ent in WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| e.depth() == 0 || !e.file_name().to_string_lossy().starts_with('.'))
    {
        let Ok(ent) = ent else {
            continue;
        };
        if !ent.file_type().is_file() {
            continue;
        }
        let Ok(rel) = ent.path().strip_prefix(dir) else {
            continue;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        if rel.split('/').any(|s| s.is_empty() || s.starts_with('.')) {
            continue;
        }
        if overlay_lookup && paths::normalize(&rel) != rel {
            // The file handler joins the overlay with the lowercased request.
            continue;
        }
        let request = format!("{request_prefix}{rel}");
        if !servable_request(&request) {
            continue;
        }
        let Some(key) = normalize_manifest_path(&request) else {
            continue;
        };
        if map.contains_key(&key) {
            continue;
        }
        let Some(cache_key) = loose_cache_key(ent.path()) else {
            continue;
        };
        map.insert(
            key,
            Pending {
                source: Source::File(ent.path().to_path_buf()),
                cache_key,
            },
        );
    }
}

fn servable_request(request: &str) -> bool {
    !paths::has_hidden_or_traversal_segment(request) && paths::is_allowed_asset_path(request)
}

fn loose_cache_key(path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    Some(
        json!([
            "loose",
            path.display().to_string(),
            mtime_string(&meta),
            meta.len()
        ])
        .to_string(),
    )
}

fn hash_source(client: &Client, source: &Source) -> Option<(String, u64)> {
    match source {
        Source::File(path) => hash_file(path),
        Source::Grf {
            grf_index,
            entry_index,
        } => {
            let grf = client.grfs.get(*grf_index)?;
            let entry = grf.entries.get(*entry_index)?;
            let bytes = grf.extract(entry).ok()?;
            Some((
                hex_encode(Sha256::digest(&bytes).as_slice()),
                bytes.len() as u64,
            ))
        }
    }
}

fn hash_file(path: &Path) -> Option<(String, u64)> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Some((hex_encode(hasher.finalize().as_slice()), total))
}

fn install_bytes(dest: &Path, bytes: &[u8], previous: Option<&Path>) -> Result<Install, String> {
    if let Ok(existing) = fs::read(dest) {
        if existing == bytes {
            return Ok(Install::Kept);
        }
    }
    if let Some(prev) = previous {
        if prev != dest {
            if let Ok(old) = fs::read(prev) {
                if old == bytes {
                    if let Some(parent) = dest.parent() {
                        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                    }
                    let _ = fs::remove_file(dest);
                    if fs::hard_link(prev, dest).is_ok() {
                        return Ok(Install::Linked);
                    }
                }
            }
        }
    }
    write_atomic(dest, bytes)?;
    Ok(Install::Wrote)
}

fn root_shard_table_matches(existing: &[u8], version: u64, table: &[(String, u64)]) -> bool {
    let Ok(text) = std::str::from_utf8(existing) else {
        return false;
    };
    if text.contains('\r') || !text.ends_with('\n') || text.contains('\0') {
        return false;
    }
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 5 + 256 || lines[0] != "GDAT2ROOT" || lines[4] != "256" {
        return false;
    }
    if lines[1] != version.to_string() {
        return false;
    }
    for (i, (sha, size)) in table.iter().enumerate() {
        if lines[5 + i] != format!("{i:02x} {sha} {size}") {
            return false;
        }
    }
    true
}

fn load_cache(path: &Path) -> HashMap<String, (String, u64)> {
    let mut map = HashMap::new();
    let Ok(file) = File::open(path) else {
        return map;
    };
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(key) = value.get("k").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(sha) = value.get("h").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(size) = value.get("n").and_then(|v| v.as_u64()) else {
            continue;
        };
        if sha.len() == 64 && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            map.insert(key.to_string(), (sha.to_string(), size));
        }
    }
    map
}

fn save_cache(path: &Path, entries: &HashMap<String, (String, u64)>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut keys: Vec<&String> = entries.keys().collect();
    keys.sort();
    let mut body = String::new();
    for key in keys {
        let (sha, size) = &entries[key];
        body.push_str(&json!({"k": key, "h": sha, "n": size}).to_string());
        body.push('\n');
    }
    write_atomic(path, body.as_bytes())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp).map_err(|e| e.to_string())?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
}

fn mtime_string(meta: &fs::Metadata) -> String {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos().to_string())
        .unwrap_or_else(|| "0".into())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

#[allow(dead_code)]
fn percent_decode_strict(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = hex_val(bytes[i + 1])?;
            let lo = hex_val(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    let bytes = text.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_val(bytes[i * 2])?;
        let lo = hex_val(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;

    #[test]
    fn fixture_matches_local_normalizer() {
        let text = include_str!("../testdata/manifest-v2-normalize.txt");
        assert!(text.ends_with('\n') && !text.starts_with('\u{feff}'));
        let mut rows = 0usize;
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut cols = line.split('\t');
            let input = cols.next().expect("input");
            let expected = cols.next().expect("expected");
            let shard = cols.next().expect("shard");
            assert!(cols.next().is_none(), "extra column in {line}");
            let got = if input.contains('%') {
                decode_then_normalize(input)
            } else {
                normalize_manifest_path(input)
            };
            rows += 1;
            if expected == "REJECT" {
                assert!(got.is_none(), "expected reject for {input:?}, got {got:?}");
                assert_eq!(shard, "-");
            } else {
                let got = got.unwrap_or_else(|| panic!("expected {expected} for {input:?}"));
                assert_eq!(got, expected, "input {input:?}");
                assert_eq!(shard_id(&got), shard, "shard of {got}");
            }
        }
        assert!(rows >= 22, "fixture lost rows: {rows}");
    }

    #[test]
    fn reference_shard_digests() {
        let cases = [
            (
                "texture/abc.bmp",
                "312e1081f58d46229528909b2e9892fda39a1052c93a037164f0fbb021b58819",
            ),
            (
                "system/iteminfo.lua",
                "428c74e1539a11afbd067b4493256d9b6220476d230bf6f54187037dfcb43a9e",
            ),
            (
                "bgm/theme.mp3",
                "24e72b04ea46e23aeb0bfc7884de088b273f3486c6ae37727c6039238710577e",
            ),
            (
                "lua files/skillinfoz/skillid.lub",
                "ae1d00f9929efdea4c66b6c64c71ca414c3233546f8d2775cd5bba68dce717f5",
            ),
            (
                "data/foo",
                "0a26bd10d4064b5c0ad5d5d133ead6dea8434e88ddf9360dae0501781a52d941",
            ),
            (
                "ai/test.mtd",
                "56bb9c5237fa84479ab645b7163c8792d1f9ccb111251ebf4bc3ea39efc51d93",
            ),
            (
                "texture/유.bmp",
                "60e90ae32634d0d17bc0e7690656d36614cc07f146ae5704bea710474828567a",
            ),
            (
                "texture/유저인터페이스/login_interface/titlebar_left.bmp",
                "62a29913aeecb33cc194e310bb37535f489295251fdf6883be5d1dda4885d0fb",
            ),
        ];
        for (path, full) in cases {
            assert_eq!(hex_encode(Sha256::digest(path.as_bytes()).as_slice()), full);
            assert_eq!(shard_id(path), &full[..2]);
        }
    }

    #[test]
    fn detached_signature_accepts_one_newline_and_matching_key() {
        let seed = [7u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let message = b"GDAT2ROOT\n1\n0\n2\n256\n";
        let sig = sk.sign(message);
        let mut file = String::new();
        file.push_str(&hex_encode(&sig.to_bytes()));
        file.push('\n');
        let key = sk.verifying_key().to_bytes();
        assert!(verify_with_keys(message, file.as_bytes(), &[key]));
        assert!(verify_with_keys(
            message,
            file.trim_end_matches('\n').as_bytes(),
            &[key]
        ));
        assert!(!verify_with_keys(
            message,
            format!("{file}\n").as_bytes(),
            &[key]
        ));
        assert!(!signature_valid(message, file.as_bytes()));
        let mut upper = file.clone();
        upper.make_ascii_uppercase();
        assert!(!verify_with_keys(message, upper.as_bytes(), &[key]));
    }

    #[test]
    fn identical_shard_bytes_are_hard_linked() {
        let dir = tempfile::tempdir().unwrap();
        let prev = dir.path().join("prev");
        let dest = dir.path().join("dest");
        fs::write(&prev, b"GDAT2SHARD\n").unwrap();
        let kind = install_bytes(&dest, b"GDAT2SHARD\n", Some(&prev)).unwrap();
        assert_eq!(kind, Install::Linked);
        assert_eq!(
            fs::metadata(&dest).unwrap().ino(),
            fs::metadata(&prev).unwrap().ino()
        );
        let again = install_bytes(&dest, b"GDAT2SHARD\n", Some(&prev)).unwrap();
        assert_eq!(again, Install::Kept);
        assert_eq!(
            fs::metadata(&dest).unwrap().ino(),
            fs::metadata(&prev).unwrap().ino()
        );
    }

    #[test]
    fn sign_script_matches_dalek_and_refuses_a_bad_root() {
        let dir = tempfile::tempdir().unwrap();
        let entries = [(
            "texture/abc.bmp".into(),
            hex_encode(Sha256::digest(b"abc").as_slice()),
            3u64,
        )];
        let mut groups: Vec<Vec<(String, String, u64)>> = (0..256).map(|_| Vec::new()).collect();
        groups[0x31].push(entries[0].clone());
        let mut table = Vec::new();
        for (i, group) in groups.iter().enumerate() {
            let bytes = encode_shard(9, &format!("{i:02x}"), group);
            table.push((
                hex_encode(Sha256::digest(&bytes).as_slice()),
                bytes.len() as u64,
            ));
        }
        let root = encode_root(9, 0, 10, &table);
        let root_path = dir.path().join("root");
        fs::write(&root_path, &root).unwrap();
        let seed_path = dir.path().join("seed");
        fs::write(&seed_path, [9u8; 32]).unwrap();
        let out = dir.path().join("root.sig");
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/sign-data-root");
        let ok = Command::new("python3")
            .arg(&script)
            .arg("--private-key")
            .arg(&seed_path)
            .arg("--root")
            .arg(&root_path)
            .arg("--out")
            .arg(&out)
            .status()
            .unwrap();
        assert!(ok.success(), "sign script failed");
        let sig = fs::read(&out).unwrap();
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        assert!(verify_with_keys(
            &root,
            &sig,
            &[sk.verifying_key().to_bytes()]
        ));

        let bad = dir.path().join("bad");
        fs::write(&bad, b"GDAT2ROOT\n0\n0\n0\n256\n").unwrap();
        let bad_out = dir.path().join("bad.sig");
        let denied = Command::new("python3")
            .arg(&script)
            .arg("--private-key")
            .arg(&seed_path)
            .arg("--root")
            .arg(&bad)
            .arg("--out")
            .arg(&bad_out)
            .status()
            .unwrap();
        assert!(!denied.success());
        assert!(!bad_out.exists());

        let zero = dir.path().join("zero");
        fs::write(&zero, [0u8; 32]).unwrap();
        let denied = Command::new("python3")
            .arg(&script)
            .arg("--private-key")
            .arg(&zero)
            .arg("--root")
            .arg(&root_path)
            .arg("--out")
            .arg(dir.path().join("nope.sig"))
            .status()
            .unwrap();
        assert!(!denied.success());

        let mut with_next = root.clone();
        with_next.extend_from_slice(
            b"next-keys\n1\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        );
        let next_path = dir.path().join("root-next");
        fs::write(&next_path, &with_next).unwrap();
        let next_out = dir.path().join("next.sig");
        let ok = Command::new("python3")
            .arg(&script)
            .arg("--private-key")
            .arg(&seed_path)
            .arg("--root")
            .arg(&next_path)
            .arg("--out")
            .arg(&next_out)
            .status()
            .unwrap();
        assert!(ok.success(), "next-keys root should sign");
    }
}
