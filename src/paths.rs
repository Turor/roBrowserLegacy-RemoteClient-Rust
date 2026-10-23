//! Path normalization + CP949 / Latin-1 mojibake.
//!
//! roBrowser often requests Korean dirs as CP949 bytes interpreted as ISO-8859-1:
//! `유저인터페이스` ↔ `À¯ÀúÀÎÅÍÆäÀÌ½º`

use encoding::all::WINDOWS_949;
use encoding::{DecoderTrap, EncoderTrap, Encoding};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub fn normalize(path: &str) -> String {
    path.replace('\\', "/").to_lowercase()
}

/// Top-level directories the roBrowser client legitimately requests
/// (verified against HAProxy access logs and the roBrowser source).
/// Matched case-insensitively on the first path segment.
pub const ALLOWED_ASSET_ROOTS: &[&str] = &["data", "bgm", "system", "systemen", "ai"];

/// True if any segment (split on `/` or `\\`) is hidden (starts with `.`, which also
/// covers `.` / `..` traversal segments) or the path contains a NUL byte.
/// `rel` must already be percent-decoded.
pub fn has_hidden_or_traversal_segment(rel: &str) -> bool {
    if rel.contains('\0') {
        return true;
    }
    rel.trim_start_matches(['/', '\\'])
        .split(['/', '\\'])
        .any(|seg| seg.starts_with('.'))
}

/// Allowlist for file serving: the path (already percent-decoded) must start with one
/// of [`ALLOWED_ASSET_ROOTS`] (case-insensitive), have at least one segment below it,
/// and contain no hidden or traversal segments. Anything else (`.env`, `src/`,
/// `plan.md`, `logs/`, `Cargo.toml`, GRF resources, ...) must not be served.
pub fn is_allowed_asset_path(rel: &str) -> bool {
    let rel = rel.trim_start_matches('/');
    if rel.is_empty() || has_hidden_or_traversal_segment(rel) {
        return false;
    }
    let mut segs = rel.split(['/', '\\']);
    let first = segs.next().unwrap_or("");
    let rest_non_empty = segs.any(|s| !s.is_empty());
    rest_non_empty
        && ALLOWED_ASSET_ROOTS
            .iter()
            .any(|root| first.eq_ignore_ascii_case(root))
}

/// Decode a request URI path: percent-encoding, then UTF-8 or Latin-1.
/// roBrowser may send `유저인터페이스`, `À¯Àú…`, or raw CP949 `%C0%AF…`.
pub fn decode_request_path(path: &str) -> String {
    let raw: Vec<u8> = percent_encoding::percent_decode(path.as_bytes()).collect();
    match String::from_utf8(raw.clone()) {
        Ok(s) => s,
        Err(_) => raw.into_iter().map(|b| char::from(b)).collect(),
    }
}

pub fn decode_cp949(bytes: &[u8]) -> String {
    WINDOWS_949
        .decode(bytes, DecoderTrap::Replace)
        .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
}

pub fn encode_cp949(s: &str) -> Vec<u8> {
    WINDOWS_949
        .encode(s, EncoderTrap::Replace)
        .unwrap_or_else(|_| s.as_bytes().to_vec())
}

/// CP949 bytes of `s` decoded as ISO-8859-1 (what the browser often sends).
pub fn to_mojibake(s: &str) -> String {
    let bytes = encode_cp949(s);
    bytes.iter().map(|&b| b as char).collect()
}

/// Reverse: Latin-1 string → CP949 Unicode.
pub fn decode_mojibake(s: &str) -> String {
    let bytes: Vec<u8> = s.chars().map(|c| c as u32 as u8).collect();
    decode_cp949(&bytes)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathMapping {
    #[serde(default)]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub paths: HashMap<String, String>,
}

impl PathMapping {
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn resolve(&self, requested: &str) -> Option<&str> {
        self.paths
            .get(requested)
            .map(|s| s.as_str())
            .or_else(|| {
                self.paths
                    .get(&requested.replace('/', "\\"))
                    .map(|s| s.as_str())
            })
            .or_else(|| {
                self.paths
                    .get(&requested.replace('\\', "/"))
                    .map(|s| s.as_str())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_keys_match_http_and_grf_names() {
        assert_eq!(
            normalize(r"data\texture\유저인터페이스\btn.bmp"),
            normalize("data/texture/유저인터페이스/btn.bmp")
        );
        assert_eq!(
            normalize("DATA/Texture/A.BMP"),
            "data/texture/a.bmp"
        );
    }

    #[test]
    fn korean_roundtrip_mojibake() {
        let korean = "유저인터페이스";
        let moji = to_mojibake(korean);
        assert_ne!(moji, korean);
        assert_eq!(decode_mojibake(&moji), korean);
        assert_eq!(moji, "À¯ÀúÀÎÅÍÆäÀÌ½º");
        let enc: String = moji
            .bytes()
            .map(|b| format!("%{b:02X}"))
            .collect();
        let decoded = decode_request_path(&format!("/data/texture/{enc}/scroll0down.bmp"));
        assert!(
            decode_mojibake(&decoded).contains(korean) || decoded.contains(korean),
            "decoded={decoded:?} moji={moji:?}"
        );
    }

    #[test]
    fn percent_encoded_utf8_mojibake() {
        let moji = "À¯ÀúÀÎÅÍÆäÀÌ½º";
        let enc = percent_encoding::utf8_percent_encode(moji, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
        let path = format!("/data/texture/{enc}/scroll0down.bmp");
        let decoded = decode_request_path(&path);
        assert!(
            decoded.contains(moji),
            "utf8 percent path should decode to mojibake, got {decoded}"
        );
        assert_eq!(decode_mojibake(moji), "유저인터페이스");
    }

    #[test]
    fn normalize_slashes() {
        assert_eq!(normalize(r"Data\Texture\A.TGA"), "data/texture/a.tga");
    }

    #[test]
    fn allowlist_permits_client_asset_roots() {
        for p in [
            "data/sprite/a.spr",
            "/data/texture/x.bmp",
            "DATA\\sprite\\a.spr",
            "Data/luafiles514/lua files/x.lub",
            "data\\texture\\\u{c720}\u{c800}\u{c778}\u{d130}\u{d398}\u{c774}\u{c2a4}\\a.bmp",
            "data/texture/\u{c0}\u{af}\u{c0}\u{fa}/a.bmp",
            "BGM/01.mp3",
            "bgm/01.mp3",
            "System/itemInfo.turoran.renewal11.lua",
            "System/Font/SCDream4.otf",
            "SystemEN/achievements.lub",
            "systemen/towninfo.lub",
            "AI/USER_AI/AI.lua",
            "AI/Util.lua",
            "data/foo.bar.baz",
            "data/sprite/a..b.spr",
        ] {
            assert!(is_allowed_asset_path(p), "should allow {p}");
        }
    }

    #[test]
    fn allowlist_denies_dotfiles_configs_and_traversal() {
        for p in [
            "",
            "/",
            ".env",
            "/.env",
            ".ENV",
            ".Env.Test",
            ".env.test",
            ".env.bak-pre0716-20261016_164532",
            ".git/config",
            ".gitignore",
            "src/main.rs",
            "src/http.rs",
            "plan.md",
            "README.md",
            "Cargo.toml",
            "Cargo.lock",
            "path-mapping.json",
            "index.html",
            "logs/missing-files.log",
            "backups/x",
            "resources/data.grf",
            "target/release/remoteclient2",
            "tests/live_ecosystem.rs",
            "overlay-0716/x.lub",
            "data",
            "data/",
            "BGM",
            "data/.hidden",
            "data/.HTACCESS",
            "data/../.env",
            "data\\..\\.env",
            "data/sub/../../src/main.rs",
            "System/.git/config",
            "AI/.env",
            "data/a\0.spr",
            "\\.env",
            "//.env",
            "dataX/a.spr",
            "systemx/a.lub",
            "/etc/passwd",
        ] {
            assert!(!is_allowed_asset_path(p), "should deny {p:?}");
        }
    }

    #[test]
    fn allowlist_applies_after_percent_decoding() {
        for raw in ["/%2eenv", "/%2Eenv", "/data/%2e%2e/.env", "/data/..%5c.env", "/data%2f..%2f.env", "/%2e%65nv"] {
            let d = decode_request_path(raw);
            assert!(!is_allowed_asset_path(&d), "should deny {raw} -> {d:?}");
        }
        let d = decode_request_path("/data/texture/%C0%AF%C0%FA/a.bmp");
        assert!(is_allowed_asset_path(&d));
    }
}
