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
}
