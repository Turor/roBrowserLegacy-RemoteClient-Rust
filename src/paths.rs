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
    fn korean_roundtrip_mojibake() {
        let korean = "유저인터페이스";
        let moji = to_mojibake(korean);
        assert_ne!(moji, korean);
        assert_eq!(decode_mojibake(&moji), korean);
    }

    #[test]
    fn normalize_slashes() {
        assert_eq!(normalize(r"Data\Texture\A.TGA"), "data/texture/a.tga");
    }
}
