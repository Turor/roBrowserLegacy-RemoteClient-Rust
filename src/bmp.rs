//! Optional RO BMP → PNG (magenta 255,0,255 is transparent). Opt-in via CONVERT_BMP.

/// Returns PNG bytes if conversion succeeds; otherwise None (caller keeps BMP).
#[allow(dead_code)]
pub fn bmp_to_png(_bmp: &[u8]) -> Option<Vec<u8>> {
    // Full DIB encoder is large; v1 keeps original BMP unless we add `image` later.
    // Hook exists so CONVERT_BMP can be wired without changing lookup.
    None
}
