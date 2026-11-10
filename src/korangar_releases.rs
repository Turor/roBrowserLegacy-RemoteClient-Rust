//! Presigned Garage URLs for Korangar main-channel releases.
//!
//! `GET /korangar/main/latest` (publicly `https://ro.turoran.com/client/korangar/main/latest`)
//! returns short-lived GET URLs for `main/manifest.jsonup` and the binaries it names.
//! The bucket stays private; this service holds a read-only key that is never web-served.

use crate::http::AppState;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_BUCKET: &str = "korangar-releases";
const DEFAULT_PUBLIC_ENDPOINT: &str = "https://garage.turoran.com";
const DEFAULT_REGION: &str = "garage";
const DEFAULT_EXPIRES: u64 = 600;
const PREFIX: &str = "main/";
const MANIFEST_KEY: &str = "main/manifest.jsonup";
const MANIFEST_LIMIT: usize = 256 * 1024;
const MAX_FILES: usize = 8;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct Service {
    access_key: String,
    secret_key: String,
    region: String,
    bucket: String,
    public_endpoint: String,
    api_endpoint: String,
    expires_secs: u64,
    rate: Arc<RateLimit>,
    http: reqwest::Client,
}

struct RateLimit {
    window: Duration,
    max: usize,
    hits: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl RateLimit {
    fn new(max: usize, window: Duration) -> Self {
        Self {
            window,
            max,
            hits: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock();
        // Drop stale IPs occasionally so the map cannot grow without bound.
        if hits.len() > 4096 {
            hits.retain(|_, q| {
                q.back()
                    .is_some_and(|t| now.duration_since(*t) < self.window)
            });
        }
        let q = hits.entry(ip).or_default();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) >= self.window)
        {
            q.pop_front();
        }
        if q.len() >= self.max {
            return false;
        }
        q.push_back(now);
        true
    }
}

impl Service {
    pub fn from_env() -> Option<Self> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID").ok()?.trim().to_string();
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .ok()?
            .trim()
            .to_string();
        if access_key.is_empty() || secret_key.is_empty() {
            return None;
        }
        let public_endpoint = env_string("KORANGAR_S3_PUBLIC_ENDPOINT", DEFAULT_PUBLIC_ENDPOINT)
            .trim_end_matches('/')
            .to_string();
        let api_endpoint = env_string("KORANGAR_S3_API_ENDPOINT", public_endpoint.as_str())
            .trim_end_matches('/')
            .to_string();
        Some(Self {
            access_key,
            secret_key,
            region: env_string("AWS_DEFAULT_REGION", DEFAULT_REGION),
            bucket: env_string("KORANGAR_S3_BUCKET", DEFAULT_BUCKET),
            public_endpoint,
            expires_secs: env_u64("KORANGAR_PRESIGN_SECS", DEFAULT_EXPIRES).clamp(60, 3600),
            rate: Arc::new(RateLimit::new(
                env_usize("KORANGAR_PRESIGN_RATE", 30),
                Duration::from_secs(env_u64("KORANGAR_PRESIGN_RATE_WINDOW_SECS", 600)),
            )),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .https_only(api_endpoint.starts_with("https://"))
                .build()
                .ok()?,
            api_endpoint,
        })
    }

    #[cfg(test)]
    fn for_test(rate_max: usize) -> Self {
        Self {
            access_key: "GKTEST".into(),
            secret_key: "testsecret".into(),
            region: DEFAULT_REGION.into(),
            bucket: DEFAULT_BUCKET.into(),
            public_endpoint: DEFAULT_PUBLIC_ENDPOINT.into(),
            api_endpoint: DEFAULT_PUBLIC_ENDPOINT.into(),
            expires_secs: DEFAULT_EXPIRES,
            rate: Arc::new(RateLimit::new(rate_max, Duration::from_secs(600))),
            http: reqwest::Client::new(),
        }
    }
}

fn env_string(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Object name under `main/`. No slashes, no traversal, no odd characters.
pub fn allowed_object_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') || name.contains('%') {
        return false;
    }
    if name.contains("..") || name.starts_with('.') {
        return false;
    }
    if name == "manifest.jsonup" {
        return true;
    }
    if let Some(rest) = name.strip_prefix("korangar-linux-") {
        return is_hex_sha(rest);
    }
    if let Some(rest) = name.strip_prefix("korangar-windows-") {
        let rest = match rest.strip_suffix(".exe") {
            Some(r) => r,
            None => return false,
        };
        return is_hex_sha(rest);
    }
    false
}

fn is_hex_sha(s: &str) -> bool {
    let n = s.len();
    (7..=64).contains(&n) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn object_key(name: &str) -> Option<String> {
    if !allowed_object_name(name) {
        return None;
    }
    Some(format!("{PREFIX}{name}"))
}

/// File names listed in a KRUP1 / KRUP1SIG payload. Does not verify the signature.
pub fn listed_object_names(bytes: &[u8]) -> Result<Vec<String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "manifest is not utf-8")?;
    let mut lines = text.lines();
    let first = lines.next().ok_or("empty manifest")?;
    if first == "KRUP1SIG" {
        let _sig = lines.next().ok_or("truncated envelope")?;
        let header = lines.next().ok_or("truncated envelope")?;
        if header != "KRUP1" {
            return Err("missing KRUP1 header".into());
        }
    } else if first != "KRUP1" {
        return Err("not a KRUP1 manifest".into());
    }
    let _version = lines.next().ok_or("missing version")?;
    let _build = lines.next().ok_or("missing build")?;
    let count: usize = lines
        .next()
        .ok_or("missing file count")?
        .parse()
        .map_err(|_| "bad file count")?;
    if count == 0 || count > MAX_FILES {
        return Err("unsupported file count".into());
    }
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        let path = lines.next().ok_or("truncated file list")?.trim();
        let _sha = lines.next().ok_or("truncated file list")?;
        let _size = lines.next().ok_or("truncated file list")?;
        let url = lines.next().ok_or("truncated file list")?.trim();
        // Only bare, allowlisted names. Never follow a remote or traversed url.
        if !allowed_object_name(path) {
            return Err(format!("refusing to presign {path}"));
        }
        if !url.is_empty() && url != path && !allowed_object_name(url) {
            return Err(format!("refusing to presign url for {path}"));
        }
        names.push(path.to_string());
    }
    Ok(names)
}

fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let keep = matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~')
            || (b == b'/' && !encode_slash);
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex_lower(&Sha256::digest(data))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

struct Endpoint {
    host_header: String,
    origin: String,
}

fn parse_endpoint(endpoint: &str) -> Result<Endpoint, String> {
    let url = endpoint.trim().trim_end_matches('/');
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err("endpoint must be http(s)".into());
    };
    let host = rest.split('/').next().unwrap_or("").trim();
    if host.is_empty() || host.contains('@') {
        return Err("bad endpoint host".into());
    }
    Ok(Endpoint {
        host_header: host.to_string(),
        origin: format!("{scheme}://{host}"),
    })
}

/// AWS SigV4 query-string presigned GET. Path-style: `/{bucket}/{key}`.
#[allow(clippy::too_many_arguments)]
pub fn presign_get(
    access_key: &str,
    secret_key: &str,
    region: &str,
    endpoint: &str,
    bucket: &str,
    key: &str,
    expires_secs: u64,
    now: SystemTime,
) -> Result<String, String> {
    if bucket != DEFAULT_BUCKET {
        return Err("refusing to presign a bucket other than korangar-releases".into());
    }
    if !key.starts_with(PREFIX) || key.contains('\\') || key.contains("..") || key.contains('\0') {
        return Err("refusing to presign key outside main/".into());
    }
    let name = key.strip_prefix(PREFIX).unwrap_or("");
    if !allowed_object_name(name) {
        return Err("refusing to presign unexpected object name".into());
    }
    let ep = parse_endpoint(endpoint)?;
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock")?
        .as_secs();
    let amz_date = chrono::DateTime::from_timestamp(secs as i64, 0)
        .ok_or("clock")?
        .format("%Y%m%dT%H%M%SZ")
        .to_string();
    let date_stamp = &amz_date[..8];
    let credential = format!("{access_key}/{date_stamp}/{region}/s3/aws4_request");
    let expires = expires_secs.clamp(60, 3600).to_string();

    let canonical_uri = uri_encode(&format!("/{bucket}/{key}"), false);
    let mut qs = [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
        ("X-Amz-Credential", credential),
        ("X-Amz-Date", amz_date.clone()),
        ("X-Amz-Expires", expires),
        ("X-Amz-SignedHeaders", "host".to_string()),
    ];
    qs.sort_by(|a, b| a.0.cmp(b.0));
    let canonical_query = qs
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&");
    let canonical_headers = format!("host:{}\n", ep.host_header);
    let canonical_request = format!(
        "GET\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\nhost\nUNSIGNED-PAYLOAD"
    );
    let scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let date_key = hmac_sha256(
        format!("AWS4{secret_key}").as_bytes(),
        date_stamp.as_bytes(),
    );
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, b"s3");
    let signing_key = hmac_sha256(&service_key, b"aws4_request");
    let signature = hex_lower(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    Ok(format!(
        "{}/{}/{}?{canonical_query}&X-Amz-Signature={signature}",
        ep.origin, bucket, key
    ))
}

impl Service {
    fn presign_public(&self, key: &str) -> Result<String, String> {
        presign_get(
            &self.access_key,
            &self.secret_key,
            &self.region,
            &self.public_endpoint,
            &self.bucket,
            key,
            self.expires_secs,
            SystemTime::now(),
        )
    }

    async fn get_object(&self, key: &str, limit: usize) -> Result<Vec<u8>, String> {
        let url = presign_get(
            &self.access_key,
            &self.secret_key,
            &self.region,
            &self.api_endpoint,
            &self.bucket,
            key,
            120,
            SystemTime::now(),
        )?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| format!("s3 get failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("s3 get status {}", response.status()));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| format!("s3 body: {e}"))?;
        if bytes.len() > limit {
            return Err("s3 object too large".into());
        }
        Ok(bytes.to_vec())
    }
}

#[derive(Serialize)]
struct LatestResponse {
    expires_in: u64,
    manifest_url: String,
    files: Vec<FileUrl>,
}

#[derive(Serialize)]
struct FileUrl {
    path: String,
    url: String,
}

fn client_ip(headers: &HeaderMap) -> IpAddr {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    IpAddr::from([127, 0, 0, 1])
}

pub async fn latest(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(svc) = state.korangar_releases.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "korangar releases not configured",
        )
            .into_response();
    };
    let ip = client_ip(&headers);
    if !svc.rate.allow(ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            "rate limit",
        )
            .into_response();
    }
    match build_latest(svc).await {
        Ok(body) => {
            let mut res = axum::Json(body).into_response();
            res.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            res
        }
        Err(err) => {
            tracing::warn!("korangar latest failed: {err}");
            (StatusCode::BAD_GATEWAY, "unable to presign release").into_response()
        }
    }
}

async fn build_latest(svc: &Service) -> Result<LatestResponse, String> {
    let manifest = svc.get_object(MANIFEST_KEY, MANIFEST_LIMIT).await?;
    let names = listed_object_names(&manifest)?;
    let manifest_url = svc.presign_public(MANIFEST_KEY)?;
    let mut files = Vec::with_capacity(names.len());
    for name in names {
        let key = object_key(&name).ok_or_else(|| format!("bad name {name}"))?;
        files.push(FileUrl {
            path: name,
            url: svc.presign_public(&key)?,
        });
    }
    Ok(LatestResponse {
        expires_in: svc.expires_secs,
        manifest_url,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_names_are_strict() {
        assert!(allowed_object_name("manifest.jsonup"));
        assert!(allowed_object_name(
            "korangar-linux-ebc2a7a7bb0bcd67a6cd8345ada1d466fe4d3a33"
        ));
        assert!(allowed_object_name(
            "korangar-windows-ebc2a7a7bb0bcd67a6cd8345ada1d466fe4d3a33.exe"
        ));
        for bad in [
            "",
            "../manifest.jsonup",
            "main/manifest.jsonup",
            "manifest.jsonup/../x",
            ".env",
            "korangar-linux-../oops",
            "korangar-linux-not-hex!",
            "korangar-windows-abc",
            "korangar-windows-abcdefg", // missing .exe
            "korangar-linux-abc",       // too short
            "secret.txt",
            "manifest.jsonup%00",
            "korangar-linux-abcd/efghijk",
            "foo\\bar",
        ] {
            assert!(!allowed_object_name(bad), "should reject {bad}");
        }
    }

    #[test]
    fn listed_names_from_envelope() {
        let body = "\
KRUP1SIG
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
KRUP1
main-ebc2a7a7bb0b
1794276315
2
korangar-linux-ebc2a7a7bb0bcd67a6cd8345ada1d466fe4d3a33
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
10
korangar-linux-ebc2a7a7bb0bcd67a6cd8345ada1d466fe4d3a33
korangar-windows-ebc2a7a7bb0bcd67a6cd8345ada1d466fe4d3a33.exe
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
11
korangar-windows-ebc2a7a7bb0bcd67a6cd8345ada1d466fe4d3a33.exe
";
        let names = listed_object_names(body.as_bytes()).unwrap();
        assert_eq!(
            names,
            [
                "korangar-linux-ebc2a7a7bb0bcd67a6cd8345ada1d466fe4d3a33",
                "korangar-windows-ebc2a7a7bb0bcd67a6cd8345ada1d466fe4d3a33.exe"
            ]
        );
        assert!(listed_object_names(b"not a manifest").is_err());
        let evil = body.replace(
            "korangar-linux-ebc2a7a7bb0bcd67a6cd8345ada1d466fe4d3a33\n",
            "../.env\n",
        );
        assert!(listed_object_names(evil.as_bytes()).is_err());
    }

    #[test]
    fn presign_is_path_style_on_public_host() {
        let now = UNIX_EPOCH + Duration::from_secs(1_794_276_315);
        let url = presign_get(
            "GKTEST",
            "testsecret",
            "garage",
            "https://garage.turoran.com",
            "korangar-releases",
            "main/manifest.jsonup",
            600,
            now,
        )
        .unwrap();
        let parsed = reqwest::Url::parse(&url).unwrap();
        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("garage.turoran.com"));
        assert_eq!(parsed.path(), "/korangar-releases/main/manifest.jsonup");
        let q: HashMap<_, _> = parsed.query_pairs().collect();
        assert_eq!(q["X-Amz-Algorithm"], "AWS4-HMAC-SHA256");
        assert_eq!(q["X-Amz-Expires"], "600");
        assert_eq!(q["X-Amz-SignedHeaders"], "host");
        assert_eq!(q["X-Amz-Date"], "20261110T020515Z");
        assert!(q["X-Amz-Signature"].len() == 64);
        assert!(q["X-Amz-Credential"].contains("/garage/s3/aws4_request"));
        assert!(presign_get(
            "GKTEST",
            "testsecret",
            "garage",
            "https://garage.turoran.com",
            "korangar-releases",
            "main/../manifest.jsonup",
            600,
            now,
        )
        .is_err());
        assert!(presign_get(
            "GKTEST",
            "testsecret",
            "garage",
            "https://garage.turoran.com",
            "wow",
            "main/manifest.jsonup",
            600,
            now,
        )
        .is_err());
    }

    #[test]
    fn rate_limit_blocks_after_max() {
        let svc = Service::for_test(3);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(svc.rate.allow(ip));
        assert!(svc.rate.allow(ip));
        assert!(svc.rate.allow(ip));
        assert!(!svc.rate.allow(ip));
        let other: IpAddr = "203.0.113.10".parse().unwrap();
        assert!(svc.rate.allow(other));
    }
}
