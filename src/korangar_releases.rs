//! Presigned Garage URLs for Korangar main-channel releases.
//!
//! `GET /korangar/main/latest` (publicly `https://ro.turoran.com/client/korangar/main/latest`)
//! returns short-lived GET URLs for `main/manifest.jsonup` and the binaries it names.
//! The bucket stays private; this service holds a read-only key that is never web-served.
//!
//! `GET /goro/main/latest` (publicly `https://ro.turoran.com/client/goro/main/latest`)
//! does the same for the goro client: objects under `goro/main/` in the same bucket,
//! manifest `goro/main/manifest.goroup` (GORO1), binaries `goro-<os>-<arch>-<sha>[.exe]`.

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
const GORO_PREFIX: &str = "goro/main/";
const MANIFEST_LIMIT: usize = 256 * 1024;
const MAX_FILES: usize = 8;

type HmacSha256 = Hmac<Sha256>;

/// A release channel served from the private bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// Korangar main: `main/manifest.jsonup` (KRUP1), `korangar-*` binaries.
    Korangar,
    /// goro main: `goro/main/manifest.goroup` (GORO1), `goro-*` binaries.
    Goro,
}

impl Channel {
    fn prefix(self) -> &'static str {
        match self {
            Channel::Korangar => PREFIX,
            Channel::Goro => GORO_PREFIX,
        }
    }

    fn manifest_key(self) -> &'static str {
        match self {
            Channel::Korangar => "main/manifest.jsonup",
            Channel::Goro => "goro/main/manifest.goroup",
        }
    }

    fn magic(self) -> (&'static str, &'static str) {
        match self {
            Channel::Korangar => ("KRUP1SIG", "KRUP1"),
            Channel::Goro => ("GORO1SIG", "GORO1"),
        }
    }

    fn allows(self, name: &str) -> bool {
        match self {
            Channel::Korangar => allowed_object_name(name),
            Channel::Goro => goro_allowed_object_name(name),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Channel::Korangar => "korangar",
            Channel::Goro => "goro",
        }
    }
}

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

/// goro object name under `goro/main/`: the manifest, or
/// `goro-<linux|windows|darwin>-<amd64|arm64>-<sha>` (`.exe` only on Windows).
pub fn goro_allowed_object_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') || name.contains('%') {
        return false;
    }
    if name.contains("..") || name.starts_with('.') {
        return false;
    }
    if name == "manifest.goroup" {
        return true;
    }
    let Some(rest) = name.strip_prefix("goro-") else {
        return false;
    };
    let mut parts = rest.splitn(3, '-');
    let (Some(os), Some(arch), Some(tail)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if !matches!(arch, "amd64" | "arm64") {
        return false;
    }
    match os {
        "windows" => tail.strip_suffix(".exe").is_some_and(is_hex_sha),
        "linux" | "darwin" => is_hex_sha(tail),
        _ => false,
    }
}

pub fn object_key(name: &str) -> Option<String> {
    object_key_for(Channel::Korangar, name)
}

pub fn object_key_for(channel: Channel, name: &str) -> Option<String> {
    if !channel.allows(name) {
        return None;
    }
    Some(format!("{}{name}", channel.prefix()))
}

/// File names listed in a KRUP1 / KRUP1SIG payload. Does not verify the signature.
pub fn listed_object_names(bytes: &[u8]) -> Result<Vec<String>, String> {
    listed_object_names_for(Channel::Korangar, bytes)
}

/// File names listed in a channel's manifest. Does not verify the signature
/// (the client does); this only decides which objects may be presigned.
pub fn listed_object_names_for(channel: Channel, bytes: &[u8]) -> Result<Vec<String>, String> {
    let (envelope, payload) = channel.magic();
    let text = std::str::from_utf8(bytes).map_err(|_| "manifest is not utf-8")?;
    let mut lines = text.lines();
    let first = lines.next().ok_or("empty manifest")?;
    if first == envelope {
        let _sig = lines.next().ok_or("truncated envelope")?;
        let header = lines.next().ok_or("truncated envelope")?;
        if header != payload {
            return Err(format!("missing {payload} header"));
        }
    } else if first != payload {
        return Err(format!("not a {payload} manifest"));
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
        if !channel.allows(path) {
            return Err(format!("refusing to presign {path}"));
        }
        if !url.is_empty() && url != path && !channel.allows(url) {
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
    if key.contains('\\') || key.contains("..") || key.contains('\0') {
        return Err("refusing to presign key outside main/".into());
    }
    let allowed = [Channel::Korangar, Channel::Goro]
        .into_iter()
        .any(|channel| {
            key.strip_prefix(channel.prefix())
                .is_some_and(|name| channel.allows(name))
        });
    if !allowed {
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
        // Do not include the reqwest error display: it can contain the presigned URL.
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| "s3 get failed".to_string())?;
        if !response.status().is_success() {
            return Err(format!("s3 get status {}", response.status()));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| "s3 body read failed".to_string())?;
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
    serve_latest(&state, &headers, Channel::Korangar).await
}

/// `GET /goro/main/latest`: the goro client's catalog from the same bucket and key.
pub async fn goro_latest(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    serve_latest(&state, &headers, Channel::Goro).await
}

async fn serve_latest(state: &AppState, headers: &HeaderMap, channel: Channel) -> Response {
    let Some(svc) = state.korangar_releases.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "korangar releases not configured",
        )
            .into_response();
    };
    let ip = client_ip(headers);
    if !svc.rate.allow(ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            "rate limit",
        )
            .into_response();
    }
    match build_latest(svc, channel).await {
        Ok(body) => {
            let mut res = axum::Json(body).into_response();
            res.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            res
        }
        Err(err) => {
            tracing::warn!("{} latest failed: {err}", channel.label());
            (StatusCode::BAD_GATEWAY, "unable to presign release").into_response()
        }
    }
}

async fn build_latest(svc: &Service, channel: Channel) -> Result<LatestResponse, String> {
    let manifest_key = channel.manifest_key();
    let manifest = svc.get_object(manifest_key, MANIFEST_LIMIT).await?;
    let names = listed_object_names_for(channel, &manifest)?;
    let manifest_url = svc.presign_public(manifest_key)?;
    let mut files = Vec::with_capacity(names.len());
    for name in names {
        let key = object_key_for(channel, &name).ok_or_else(|| format!("bad name {name}"))?;
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

    const GORO_SHA: &str = "2a6f056b3707c27e9496c149fb344278eae6ca80";

    #[test]
    fn goro_object_names_are_strict() {
        assert!(goro_allowed_object_name("manifest.goroup"));
        assert!(goro_allowed_object_name(&format!(
            "goro-linux-amd64-{GORO_SHA}"
        )));
        assert!(goro_allowed_object_name(&format!(
            "goro-windows-amd64-{GORO_SHA}.exe"
        )));
        assert!(goro_allowed_object_name(&format!(
            "goro-linux-arm64-{GORO_SHA}"
        )));
        for bad in [
            "manifest.jsonup".to_string(),
            format!("korangar-linux-{GORO_SHA}"),
            format!("goro-windows-amd64-{GORO_SHA}"),
            format!("goro-linux-amd64-{GORO_SHA}.exe"),
            format!("goro-linux-x86-{GORO_SHA}"),
            format!("goro-plan9-amd64-{GORO_SHA}"),
            "goro-linux-amd64-abc".to_string(),
            "goro-linux-amd64-../x".to_string(),
            format!("goro-linux-amd64-{GORO_SHA}/x"),
            ".manifest.goroup.tmp".to_string(),
        ] {
            assert!(!goro_allowed_object_name(&bad), "should reject {bad}");
        }
        // Each channel only presigns its own names.
        assert!(!allowed_object_name("manifest.goroup"));
        assert_eq!(
            object_key_for(Channel::Goro, "manifest.goroup").as_deref(),
            Some("goro/main/manifest.goroup")
        );
        assert!(object_key_for(Channel::Goro, "manifest.jsonup").is_none());
    }

    #[test]
    fn goro_listed_names_need_goro_magic() {
        let sig = "a".repeat(128);
        let sha = "c".repeat(64);
        let linux = format!("goro-linux-amd64-{GORO_SHA}");
        let windows = format!("goro-windows-amd64-{GORO_SHA}.exe");
        let body = format!(
            "GORO1SIG\n{sig}\nGORO1\nmain-2a6f056b3707\n1794955275\n2\n{linux}\n{sha}\n10\n{linux}\n{windows}\n{sha}\n11\n{windows}\n"
        );
        assert_eq!(
            listed_object_names_for(Channel::Goro, body.as_bytes()).unwrap(),
            [linux.clone(), windows.clone()]
        );
        // A goro manifest is not a Korangar one, and the other way round.
        assert!(listed_object_names_for(Channel::Korangar, body.as_bytes()).is_err());
        let krup = body.replace("GORO1", "KRUP1");
        assert!(listed_object_names_for(Channel::Goro, krup.as_bytes()).is_err());
        let evil = body.replacen(&format!("{linux}\n{sha}"), &format!("../.env\n{sha}"), 1);
        assert!(listed_object_names_for(Channel::Goro, evil.as_bytes()).is_err());
    }

    #[test]
    fn presign_accepts_goro_prefix_only_for_goro_names() {
        let now = UNIX_EPOCH + Duration::from_secs(1_794_276_315);
        let sign = |key: &str| {
            presign_get(
                "GKTEST",
                "testsecret",
                "garage",
                "https://garage.turoran.com",
                "korangar-releases",
                key,
                600,
                now,
            )
        };
        let url = sign("goro/main/manifest.goroup").unwrap();
        assert!(url.starts_with(
            "https://garage.turoran.com/korangar-releases/goro/main/manifest.goroup?"
        ));
        assert!(sign(&format!("goro/main/goro-windows-amd64-{GORO_SHA}.exe")).is_ok());
        assert!(sign("goro/main/manifest.jsonup").is_err());
        assert!(sign(&format!("main/goro-linux-amd64-{GORO_SHA}")).is_err());
        assert!(sign(&format!("goro/main/korangar-linux-{GORO_SHA}")).is_err());
        assert!(sign("goro/main/../main/manifest.jsonup").is_err());
        assert!(sign("main/manifest.jsonup").is_ok());
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
