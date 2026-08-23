//! HTTP routes. Micronaut analog: `@Controller` classes + a catch-all file handler.

use crate::cache::etag_for;
use crate::client::Client;
use crate::config::Config;
use crate::ws;
use axum::body::Body;
use axum::extract::{Json, State};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use std::path::Path;
use std::sync::Arc;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};

pub struct AppState {
    pub config: Config,
    pub client: Arc<Client>,
}

pub fn router(state: Arc<AppState>) -> Router {
    let cors = if state.config.cors_any {
        CorsLayer::new().allow_origin(AllowOrigin::any())
    } else {
        let origins: Vec<_> = state
            .config
            .cors_origins
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        CorsLayer::new().allow_origin(AllowOrigin::list(origins))
    };
    let cors = cors
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
            axum::http::Method::HEAD,
        ])
        .allow_headers(tower_http::cors::Any);

    Router::new()
        .route("/api/health", get(health))
        .route("/api/health/simple", get(health_simple))
        .route("/api/cache-stats", get(cache_stats))
        .route("/api/missing-files", get(missing_files))
        .route("/api/missing-files/clear", post(clear_missing))
        .route("/api/validate", get(validate))
        .route("/api/path-mapping", get(path_mapping))
        .route("/api/warm-cache", get(warm_stats))
        .route("/api/warm-cache/run", post(warm_run))
        .route("/search", post(search))
        .route("/batch", post(batch))
        .route("/list-files", get(list_files))
        .route("/ws/{*target}", get(ws::upgrade))
        .fallback(fallback)
        .layer(CompressionLayer::new())
        .layer(cors)
        .with_state(state)
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "grfs": {
            "total": state.client.grfs.len(),
            "valid": state.client.grfs.len(),
        },
        "cache": state.client.cache.stats(),
        "index": state.client.index_stats(),
        "missingFiles": state.client.missing_summary(),
        "esrgan": { "enabled": state.config.esrgan_enabled },
    }))
}

async fn health_simple() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "status": "ok" }))
}

async fn cache_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "cache": state.client.cache.stats(),
        "index": state.client.index_stats(),
    }))
}

async fn missing_files(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    axum::Json(state.client.missing_summary())
}

async fn clear_missing(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.client.clear_missing();
    axum::Json(serde_json::json!({ "success": true, "message": "Log cleared successfully" }))
}

async fn validate(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "success": !state.client.grfs.is_empty(),
        "grfCount": state.client.grfs.len(),
        "indexKeys": state.client.index.len(),
    }))
}

async fn path_mapping(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "enabled": true,
        "entries": state.client.mapping.paths.len(),
    }))
}

async fn warm_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "cache": state.client.cache.stats(),
        "limit": state.config.cache_warm_up_limit,
    }))
}

async fn warm_run(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let n = state.client.warm_cache(state.config.cache_warm_up_limit);
    axum::Json(serde_json::json!({ "warmed": n }))
}

#[derive(Deserialize)]
struct SearchBody {
    filter: Option<String>,
}

async fn search(State(state): State<Arc<AppState>>, Json(body): Json<SearchBody>) -> Response {
    if !state.config.enable_search {
        return (StatusCode::BAD_REQUEST, "Search feature is disabled").into_response();
    }
    let Some(filter) = body.filter else {
        return (StatusCode::BAD_REQUEST, "invalid filter").into_response();
    };
    let files = state.client.search(&filter);
    files.join("\n").into_response()
}

#[derive(Deserialize)]
struct BatchBody {
    files: Vec<String>,
}

async fn batch(State(state): State<Arc<AppState>>, Json(body): Json<BatchBody>) -> Response {
    if body.files.is_empty() || body.files.len() > 50 {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": "Invalid files array (1-50 files)" })),
        )
            .into_response();
    }
    let mut map = serde_json::Map::new();
    for f in body.files {
        if let Some(bytes) = state.client.get_file(&f) {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
            map.insert(f, serde_json::Value::String(b64));
        }
    }
    axum::Json(serde_json::Value::Object(map)).into_response()
}

async fn list_files(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    axum::Json(state.client.list_files())
}

async fn fallback(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let path = req.uri().path();
    if path == "/" {
        match std::fs::read_to_string("index.html") {
            Ok(s) => {
                return ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], s).into_response();
            }
            Err(_) => {
                return (StatusCode::NOT_FOUND, "index.html not found").into_response();
            }
        }
    }

    // ESRGAN overlay
    if state.config.esrgan_enabled {
        if let Some(png) = esrgan_lookup(&state.config.esrgan_cache_dir, path) {
            return file_response(&req, path, png, true);
        }
    }

    // Static roBrowser tree
    if state.config.enable_static_serve {
        if let Some(resp) = try_static(&state.config.robrowser_path, path, req.uri().query()) {
            return resp;
        }
    }

    let rel = path.trim_start_matches('/');
    if state.config.restrict_asset_paths {
        let ok = rel.starts_with("data/")
            || rel.starts_with("data\\")
            || rel.starts_with("BGM/")
            || rel.starts_with("BGM\\");
        if !ok {
            return (StatusCode::FORBIDDEN, "Forbidden directory").into_response();
        }
    }

    if let Some(cached) = state.client.cache.get(&rel.to_lowercase()) {
        if let Some(inm) = req.headers().get(header::IF_NONE_MATCH) {
            if inm.to_str().ok() == Some(&format!("\"{}\"", cached.etag)) {
                return StatusCode::NOT_MODIFIED.into_response();
            }
        }
        return file_response_headers(rel, cached.data, false, Some(&cached.etag));
    }

    match state.client.get_file(rel) {
        Some(bytes) => file_response(&req, rel, bytes, false),
        None => {
            let mut res = (StatusCode::NOT_FOUND, "File not found").into_response();
            res.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            res
        }
    }
}

fn esrgan_lookup(dir: &Path, url_path: &str) -> Option<Vec<u8>> {
    let rel = url_path.trim_start_matches('/');
    let stem = Path::new(rel).with_extension("png");
    let p = dir.join(stem);
    std::fs::read(p).ok()
}

fn try_static(root: &Path, url_path: &str, query: Option<&str>) -> Option<Response> {
    let rel = url_path.trim_start_matches('/');
    let candidate = root.join(rel);
    let canon_root = root.canonicalize().ok()?;
    let canon = candidate.canonicalize().ok()?;
    if !canon.starts_with(&canon_root) || !canon.is_file() {
        return None;
    }
    let bytes = std::fs::read(&canon).ok()?;
    if query.map(|q| q.contains("raw")).unwrap_or(false) {
        let escaped = serde_json::to_string(&String::from_utf8_lossy(&bytes)).unwrap_or_default();
        let body = format!("export default {escaped};");
        return Some(
            (
                [
                    (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
                    (header::CACHE_CONTROL, "public, max-age=60"),
                ],
                body,
            )
                .into_response(),
        );
    }
    Some(file_response_headers(url_path, bytes, false, None))
}

fn file_response(req: &Request<Body>, path: &str, bytes: Vec<u8>, esrgan: bool) -> Response {
    let etag = etag_for(&bytes);
    if let Some(inm) = req.headers().get(header::IF_NONE_MATCH) {
        if inm.to_str().ok() == Some(&format!("\"{etag}\"")) {
            return StatusCode::NOT_MODIFIED.into_response();
        }
    }
    file_response_headers(path, bytes, esrgan, Some(&etag))
}

fn file_response_headers(path: &str, bytes: Vec<u8>, esrgan: bool, etag: Option<&str>) -> Response {
    let mime = mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_str(&mime)
            .unwrap_or(header::HeaderValue::from_static("application/octet-stream")),
    );
    if is_static_asset(path) {
        headers.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("public, max-age=86400, immutable"),
        );
        if let Some(e) = etag {
            if let Ok(v) = header::HeaderValue::from_str(&format!("\"{e}\"")) {
                headers.insert(header::ETAG, v);
            }
        }
    } else {
        headers.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-cache, no-store, must-revalidate"),
        );
    }
    if esrgan {
        headers.insert(
            "x-esrgan-upscaled",
            header::HeaderValue::from_static("true"),
        );
    }
    (headers, bytes).into_response()
}

fn is_static_asset(path: &str) -> bool {
    const EXTS: &[&str] = &[
        ".grf", ".gat", ".rsw", ".gnd", ".rsm", ".str", ".spr", ".act", ".pal", ".bmp", ".tga",
        ".jpg", ".jpeg", ".png", ".gif", ".wav", ".mp3", ".ogg", ".txt", ".xml", ".lub", ".lua",
    ];
    let lower = path.to_lowercase();
    EXTS.iter().any(|e| lower.ends_with(e))
}
