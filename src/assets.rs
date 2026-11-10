//! Opt-in immutable raw-asset snapshots, independent of mutable browser routes.
use crate::{client::Client, http::AppState, paths};
use axum::{
    extract::{Path as UrlPath, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

const MAX_ASSET: u64 = 100 * 1024 * 1024;
const MAX_MANIFEST: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format_version: u32,
    pub revision: String,
    pub files: Vec<AssetEntry>,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn canonical(path: &str) -> Option<String> {
    if path.starts_with(['/', '\\'])
        || path.contains(['%', ':', '?', '#'])
        || path.chars().any(char::is_control)
    {
        return None;
    }
    let path = paths::normalize(path);
    if path.split('/').any(|p| p.is_empty() || p.starts_with('.'))
        || !paths::is_allowed_asset_path(&path)
    {
        return None;
    }
    Some(path)
}
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    if !fs::symlink_metadata(path)
        .map_err(|_| "missing asset")?
        .file_type()
        .is_file()
    {
        return Err("not a regular file".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "asset open failed")?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "asset read failed")?;
    if bytes.len() as u64 > limit {
        return Err("asset too large".into());
    }
    Ok(bytes)
}
fn publish(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "snapshot write failed")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "snapshot sync failed".into())
}

/// Canonical paths and immutable blobs; arbitrary files cannot be addressed.
pub struct AssetSnapshot {
    root: PathBuf,
    manifest: Vec<u8>,
    blobs: BTreeMap<String, u64>,
}
impl AssetSnapshot {
    pub fn open(root: &Path) -> Result<Self, String> {
        let root = root
            .canonicalize()
            .map_err(|_| "invalid snapshot directory")?;
        let bytes = read_bounded(&root.join("manifest.json"), MAX_MANIFEST)?;
        let m: Manifest = serde_json::from_slice(&bytes).map_err(|_| "invalid asset manifest")?;
        if m.format_version != 1
            || m.files.is_empty()
            || !valid_digest(&m.revision)
            || digest(&serde_json::to_vec(&m.files).map_err(|_| "invalid entries")?) != m.revision
        {
            return Err("invalid snapshot revision".into());
        }
        let mut previous: Option<&str> = None;
        let mut blobs = BTreeMap::new();
        for entry in &m.files {
            if canonical(&entry.path).as_deref() != Some(&entry.path)
                || !valid_digest(&entry.sha256)
                || entry.size > MAX_ASSET
                || previous.is_some_and(|p| p >= entry.path.as_str())
            {
                return Err("invalid snapshot entry".into());
            }
            previous = Some(&entry.path);
            if let Some(old) = blobs.insert(entry.sha256.clone(), entry.size) {
                if old != entry.size {
                    return Err("inconsistent blob size".into());
                }
            }
        }
        if fs::symlink_metadata(root.join("blobs"))
            .map_err(|_| "missing blobs")?
            .file_type()
            .is_symlink()
        {
            return Err("invalid blob directory".into());
        }
        // Fail startup for missing/incomplete/tampered snapshots, not after clients install them.
        for (hash, size) in &blobs {
            let data = read_bounded(&root.join("blobs").join(hash), *size)?;
            if data.len() as u64 != *size || digest(&data) != *hash {
                return Err("snapshot integrity failure".into());
            }
        }
        Ok(Self {
            root,
            manifest: bytes,
            blobs,
        })
    }
    fn read_blob(&self, hash: &str) -> Option<Vec<u8>> {
        let size = *self.blobs.get(hash)?;
        let data = read_bounded(&self.root.join("blobs").join(hash), size).ok()?;
        (data.len() as u64 == size && digest(&data) == hash).then_some(data)
    }
}

pub async fn manifest(State(state): State<Arc<AppState>>) -> Response {
    let Some(snapshot) = &state.asset_snapshot else {
        return StatusCode::NOT_FOUND.into_response();
    };
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        snapshot.manifest.clone(),
    )
        .into_response()
}
pub async fn blob(State(state): State<Arc<AppState>>, UrlPath(hash): UrlPath<String>) -> Response {
    let Some(snapshot) = state.asset_snapshot.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !valid_digest(&hash) || !snapshot.blobs.contains_key(&hash) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match tokio::task::spawn_blocking(move || snapshot.read_blob(&hash)).await {
        Ok(Some(data)) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            data,
        )
            .into_response(),
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// Enumerate only declared asset roots. Never follow symlinks or walk the service root.
fn loose_files(root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    if fs::symlink_metadata(root)
        .map_err(|_| "invalid asset root")?
        .file_type()
        .is_symlink()
    {
        return Err("symlink asset root".into());
    }
    let root = root.canonicalize().map_err(|_| "invalid asset root")?;
    let mut out = Vec::new();
    for item in walkdir::WalkDir::new(&root).follow_links(false) {
        let item = item.map_err(|_| "asset enumeration failed")?;
        if item.file_type().is_symlink() {
            return Err("symlink in asset root".into());
        }
        if !item.file_type().is_file() {
            continue;
        }
        let rel = item
            .path()
            .strip_prefix(&root)
            .map_err(|_| "invalid asset path")?
            .to_str()
            .ok_or("non-UTF8 asset path")?;
        if let Some(path) = canonical(rel) {
            out.push((path, item.path().to_path_buf()));
        }
    }
    Ok(out)
}

/// Offline, explicit build step. Output must be a new directory. Never deploys it.
/// Raw GRF bytes, first-GRF-wins, then the same declared overlay precedence as Client.
pub fn build_snapshot(client: &Client, output: &Path) -> Result<(), String> {
    let cwd = std::env::current_dir().map_err(|_| "working directory unavailable")?;
    build_snapshot_from(client, output, &cwd)
}
fn build_snapshot_from(client: &Client, output: &Path, cwd: &Path) -> Result<(), String> {
    let mut loose: BTreeMap<String, PathBuf> = BTreeMap::new();
    // Lowest-priority loose source first. Require data_override paths to be enumerated
    // as data/ virtual files, rather than walking anything outside its configured root.
    if let Some(root) = &client.config.data_override_path {
        if root.exists() {
            for item in walkdir::WalkDir::new(root).follow_links(false) {
                let item = item.map_err(|_| "override enumeration failed")?;
                if item.file_type().is_symlink() {
                    return Err("symlink in override".into());
                }
                if item.file_type().is_file() {
                    let rel = item
                        .path()
                        .strip_prefix(root)
                        .map_err(|_| "invalid override")?
                        .to_str()
                        .ok_or("non-UTF8 override")?;
                    if let Some(p) = canonical(&format!("data/{}", rel.replace('\\', "/"))) {
                        loose.insert(p, item.path().to_path_buf());
                    }
                }
            }
        }
    }
    if let Some(root) = &client.config.overlay_path {
        for (p, file) in loose_files(root)? {
            loose.insert(p, file);
        }
    }
    for entry in fs::read_dir(&cwd).map_err(|_| "asset roots unavailable")? {
        let entry = entry.map_err(|_| "asset root entry failed")?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !paths::ALLOWED_ASSET_ROOTS
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&name))
        {
            continue;
        }
        if entry
            .file_type()
            .map_err(|_| "asset root type failed")?
            .is_symlink()
        {
            return Err("symlink asset root".into());
        }
        // The System/overlay directory contains virtual overlay roots, not public System
        // assets. Prune it below to avoid exporting the overlay tree a second time.
        for item in walkdir::WalkDir::new(entry.path())
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                !(name.eq_ignore_ascii_case("system")
                    && e.depth() == 1
                    && e.file_name() == "overlay")
            })
        {
            let item = item.map_err(|_| "asset enumeration failed")?;
            if item.file_type().is_symlink() {
                return Err("symlink in asset root".into());
            }
            if item.file_type().is_file() {
                let rel = item
                    .path()
                    .strip_prefix(&cwd)
                    .map_err(|_| "invalid loose asset")?
                    .to_str()
                    .ok_or("non-UTF8 loose asset")?;
                if let Some(p) = canonical(rel) {
                    loose.insert(p, item.path().to_path_buf());
                }
            }
        }
    }
    let mut names: BTreeSet<String> = client
        .list_files()
        .iter()
        .filter_map(|p| canonical(p))
        .collect();
    names.extend(loose.keys().cloned());
    if names.is_empty() {
        return Err("empty asset snapshot".into());
    }
    fs::create_dir(output).map_err(|_| "output must be a new directory")?;
    fs::create_dir(output.join("blobs")).map_err(|_| "blob directory failed")?;
    let mut files = Vec::new();
    for path in names {
        let bytes = if let Some(file) = loose.get(&path) {
            read_bounded(file, MAX_ASSET)?
        } else {
            let hit = client.index.get(&path).ok_or("missing indexed asset")?;
            let grf = &client.grfs[hit.grf_index];
            let bytes = grf
                .extract(&grf.entries[hit.entry_index])
                .map_err(|_| "GRF extraction failed")?;
            if bytes.len() as u64 > MAX_ASSET {
                return Err("asset too large".into());
            }
            bytes
        };
        let hash = digest(&bytes);
        let target = output.join("blobs").join(&hash);
        if !target.exists() {
            publish(&target, &bytes)?;
        }
        files.push(AssetEntry {
            path,
            size: bytes.len() as u64,
            sha256: hash,
        });
    }
    let revision = digest(&serde_json::to_vec(&files).map_err(|_| "entry serialization failed")?);
    let manifest = Manifest {
        format_version: 1,
        revision,
        files,
    };
    let bytes = serde_json::to_vec(&manifest).map_err(|_| "manifest serialization failed")?;
    if bytes.len() as u64 > MAX_MANIFEST {
        return Err("manifest too large".into());
    }
    // Published last; interrupted builds have no valid manifest and cannot be opened.
    publish(&output.join("manifest.json"), &bytes)?;
    fs::File::open(output.join("blobs"))
        .and_then(|f| f.sync_all())
        .map_err(|_| "directory sync failed")?;
    fs::File::open(output)
        .and_then(|f| f.sync_all())
        .map_err(|_| "directory sync failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(root: &Path, path: &str, content: &[u8]) {
        fs::create_dir(root.join("blobs")).unwrap();
        let hash = digest(content);
        fs::write(root.join("blobs").join(&hash), content).unwrap();
        let files = vec![AssetEntry {
            path: path.into(),
            size: content.len() as u64,
            sha256: hash,
        }];
        let revision = digest(&serde_json::to_vec(&files).unwrap());
        fs::write(
            root.join("manifest.json"),
            serde_json::to_vec(&Manifest {
                format_version: 1,
                revision,
                files,
            })
            .unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn strict_virtual_path_allowlist() {
        for p in [
            ".env",
            "src/main.rs",
            "data/../secret",
            "/data/a",
            "data//a",
            "data/.key",
            "data/%2e%2e/a",
            "C:/data/a",
            "data/a?b",
            "data/a\0",
        ] {
            assert!(canonical(p).is_none(), "{p}");
        }
        assert_eq!(
            canonical("DATA\\sprite\\test.spr").unwrap(),
            "data/sprite/test.spr"
        );
    }
    #[test]
    fn approved_blob_only_and_integrity() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), "data/test.spr", b"synthetic");
        let snapshot = AssetSnapshot::open(dir.path()).unwrap();
        assert_eq!(
            snapshot.read_blob(&digest(b"synthetic")).unwrap(),
            b"synthetic"
        );
        assert!(snapshot.read_blob("../../.env").is_none());
        assert!(snapshot.read_blob(&digest(b"not in manifest")).is_none());
        fs::write(
            dir.path().join("blobs").join(digest(b"synthetic")),
            b"corrupt",
        )
        .unwrap();
        assert!(snapshot.read_blob(&digest(b"synthetic")).is_none());
        assert!(AssetSnapshot::open(dir.path()).is_err());
    }
    #[test]
    fn forbidden_manifest_path_is_rejected_even_with_valid_revision() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), "src/main.rs", b"synthetic");
        assert!(AssetSnapshot::open(dir.path()).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn symlink_blob_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), "data/test.spr", b"synthetic");
        let hash = digest(b"synthetic");
        let blob = dir.path().join("blobs").join(hash);
        fs::remove_file(&blob).unwrap();
        let external = tempfile::NamedTempFile::new().unwrap();
        fs::write(external.path(), b"synthetic").unwrap();
        std::os::unix::fs::symlink(external.path(), blob).unwrap();
        assert!(AssetSnapshot::open(dir.path()).is_err());
    }
    #[test]
    fn incomplete_snapshot_cannot_be_served() {
        let dir = tempfile::tempdir().unwrap();
        assert!(AssetSnapshot::open(dir.path()).is_err());
    }
}
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::{config::Config, grf::build_test_grf_200, metrics::HttpMetrics};
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    fn client(root: &Path) -> Arc<Client> {
        fs::write(root.join("DATA.INI"), "[Data]\n0=first.grf\n1=second.grf\n").unwrap();
        fs::write(
            root.join("first.grf"),
            build_test_grf_200(&[
                ("data\\test.spr", b"first"),
                ("data\\overlay.act", b"grf"),
                ("src\\secret.rs", b"not public"),
            ]),
        )
        .unwrap();
        fs::write(
            root.join("second.grf"),
            build_test_grf_200(&[("data\\test.spr", b"second")]),
        )
        .unwrap();
        let mut config = Config::from_env();
        config.client_respath = root.into();
        config.client_dataini = "DATA.INI".into();
        config.overlay_path = Some(root.join("overlays"));
        config.data_override_path = None;
        config.path_mapping_file = root.join("no-mapping.json");
        config.auto_extract = false;
        config.enable_static_serve = false;
        config.enable_wsproxy = false;
        Client::init(config).unwrap()
    }
    #[test]
    fn snapshot_is_raw_first_grf_wins_with_overlays_and_no_service_files() {
        let root = tempfile::tempdir().unwrap();
        let client = client(root.path());
        fs::create_dir_all(root.path().join("overlays/data")).unwrap();
        fs::write(root.path().join("overlays/data/overlay.act"), b"overlay").unwrap();
        fs::write(root.path().join(".env"), b"secret").unwrap();
        let output = root.path().join("snapshot");
        build_snapshot_from(&client, &output, root.path()).unwrap();
        let snapshot = AssetSnapshot::open(&output).unwrap();
        let manifest: Manifest = serde_json::from_slice(&snapshot.manifest).unwrap();
        assert_eq!(
            manifest
                .files
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            ["data/overlay.act", "data/test.spr"]
        );
        assert_eq!(snapshot.read_blob(&digest(b"first")).unwrap(), b"first");
        assert_eq!(snapshot.read_blob(&digest(b"overlay")).unwrap(), b"overlay");
        assert!(snapshot.read_blob(&digest(b"not public")).is_none());
        assert!(build_snapshot_from(&client, &output, root.path()).is_err());
    }
    #[tokio::test]
    async fn routes_are_opt_in_and_only_serve_manifest_authorized_blobs() {
        let root = tempfile::tempdir().unwrap();
        let client = client(root.path());
        let output = root.path().join("snapshot");
        build_snapshot_from(&client, &output, root.path()).unwrap();
        let snapshot = Arc::new(AssetSnapshot::open(&output).unwrap());
        let state = |enabled| {
            Arc::new(AppState {
                config: client.config.clone(),
                client: client.clone(),
                metrics: HttpMetrics::new(),
                asset_snapshot: enabled,
                korangar_releases: None,
            })
        };
        let app = crate::http::router(state(Some(snapshot)));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/assets/v1/manifest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let m: Manifest = serde_json::from_slice(&body).unwrap();
        assert_eq!(m.files.len(), 2);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/assets/v1/blobs/{}", digest(b"first")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            b"first"
        );
        for path in [
            format!("/api/assets/v1/blobs/{}", digest(b"not authorized")),
            "/api/assets/v1/blobs/.env".into(),
            "/api/assets/v1/blobs/%2e%2e".into(),
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        let app = crate::http::router(state(None));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/assets/v1/manifest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
