//! Monotonic data-version stamp, change log, and operator-published signed
//! manifests. The signing seed never lives on this host.
use crate::client::Client;
use crate::config::Config;
use crate::paths;
use chrono::{Duration as ChronoDuration, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use walkdir::WalkDir;

const HEADER: &str = "x-data-version";
const MAX_CHANGE_PATHS: usize = 4000;
const RETAIN_MIN: usize = 1000;
const RETAIN_DAYS: i64 = 30;

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateFile {
    pub version: u64,
    pub snapshot: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeLine {
    pub version: u64,
    pub at: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub full: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChangesBody {
    pub version: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub full: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Fingerprint {
    kind: String,
}

struct Inner {
    version: u64,
    snapshot: String,
    files: BTreeMap<String, Fingerprint>,
    archives: BTreeMap<String, (u64, i64)>,
    changes: Vec<ChangeLine>,
}

pub struct DataVersion {
    inner: Mutex<Inner>,
    state_dir: PathBuf,
    manifest_dir: PathBuf,
    client: Arc<Client>,
}

impl DataVersion {
    pub fn start(client: Arc<Client>, config: &Config) -> Result<Arc<Self>, String> {
        let state_dir = config.data_version_state_dir.clone();
        let manifest_dir = config.data_manifest_dir.clone();
        fs::create_dir_all(&state_dir).map_err(|e| e.to_string())?;
        fs::create_dir_all(&manifest_dir).map_err(|e| e.to_string())?;
        let (state, changes) = load_state(&state_dir);
        let last_known = changes
            .last()
            .map(|c| c.version)
            .or_else(|| state.as_ref().map(|s| s.version))
            .unwrap_or(0);
        let (files, archives) = scan(&client);
        let snapshot = snapshot_hash(&files, &archives);
        let mut inner = Inner {
            version: state.as_ref().map(|s| s.version).unwrap_or(last_known),
            snapshot: state
                .as_ref()
                .map(|s| s.snapshot.clone())
                .unwrap_or_default(),
            files,
            archives,
            changes,
        };
        if inner.version == 0 {
            bump(&mut inner, &state_dir, snapshot, Vec::new(), false);
        } else if inner.snapshot != snapshot {
            bump(&mut inner, &state_dir, snapshot, Vec::new(), true);
        }
        info!(version = inner.version, "data version tracking enabled");
        Ok(Arc::new(Self {
            inner: Mutex::new(inner),
            state_dir,
            manifest_dir,
            client,
        }))
    }

    pub fn current(&self) -> u64 {
        self.inner.lock().version
    }

    pub fn header_name() -> &'static str {
        HEADER
    }

    pub fn changes_since(&self, since: u64) -> ChangesBody {
        let inner = self.inner.lock();
        let n = inner.version;
        if since == n {
            return ChangesBody {
                version: n,
                paths: Vec::new(),
                full: false,
            };
        }
        if since > n {
            return ChangesBody {
                version: n,
                paths: Vec::new(),
                full: true,
            };
        }
        let oldest = inner.changes.first().map(|c| c.version).unwrap_or(n);
        if since + 1 < oldest {
            return ChangesBody {
                version: n,
                paths: Vec::new(),
                full: true,
            };
        }
        let mut paths = BTreeSet::new();
        let mut full = false;
        for line in inner
            .changes
            .iter()
            .filter(|c| c.version > since && c.version <= n)
        {
            if line.full {
                full = true;
                break;
            }
            for p in &line.paths {
                paths.insert(p.clone());
                if paths.len() > MAX_CHANGE_PATHS {
                    full = true;
                    break;
                }
            }
            if full {
                break;
            }
        }
        if full {
            ChangesBody {
                version: n,
                paths: Vec::new(),
                full: true,
            }
        } else {
            ChangesBody {
                version: n,
                paths: paths.into_iter().collect(),
                full: false,
            }
        }
    }

    pub fn signed_manifest(&self, version: Option<u64>) -> Option<Vec<u8>> {
        let v = version.unwrap_or_else(|| self.current());
        let path = self.manifest_dir.join(format!("{v}.gdat"));
        read_regular(&path).or_else(|| read_regular(&self.manifest_dir.join("manifest.gdat")))
    }

    pub fn watch_stamp(client: &Client) -> u128 {
        let mut n = 0u128;
        let mut roots = Vec::new();
        if let Some(p) = &client.config.overlay_path {
            roots.push(p.clone());
        }
        if let Some(p) = &client.config.data_override_path {
            roots.push(p.clone());
        }
        if let Some(p) = &client.config.data_version_loose_root {
            roots.push(p.join("System"));
            roots.push(p.join("data"));
        }
        for root in roots {
            if !root.exists() {
                continue;
            }
            for ent in WalkDir::new(&root).into_iter().filter_map(|e| e.ok()) {
                if let Ok(meta) = ent.metadata() {
                    n = n.wrapping_add(meta.len() as u128);
                    if let Ok(t) = meta.modified() {
                        if let Ok(d) = t.duration_since(UNIX_EPOCH) {
                            n = n.wrapping_add(d.as_nanos());
                        }
                    }
                }
            }
        }
        for grf in &client.grfs {
            if let Ok(meta) = fs::metadata(&grf.path) {
                n = n.wrapping_add(meta.len() as u128);
                if let Ok(t) = meta.modified() {
                    if let Ok(d) = t.duration_since(UNIX_EPOCH) {
                        n = n.wrapping_add(d.as_nanos());
                    }
                }
            }
        }
        n
    }

    pub async fn watch_loop(self: Arc<Self>) {
        let mut last = Self::watch_stamp(&self.client);
        let mut dirty_at: Option<tokio::time::Instant> = None;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            let now = Self::watch_stamp(&self.client);
            if now != last {
                last = now;
                dirty_at = Some(tokio::time::Instant::now());
            }
            if let Some(t) = dirty_at {
                if t.elapsed() >= std::time::Duration::from_secs(5) {
                    self.rescan();
                    dirty_at = None;
                }
            }
        }
    }

    pub fn rescan(&self) {
        let (files, archives) = scan(&self.client);
        let snapshot = snapshot_hash(&files, &archives);
        let mut inner = self.inner.lock();
        if snapshot == inner.snapshot {
            inner.files = files;
            inner.archives = archives;
            return;
        }
        let mut full = false;
        let mut changed = BTreeSet::new();
        for (path, fp) in &files {
            match inner.files.get(path) {
                Some(old) if old == fp => {}
                _ => {
                    changed.insert(path.clone());
                }
            }
        }
        for path in inner.files.keys() {
            if !files.contains_key(path) {
                changed.insert(path.clone());
            }
        }
        for (path, ident) in &archives {
            match inner.archives.get(path) {
                Some(old) if old == ident => {}
                Some(_) => full = true,
                None => full = true,
            }
        }
        for path in inner.archives.keys() {
            if !archives.contains_key(path) {
                full = true;
            }
        }
        let paths: Vec<String> = if full {
            Vec::new()
        } else {
            changed.into_iter().collect()
        };
        inner.files = files;
        inner.archives = archives;
        bump(&mut inner, &self.state_dir, snapshot, paths, full);
    }
}

fn next_version(last: u64) -> u64 {
    last.saturating_add(1).max(unix_now().max(1))
}

fn bump(inner: &mut Inner, state_dir: &Path, snapshot: String, paths: Vec<String>, full: bool) {
    let next = next_version(inner.version);
    let line = ChangeLine {
        version: next,
        at: Utc::now().to_rfc3339(),
        paths,
        full,
    };
    inner.version = next;
    inner.snapshot = snapshot.clone();
    inner.changes.push(line.clone());
    compact_changes(&mut inner.changes);
    if let Err(e) = persist(state_dir, inner) {
        warn!("data version persist failed: {e}");
    }
    info!(
        version = next,
        full,
        paths = line.paths.len(),
        "data version bumped"
    );
}

fn compact_changes(changes: &mut Vec<ChangeLine>) {
    if changes.len() <= RETAIN_MIN {
        return;
    }
    let cutoff = Utc::now() - ChronoDuration::days(RETAIN_DAYS);
    let cutoff_s = cutoff.to_rfc3339();
    while changes.len() > RETAIN_MIN {
        if changes[0].at >= cutoff_s {
            break;
        }
        changes.remove(0);
    }
}

fn persist(state_dir: &Path, inner: &Inner) -> Result<(), String> {
    fs::create_dir_all(state_dir).map_err(|e| e.to_string())?;
    let state = StateFile {
        version: inner.version,
        snapshot: inner.snapshot.clone(),
    };
    write_atomic(
        &state_dir.join("data-version.json"),
        &serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?,
    )?;
    let mut log = String::new();
    for line in &inner.changes {
        log.push_str(&serde_json::to_string(line).map_err(|e| e.to_string())?);
        log.push('\n');
    }
    write_atomic(&state_dir.join("changes.jsonl"), log.as_bytes())?;
    Ok(())
}

fn load_state(state_dir: &Path) -> (Option<StateFile>, Vec<ChangeLine>) {
    let state: Option<StateFile> = fs::read(state_dir.join("data-version.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let mut changes = Vec::new();
    if let Ok(file) = fs::File::open(state_dir.join("changes.jsonl")) {
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(c) = serde_json::from_str::<ChangeLine>(&line) {
                changes.push(c);
            }
        }
    }
    (state, changes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(|e| e.to_string())?;
        f.write_all(bytes).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    fs::rename(tmp, path).map_err(|e| e.to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1)
}

fn snapshot_hash(
    files: &BTreeMap<String, Fingerprint>,
    archives: &BTreeMap<String, (u64, i64)>,
) -> String {
    let mut h = Sha256::new();
    for (p, fp) in files {
        h.update(p.as_bytes());
        h.update(0u8.to_be_bytes());
        h.update(fp.kind.as_bytes());
        h.update([0xff]);
    }
    for (p, (sz, mt)) in archives {
        h.update(p.as_bytes());
        h.update(sz.to_be_bytes());
        h.update(mt.to_be_bytes());
    }
    format!("{:x}", h.finalize())
}

fn scan(client: &Client) -> (BTreeMap<String, Fingerprint>, BTreeMap<String, (u64, i64)>) {
    let mut files = BTreeMap::new();
    let mut archives = BTreeMap::new();
    if let Some(root) = &client.config.overlay_path {
        collect_tree(root, "", &mut files);
    }
    if let Some(root) = &client.config.data_override_path {
        collect_tree(root, "data/", &mut files);
    }
    if let Some(root) = &client.config.data_version_loose_root {
        collect_tree(&root.join("System"), "System/", &mut files);
        collect_tree(&root.join("data"), "data/", &mut files);
    }
    for grf in &client.grfs {
        if let Ok(meta) = fs::metadata(&grf.path) {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            archives.insert(grf.path.display().to_string(), (meta.len(), mtime));
        }
        for entry in &grf.entries {
            let unicode = paths::decode_cp949(&entry.original_bytes);
            let Some(server) = server_path(&unicode) else {
                continue;
            };
            files.entry(server).or_insert_with(|| Fingerprint {
                kind: format!(
                    "grf:{}:{}:{}:{}",
                    entry.pack_size, entry.real_size, entry.position, entry.flags
                ),
            });
        }
    }
    (files, archives)
}

fn collect_tree(root: &Path, prefix: &str, files: &mut BTreeMap<String, Fingerprint>) {
    if !root.exists() {
        return;
    }
    for ent in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = ent.path();
        if !ent.file_type().is_file() {
            continue;
        }
        let rel = match path.strip_prefix(root) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        if rel.split('/').any(|s| s.starts_with('.') || s.is_empty()) {
            continue;
        }
        let server = if prefix.is_empty() {
            match server_path(&rel) {
                Some(s) => s,
                None => continue,
            }
        } else if prefix.eq_ignore_ascii_case("system/") {
            format!("System/{rel}")
        } else {
            format!("{prefix}{rel}")
        };
        if let Some(bytes) = read_regular(path) {
            files.insert(
                server,
                Fingerprint {
                    kind: format!("{:x}:{}", Sha256::digest(&bytes), bytes.len()),
                },
            );
        }
    }
}

fn server_path(name: &str) -> Option<String> {
    let n = name.replace('\\', "/");
    let (first, rest) = n.split_once('/')?;
    if rest.is_empty()
        || rest
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return None;
    }
    if first.eq_ignore_ascii_case("data") {
        Some(format!("data/{rest}"))
    } else if first.eq_ignore_ascii_case("system") {
        Some(format!("System/{rest}"))
    } else {
        None
    }
}

fn read_regular(path: &Path) -> Option<Vec<u8>> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    fs::read(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::grf::build_test_grf_200;
    use std::fs;

    fn test_client(root: &Path) -> Arc<Client> {
        fs::write(root.join("DATA.INI"), "[Data]\n0=test.grf\n").unwrap();
        fs::write(
            root.join("test.grf"),
            build_test_grf_200(&[
                ("data\\hello.txt", b"grf-hello"),
                ("data\\keep.txt", b"keep"),
            ]),
        )
        .unwrap();
        fs::create_dir_all(root.join("overlays/data")).unwrap();
        fs::write(root.join("overlays/data/hello.txt"), b"overlay-hello").unwrap();
        let mut config = Config::from_env();
        config.client_respath = root.into();
        config.client_dataini = "DATA.INI".into();
        config.overlay_path = Some(root.join("overlays"));
        config.data_override_path = None;
        config.path_mapping_file = root.join("no-mapping.json");
        config.auto_extract = false;
        config.enable_static_serve = false;
        config.enable_wsproxy = false;
        config.data_version = true;
        config.data_version_state_dir = root.join("state");
        config.data_manifest_dir = root.join("state/manifests");
        Client::init(config).unwrap()
    }

    #[test]
    fn first_version_is_unix_time_and_monotonic() {
        let root = tempfile::tempdir().unwrap();
        let client = test_client(root.path());
        let dv = DataVersion::start(client.clone(), &client.config).unwrap();
        let v1 = dv.current();
        assert!(v1 >= unix_now().saturating_sub(5));
        fs::write(root.path().join("overlays/data/hello.txt"), b"changed").unwrap();
        dv.rescan();
        let v2 = dv.current();
        assert!(v2 > v1);
        let delta = dv.changes_since(v1);
        assert!(!delta.full);
        assert!(delta.paths.iter().any(|p| p == "data/hello.txt"));
    }

    #[test]
    fn too_old_or_future_since_is_full() {
        let root = tempfile::tempdir().unwrap();
        let client = test_client(root.path());
        let dv = DataVersion::start(client.clone(), &client.config).unwrap();
        let n = dv.current();
        let old = dv.changes_since(1);
        assert!(old.full && old.version == n);
        let future = dv.changes_since(n + 10);
        assert!(future.full && future.version == n);
        let same = dv.changes_since(n);
        assert!(!same.full && same.paths.is_empty());
    }

    #[test]
    fn replaced_archive_is_full() {
        let root = tempfile::tempdir().unwrap();
        let client = test_client(root.path());
        let dv = DataVersion::start(client.clone(), &client.config).unwrap();
        let v1 = dv.current();
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(
            root.path().join("test.grf"),
            build_test_grf_200(&[
                ("data\\hello.txt", b"replaced"),
                ("data\\keep.txt", b"keep"),
            ]),
        )
        .unwrap();
        dv.rescan();
        let delta = dv.changes_since(v1);
        assert!(delta.full, "replaced GRF must be a full recheck");
    }

    #[test]
    fn serves_operator_published_manifest_without_a_key() {
        let root = tempfile::tempdir().unwrap();
        let client = test_client(root.path());
        let dv = DataVersion::start(client.clone(), &client.config).unwrap();
        let v = dv.current();
        let body = b"GDAT1SIG\ndeadbeef\nGDAT1\n";
        fs::create_dir_all(root.path().join("state/manifests")).unwrap();
        fs::write(root.path().join(format!("state/manifests/{v}.gdat")), body).unwrap();
        assert_eq!(dv.signed_manifest(None).as_deref(), Some(body.as_slice()));
        assert_eq!(
            dv.signed_manifest(Some(v)).as_deref(),
            Some(body.as_slice())
        );
    }

    #[test]
    fn restart_never_goes_backwards() {
        let root = tempfile::tempdir().unwrap();
        let client = test_client(root.path());
        let dv = DataVersion::start(client.clone(), &client.config).unwrap();
        let v1 = dv.current();
        drop(dv);
        let dv2 = DataVersion::start(client.clone(), &client.config).unwrap();
        assert!(dv2.current() >= v1);
    }

    #[tokio::test]
    async fn http_header_changes_and_version() {
        use crate::http::{router, AppState};
        use crate::metrics::HttpMetrics;
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let root = tempfile::tempdir().unwrap();
        let client = test_client(root.path());
        let dv = DataVersion::start(client.clone(), &client.config).unwrap();
        let v = dv.current();
        fs::write(
            root.path().join(format!("state/manifests/{v}.gdat")),
            b"GDAT1SIG\n00\nGDAT1\n",
        )
        .unwrap();
        let state = Arc::new(AppState {
            config: client.config.clone(),
            client: client.clone(),
            metrics: HttpMetrics::new(),
            asset_snapshot: None,
            korangar_releases: None,
            data_version: Some(dv.clone()),
        });
        let app = router(state);
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/list-files")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.headers().get(HEADER).and_then(|h| h.to_str().ok()),
            Some(v.to_string()).as_deref()
        );
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["version"], v);
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/changes?since={v}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["version"], v);
        assert!(json.get("full").is_none() || json["full"] == false);
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/changes?since=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["full"], true);
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/data-manifest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert!(body.starts_with(b"GDAT1SIG"));
    }
}
