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

struct SigSeen {
    version: u64,
    fingerprint: String,
}

pub struct DataVersion {
    inner: Mutex<Inner>,
    state_dir: PathBuf,
    manifest_dir: PathBuf,
    client: Arc<Client>,
    sig_seen: Mutex<Option<SigSeen>>,
}

#[derive(Clone, Copy)]
pub enum V2Object {
    Root,
    Signature,
    Shard(u8),
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
        let (target, previous, full, do_bump) = if inner.version == 0 {
            (next_version(0), 0, false, true)
        } else if inner.snapshot != snapshot {
            (next_version(inner.version), inner.version, true, true)
        } else {
            (
                inner.version,
                previous_of(&inner.changes, inner.version),
                false,
                false,
            )
        };
        crate::manifest_v2::publish(&client, &state_dir, &manifest_dir, target, previous)
            .map_err(|e| format!("data manifest v2 export failed: {e}"))?;
        if do_bump {
            bump_to(&mut inner, &state_dir, target, snapshot, Vec::new(), full);
        }
        info!(version = inner.version, "data version tracking enabled");
        let dv = Arc::new(Self {
            inner: Mutex::new(inner),
            state_dir,
            manifest_dir,
            client,
            sig_seen: Mutex::new(None),
        });
        dv.observe_signature_file(target);
        Ok(dv)
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

    pub fn read_v2(&self, version: u64, object: V2Object) -> Option<Vec<u8>> {
        if version == 0 {
            return None;
        }
        let dir = self.manifest_dir.join(version.to_string());
        let path = match object {
            V2Object::Root => dir.join("root"),
            V2Object::Signature => dir.join("root.sig"),
            V2Object::Shard(id) => dir.join("shards").join(format!("{id:02x}")),
        };
        let bytes = read_regular(&path)?;
        if matches!(object, V2Object::Signature) {
            self.observe_signature(version, &path, &bytes);
        }
        Some(bytes)
    }

    fn observe_signature_file(&self, version: u64) {
        let path = self.manifest_dir.join(version.to_string()).join("root.sig");
        let Some(bytes) = read_regular(&path) else {
            return;
        };
        self.observe_signature(version, &path, &bytes);
    }

    fn observe_signature(&self, version: u64, path: &Path, bytes: &[u8]) {
        let mtime = fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos().to_string())
            .unwrap_or_default();
        let fingerprint = format!("{mtime}:{}:{:x}", bytes.len(), Sha256::digest(bytes));
        {
            let seen = self.sig_seen.lock();
            if let Some(prev) = seen.as_ref() {
                if prev.version == version && prev.fingerprint == fingerprint {
                    return;
                }
            }
        }
        let root = read_regular(&path.with_file_name("root")).unwrap_or_default();
        let valid = crate::manifest_v2::signature_valid(&root, bytes);
        if valid {
            info!(version, "data manifest root.sig verified");
        } else {
            warn!(version, "data manifest root.sig failed verification");
        }
        *self.sig_seen.lock() = Some(SigSeen {
            version,
            fingerprint,
        });
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
            for (dir, _) in crate::manifest_v2::loose_asset_dirs(p) {
                roots.push(dir);
            }
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
                    let dv = Arc::clone(&self);
                    let _ = tokio::task::spawn_blocking(move || dv.rescan()).await;
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
        let (paths, full) = changed_paths(&inner, &files, &archives);
        let previous = inner.version;
        let target = next_version(previous);
        drop(inner);
        if let Err(e) = crate::manifest_v2::publish(
            &self.client,
            &self.state_dir,
            &self.manifest_dir,
            target,
            previous,
        ) {
            warn!("data manifest v2 export failed: {e}");
            return;
        }
        let mut inner = self.inner.lock();
        inner.files = files;
        inner.archives = archives;
        bump_to(&mut inner, &self.state_dir, target, snapshot, paths, full);
        drop(inner);
        self.observe_signature_file(target);
    }
}

fn previous_of(changes: &[ChangeLine], version: u64) -> u64 {
    changes
        .iter()
        .rev()
        .find(|c| c.version < version)
        .map(|c| c.version)
        .unwrap_or(0)
}

fn changed_paths(
    inner: &Inner,
    files: &BTreeMap<String, Fingerprint>,
    archives: &BTreeMap<String, (u64, i64)>,
) -> (Vec<String>, bool) {
    let mut full = false;
    let mut changed = BTreeSet::new();
    for (path, fp) in files {
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
    for (path, ident) in archives {
        match inner.archives.get(path) {
            Some(old) if old == ident => {}
            _ => full = true,
        }
    }
    for path in inner.archives.keys() {
        if !archives.contains_key(path) {
            full = true;
        }
    }
    if full {
        (Vec::new(), true)
    } else {
        (changed.into_iter().collect(), false)
    }
}

fn next_version(last: u64) -> u64 {
    last.saturating_add(1).max(unix_now().max(1))
}

fn bump_to(
    inner: &mut Inner,
    state_dir: &Path,
    version: u64,
    snapshot: String,
    paths: Vec<String>,
    full: bool,
) {
    let line = ChangeLine {
        version,
        at: Utc::now().to_rfc3339(),
        paths,
        full,
    };
    inner.version = version;
    inner.snapshot = snapshot;
    inner.changes.push(line.clone());
    compact_changes(&mut inner.changes);
    if let Err(e) = persist(state_dir, inner) {
        warn!("data version persist failed: {e}");
    }
    info!(
        version,
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
    // Serve order: loose cwd trees, then overlay, then data override, then GRF.
    if let Some(root) = &client.config.data_version_loose_root {
        for (dir, prefix) in crate::manifest_v2::loose_asset_dirs(root) {
            collect_tree(&dir, &format!("{prefix}/"), &mut files);
        }
    }
    if let Some(root) = &client.config.overlay_path {
        collect_tree(root, "", &mut files);
    }
    if let Some(root) = &client.config.data_override_path {
        collect_tree(root, "data/", &mut files);
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
            if !crate::manifest_v2::is_grf_payload(entry.flags) {
                continue;
            }
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
    for ent in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| e.depth() == 0 || !e.file_name().to_string_lossy().starts_with('.'))
        .filter_map(|e| e.ok())
    {
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
        } else {
            format!("{prefix}{rel}")
        };
        if files.contains_key(&server) {
            continue;
        }
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
    let prefix = crate::manifest_v2::canonical_asset_root(first)?;
    Some(format!("{prefix}/{rest}"))
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
        config.data_version_loose_root = None;
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

    fn sha_hex(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn rich_client(root: &Path) -> Arc<Client> {
        fs::create_dir_all(root.join("BGM")).unwrap();
        fs::write(root.join("BGM/theme.mp3"), b"theme").unwrap();
        fs::write(root.join("BGM/.hidden.mp3"), b"nope").unwrap();
        fs::create_dir_all(root.join("AI")).unwrap();
        fs::write(root.join("AI/test.mtd"), b"ai-body").unwrap();
        fs::create_dir_all(root.join("System")).unwrap();
        fs::write(root.join("System/itemInfo.lua"), b"item").unwrap();
        fs::write(root.join("System/.gitkeep"), b"x").unwrap();
        fs::create_dir_all(root.join("data/texture")).unwrap();
        fs::write(root.join("data/texture/abc.bmp"), b"bmp-loose").unwrap();
        fs::create_dir_all(root.join("overrides/texture")).unwrap();
        fs::write(root.join("overrides/texture/abc.bmp"), b"override-bmp").unwrap();
        fs::write(root.join("overrides/keep.txt"), b"override-keep").unwrap();
        fs::write(root.join("DATA.INI"), "[Data]\n0=first.grf\n1=second.grf\n").unwrap();
        fs::write(
            root.join("first.grf"),
            build_test_grf_200(&[
                ("data\\hello.txt", b"grf-hello"),
                ("data\\keep.txt", b"first-keep"),
                ("data\\duel.txt", b"one"),
                ("BGM\\only-grf.mp3", b"from-grf"),
            ]),
        )
        .unwrap();
        fs::write(
            root.join("second.grf"),
            build_test_grf_200(&[
                ("data\\keep.txt", b"second-keep"),
                ("data\\duel.txt", b"two"),
                ("data\\second-only.txt", b"second"),
            ]),
        )
        .unwrap();
        fs::create_dir_all(root.join("overlays/data")).unwrap();
        fs::write(root.join("overlays/data/hello.txt"), b"overlay-hello").unwrap();
        let mut config = Config::from_env();
        config.client_respath = root.into();
        config.client_dataini = "DATA.INI".into();
        config.overlay_path = Some(root.join("overlays"));
        config.data_override_path = Some(root.join("overrides"));
        config.path_mapping_file = root.join("no-mapping.json");
        config.auto_extract = false;
        config.enable_static_serve = false;
        config.enable_wsproxy = false;
        config.data_version = true;
        config.data_version_state_dir = root.join("state");
        config.data_manifest_dir = root.join("state/manifests");
        config.data_version_loose_root = Some(root.to_path_buf());
        Client::init(config).unwrap()
    }

    fn manifest_entry(root: &Path, version: u64, key: &str) -> (String, u64) {
        let id = crate::manifest_v2::shard_id(key);
        let text = fs::read_to_string(
            root.join("state/manifests")
                .join(version.to_string())
                .join("shards")
                .join(&id),
        )
        .unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "GDAT2SHARD");
        assert_eq!(lines[1], version.to_string());
        assert_eq!(lines[2], id);
        let count: usize = lines[3].parse().unwrap();
        assert_eq!(lines.len(), 4 + count * 3);
        for i in 0..count {
            if lines[4 + i * 3] == key {
                return (
                    lines[5 + i * 3].to_string(),
                    lines[6 + i * 3].parse().unwrap(),
                );
            }
        }
        panic!("missing manifest entry {key}");
    }

    #[test]
    fn v2_hashes_served_bytes_and_keeps_identical_shards() {
        use std::os::unix::fs::MetadataExt;

        let root = tempfile::tempdir().unwrap();
        let client = rich_client(root.path());
        let dv = DataVersion::start(client.clone(), &client.config).unwrap();
        let v1 = dv.current();
        let manifest = root.path().join("state/manifests").join(v1.to_string());
        assert!(manifest.join("root").is_file());
        assert!(!manifest.join("root.sig").exists());
        for i in 0..256 {
            assert!(manifest.join("shards").join(format!("{i:02x}")).is_file());
        }
        let root_text = fs::read_to_string(manifest.join("root")).unwrap();
        let lines: Vec<&str> = root_text.lines().collect();
        assert_eq!(lines[0], "GDAT2ROOT");
        assert_eq!(lines[1], v1.to_string());
        assert_eq!(lines[2], "0");
        assert_eq!(lines[4], "256");
        assert_eq!(lines.len(), 261);
        for i in 0..256 {
            let id = format!("{i:02x}");
            let bytes = fs::read(manifest.join("shards").join(&id)).unwrap();
            let expect = format!("{id} {} {}", sha_hex(&bytes), bytes.len());
            assert_eq!(lines[5 + i], expect);
            assert!(std::str::from_utf8(&bytes)
                .unwrap()
                .starts_with("GDAT2SHARD\n"));
        }

        let (hello_sha, hello_len) = manifest_entry(root.path(), v1, "hello.txt");
        assert_eq!(hello_sha, sha_hex(b"overlay-hello"));
        assert_eq!(hello_len, b"overlay-hello".len() as u64);
        let (keep_sha, _) = manifest_entry(root.path(), v1, "keep.txt");
        assert_eq!(keep_sha, sha_hex(b"override-keep"));
        let (bmp_sha, _) = manifest_entry(root.path(), v1, "texture/abc.bmp");
        assert_eq!(bmp_sha, sha_hex(b"bmp-loose"));
        let (duel_sha, _) = manifest_entry(root.path(), v1, "duel.txt");
        assert_eq!(duel_sha, sha_hex(b"one"));
        let (grf_bgm, grf_len) = manifest_entry(root.path(), v1, "bgm/only-grf.mp3");
        assert_eq!(grf_bgm, sha_hex(b"from-grf"));
        assert_eq!(grf_len, b"from-grf".len() as u64);
        let (theme, _) = manifest_entry(root.path(), v1, "bgm/theme.mp3");
        assert_eq!(theme, sha_hex(b"theme"));
        let (ai, _) = manifest_entry(root.path(), v1, "ai/test.mtd");
        assert_eq!(ai, sha_hex(b"ai-body"));
        let (lua_sha, _) = manifest_entry(root.path(), v1, "system/iteminfo.lua");
        assert_eq!(lua_sha, sha_hex(b"item"));
        let (second_sha, _) = manifest_entry(root.path(), v1, "second-only.txt");
        assert_eq!(second_sha, sha_hex(b"second"));
        let joined = fs::read_to_string(manifest.join("shards").join("00")).unwrap()
            + &fs::read_to_string(manifest.join("root")).unwrap();
        assert!(!joined.contains(".gitkeep"));
        assert!(!joined.contains("hidden"));

        let shard31 = manifest.join("shards").join("31");
        let ino = fs::metadata(&shard31).unwrap().ino();
        let again = crate::manifest_v2::publish(
            &client,
            &client.config.data_version_state_dir,
            &client.config.data_manifest_dir,
            v1,
            0,
        )
        .unwrap();
        assert!(again.cache_hits > 0);
        assert_eq!(again.shards_written, 0);
        assert!(!again.root_written);
        assert_eq!(fs::metadata(&shard31).unwrap().ino(), ino);

        fs::write(root.path().join("System/itemInfo.lua"), b"item-2").unwrap();
        dv.rescan();
        let v2 = dv.current();
        assert!(v2 > v1);
        let root2 = fs::read_to_string(
            root.path()
                .join("state/manifests")
                .join(v2.to_string())
                .join("root"),
        )
        .unwrap();
        let lines2: Vec<&str> = root2.lines().collect();
        assert_eq!(lines2[1], v2.to_string());
        assert_eq!(lines2[2], v1.to_string());
        let (lua2, _) = manifest_entry(root.path(), v2, "system/iteminfo.lua");
        assert_eq!(lua2, sha_hex(b"item-2"));
        let (bmp2, _) = manifest_entry(root.path(), v2, "texture/abc.bmp");
        assert_eq!(bmp2, bmp_sha);
        let old_theme = fs::read(
            root.path()
                .join("state/manifests")
                .join(v1.to_string())
                .join("shards")
                .join("24"),
        )
        .unwrap();
        let new_theme = fs::read(
            root.path()
                .join("state/manifests")
                .join(v2.to_string())
                .join("shards")
                .join("24"),
        )
        .unwrap();
        assert_ne!(old_theme, new_theme);
        assert!(std::str::from_utf8(&new_theme)
            .unwrap()
            .contains(&format!("\n{v2}\n")));
    }

    #[tokio::test]
    async fn v2_http_endpoints_keep_legacy_manifest() {
        use crate::http::{router, AppState};
        use crate::metrics::HttpMetrics;
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let root = tempfile::tempdir().unwrap();
        let client = rich_client(root.path());
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
                    .uri("/data-manifest/root")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap(),
            "no-cache"
        );
        assert_eq!(
            res.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert!(res.headers().get(axum::http::header::ETAG).is_some());
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert!(body.starts_with(b"GDAT2ROOT\n"));

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/data-manifest/v/{v}/shards/31"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap(),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(res.status(), axum::http::StatusCode::OK);

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/data-manifest/v/{v}/shards/FF"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::BAD_REQUEST);
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/data-manifest/v/01/root")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::BAD_REQUEST);
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/data-manifest/v/999999/root")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::NOT_FOUND);
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/data-manifest/root.sig")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::NOT_FOUND);

        fs::write(
            root.path()
                .join("state/manifests")
                .join(v.to_string())
                .join("root.sig"),
            b"abcd\n",
        )
        .unwrap();
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/data-manifest/v/{v}/root.sig"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap(),
            "no-cache"
        );

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
