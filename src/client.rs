//! File lookup: cache → disk → override → GRF index → mapping → miss.
//! Micronaut analog: a `@Singleton` service injected into controllers.

use crate::cache::LruFileCache;
use crate::config::Config;
use crate::grf::GrfArchive;
use crate::ini;
use crate::paths::{self, PathMapping};
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Clone)]
pub struct IndexHit {
    pub grf_index: usize,
    pub entry_index: usize,
}

pub struct Client {
    pub config: Config,
    pub grfs: Vec<GrfArchive>,
    /// Normalized path → first GRF that contains it.
    pub index: HashMap<String, IndexHit>,
    pub cache: LruFileCache,
    pub mapping: PathMapping,
    missing: Mutex<Vec<serde_json::Value>>,
    missing_set: Mutex<HashSet<String>>,
}

#[derive(Serialize)]
pub struct IndexStats {
    pub total_files: usize,
    pub grf_count: usize,
    pub index_built: bool,
}

impl Client {
    pub fn init(config: Config) -> Result<Arc<Self>, String> {
        let ini_path = config.client_respath.join(&config.client_dataini);
        if !ini_path.exists() {
            return Err(format!("DATA.INI not found: {}", ini_path.display()));
        }
        let text = fs::read_to_string(&ini_path).map_err(|e| e.to_string())?;
        let grf_names = ini::parse_data_ini(&text);
        if grf_names.is_empty() {
            warn!("No GRF files listed in DATA.INI");
        }

        let mut grfs = Vec::new();
        for name in &grf_names {
            let path = config.client_respath.join(name);
            match GrfArchive::open(&path) {
                Ok(g) => {
                    info!(
                        "Loaded GRF {} (0x{:x}, {} files)",
                        g.filename,
                        g.version,
                        g.entries.len()
                    );
                    grfs.push(g);
                }
                Err(e) => warn!("Skipping {}: {e}", path.display()),
            }
        }

        tracing::debug!("GRF filename encoding: {}", config.grf_encoding);
        let mapping = PathMapping::load(&config.path_mapping_file);
        let mut client = Self {
            cache: LruFileCache::new(config.cache_max_files, config.cache_max_memory_mb),
            config,
            grfs,
            index: HashMap::new(),
            mapping,
            missing: Mutex::new(Vec::new()),
            missing_set: Mutex::new(HashSet::new()),
        };
        client.build_index();
        Ok(Arc::new(client))
    }

    fn insert_index_key(&mut self, key: String, hit: IndexHit) {
        self.index.entry(key).or_insert(hit);
    }

    fn build_index(&mut self) {
        let mut mojibake = 0usize;
        let mut pending: Vec<(String, IndexHit)> = Vec::new();
        for (gi, grf) in self.grfs.iter().enumerate() {
            for (ei, entry) in grf.entries.iter().enumerate() {
                let unicode = paths::decode_cp949(&entry.original_bytes);
                let hit = IndexHit {
                    grf_index: gi,
                    entry_index: ei,
                };
                pending.push((paths::normalize(&unicode), hit.clone()));
                pending.push((paths::normalize(&entry.original_name), hit.clone()));

                let moji = paths::to_mojibake(&unicode);
                if moji != unicode {
                    pending.push((paths::normalize(&moji), hit.clone()));
                    mojibake += 1;
                }
            }
        }
        for (k, hit) in pending {
            self.insert_index_key(k, hit);
        }
        let mapped: Vec<(String, String)> = self
            .mapping
            .paths
            .iter()
            .map(|(a, b)| (a.clone(), b.clone()))
            .collect();
        for (korean, grf_path) in mapped {
            if let Some(hit) = self.index.get(&paths::normalize(&grf_path)).cloned() {
                self.insert_index_key(paths::normalize(&korean), hit);
            }
        }
        info!(
            "File index: {} keys from {} GRFs ({} mojibake variants)",
            self.index.len(),
            self.grfs.len(),
            mojibake
        );
    }

    pub fn index_stats(&self) -> IndexStats {
        IndexStats {
            total_files: self.index.len(),
            grf_count: self.grfs.len(),
            index_built: true,
        }
    }

    pub fn list_files(&self) -> Vec<String> {
        let mut set = HashSet::new();
        for grf in &self.grfs {
            for e in &grf.entries {
                set.insert(paths::decode_cp949(&e.original_bytes));
            }
        }
        let mut v: Vec<_> = set.into_iter().collect();
        v.sort();
        v
    }

    pub fn search(&self, pattern: &str) -> Vec<String> {
        if !self.config.enable_search {
            return Vec::new();
        }
        let re = match regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .size_limit(1_000_000)
            .build()
        {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        self.list_files()
            .into_iter()
            .filter(|f| re.is_match(f))
            .take(5000)
            .collect()
    }

    pub fn get_file(&self, requested: &str) -> Option<Vec<u8>> {
        let requested = crate::paths::decode_request_path(requested);
        let requested = requested.as_str();
        let cache_key = paths::normalize(requested);
        if let Some(hit) = self.cache.get(&cache_key) {
            return Some(hit.data);
        }

        let rel = requested.trim_start_matches('/');
        if let Some(bytes) = read_if_file(Path::new(rel)) {
            self.cache.set(cache_key, bytes.clone());
            return Some(bytes);
        }

        if let Some(over) = &self.config.data_override_path {
            let stripped = rel
                .strip_prefix("data/")
                .or_else(|| rel.strip_prefix("data\\"))
                .unwrap_or(rel);
            if let Some(bytes) = read_if_file(&over.join(stripped)) {
                self.cache.set(cache_key, bytes.clone());
                return Some(bytes);
            }
        }

        if let Some(bytes) = self.from_index(requested) {
            let mut bytes = bytes;
            if self.config.convert_bmp && rel.to_ascii_lowercase().ends_with(".bmp") {
                if let Some(png) = crate::bmp::bmp_to_png(&bytes) {
                    bytes = png;
                }
            }
            if self.config.auto_extract {
                self.extract_to_disk(rel, &bytes);
            }
            self.cache.set(cache_key, bytes.clone());
            return Some(bytes);
        }

        self.log_missing(requested);
        None
    }

    fn from_index(&self, requested: &str) -> Option<Vec<u8>> {
        let mut keys = vec![paths::normalize(requested)];
        let decoded = paths::decode_mojibake(requested);
        if decoded != requested {
            keys.push(paths::normalize(&decoded));
        }
        if let Some(mapped) = self.mapping.resolve(requested) {
            keys.push(paths::normalize(mapped));
        }

        for k in keys {
            if let Some(hit) = self.index.get(&k) {
                let grf = self.grfs.get(hit.grf_index)?;
                let entry = grf.entries.get(hit.entry_index)?;
                if let Ok(bytes) = grf.extract(entry) {
                    return Some(bytes);
                }
            }
        }

        // Sequential fallback (rare).
        let needle = requested.replace('/', "\\");
        for grf in &self.grfs {
            for entry in &grf.entries {
                if entry.original_name.eq_ignore_ascii_case(&needle)
                    || paths::normalize(&entry.original_name) == paths::normalize(requested)
                {
                    if let Ok(bytes) = grf.extract(entry) {
                        return Some(bytes);
                    }
                }
            }
        }
        None
    }

    fn extract_to_disk(&self, rel: &str, bytes: &[u8]) {
        let path = PathBuf::from(rel);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, bytes);
    }

    fn log_missing(&self, requested: &str) {
        {
            let mut set = self.missing_set.lock();
            if !set.insert(requested.to_string()) {
                return;
            }
        }
        let entry = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "requestedPath": requested,
        });
        {
            let mut v = self.missing.lock();
            v.push(entry.clone());
            if v.len() > 1000 {
                v.remove(0);
            }
        }
        if let Some(parent) = self.config.missing_log_file.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.missing_log_file)
        {
            let _ = writeln!(f, "{entry}");
        }
    }

    pub fn missing_summary(&self) -> serde_json::Value {
        let v = self.missing.lock();
        serde_json::json!({
            "total": v.len(),
            "files": v.iter().rev().take(50).cloned().collect::<Vec<_>>(),
            "logFile": self.config.missing_log_file,
        })
    }

    pub fn clear_missing(&self) {
        self.missing.lock().clear();
        self.missing_set.lock().clear();
        let _ = fs::write(&self.config.missing_log_file, b"");
    }

    pub fn warm_cache(&self, limit: usize) -> usize {
        let patterns = [
            "userinterface",
            "유저인터페이스",
            "loading",
            "cardbmp",
            "prontera.gat",
            "prontera.gnd",
            "prontera.rsw",
            ".pal",
            ".lub",
        ];
        let mut n = 0usize;
        for grf in &self.grfs {
            for entry in &grf.entries {
                if n >= limit {
                    return n;
                }
                let name = paths::decode_cp949(&entry.original_bytes);
                if patterns.iter().any(|p| name.to_lowercase().contains(p)) {
                    if let Ok(bytes) = grf.extract(entry) {
                        self.cache.set(paths::normalize(&name), bytes);
                        n += 1;
                    }
                }
            }
        }
        n
    }
}

fn read_if_file(path: &Path) -> Option<Vec<u8>> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    fs::read(path).ok()
}
