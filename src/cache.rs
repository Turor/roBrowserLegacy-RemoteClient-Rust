//! Byte-limited LRU. Micronaut equivalent: Caffeine with a weigher.

use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
pub struct CachedFile {
    pub data: Vec<u8>,
    pub etag: String, // stored so HTTP can send 304 without hashing again
}

pub fn etag_for(data: &[u8]) -> String {
    let d = md5::compute(data);
    format!("{:x}", d)[..16].to_string()
}

struct Inner {
    order: VecDeque<String>,
    map: HashMap<String, CachedFile>,
    bytes: usize,
}

pub struct LruFileCache {
    inner: Mutex<Inner>,
    max_files: usize,
    max_bytes: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl LruFileCache {
    pub fn new(max_files: usize, max_memory_mb: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                order: VecDeque::new(),
                map: HashMap::new(),
                bytes: 0,
            }),
            max_files: max_files.max(1),
            max_bytes: max_memory_mb.saturating_mul(1024 * 1024).max(1),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn get(&self, key: &str) -> Option<CachedFile> {
        let mut g = self.inner.lock();
        if g.map.contains_key(key) {
            if let Some(pos) = g.order.iter().position(|k| k == key) {
                g.order.remove(pos);
                g.order.push_back(key.to_string());
            }
            self.hits.fetch_add(1, Ordering::Relaxed);
            return g.map.get(key).cloned();
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn set(&self, key: String, data: Vec<u8>) {
        if data.len() > self.max_bytes / 10 {
            return;
        }
        let etag = etag_for(&data);
        let mut g = self.inner.lock();
        if let Some(old) = g.map.remove(&key) {
            g.bytes = g.bytes.saturating_sub(old.data.len());
            if let Some(pos) = g.order.iter().position(|k| k == &key) {
                g.order.remove(pos);
            }
        }
        while g.map.len() >= self.max_files || g.bytes + data.len() > self.max_bytes {
            if let Some(evict) = g.order.pop_front() {
                if let Some(old) = g.map.remove(&evict) {
                    g.bytes = g.bytes.saturating_sub(old.data.len());
                }
            } else {
                break;
            }
        }
        g.bytes += data.len();
        g.order.push_back(key.clone());
        g.map.insert(key, CachedFile { data, etag });
    }

    pub fn stats(&self) -> serde_json::Value {
        let g = self.inner.lock();
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total == 0 {
            "0%".into()
        } else {
            format!("{:.2}%", hits as f64 / total as f64 * 100.0)
        };
        serde_json::json!({
            "size": g.map.len(),
            "maxSize": self.max_files,
            "memoryUsedMB": format!("{:.2}", g.bytes as f64 / 1024.0 / 1024.0),
            "maxMemoryMB": format!("{}", self.max_bytes / 1024 / 1024),
            "hits": hits,
            "misses": misses,
            "hitRate": hit_rate,
        })
    }
}
