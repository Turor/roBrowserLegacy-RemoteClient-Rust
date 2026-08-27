//! Optional InfluxDB v2 reporter for request + cache performance.

use crate::client::Client;
use crate::config::Config;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

pub struct HttpMetrics {
    pub requests: AtomicU64,
    pub errors: AtomicU64,
    pub duration_us: AtomicU64,
}

impl HttpMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            requests: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            duration_us: AtomicU64::new(0),
        })
    }
}

pub async fn track(metrics: Arc<HttpMetrics>, req: Request, next: Next) -> Response {
    let start = Instant::now();
    let res = next.run(req).await;
    let us = start.elapsed().as_micros() as u64;
    metrics.requests.fetch_add(1, Ordering::Relaxed);
    metrics.duration_us.fetch_add(us, Ordering::Relaxed);
    if res.status().is_server_error() || res.status() == StatusCode::NOT_FOUND {
        metrics.errors.fetch_add(1, Ordering::Relaxed);
    }
    res
}

pub fn spawn_reporter(config: Config, client: Arc<Client>, http: Arc<HttpMetrics>) {
    if config.influx_url.is_empty() || config.influx_token.is_empty() {
        debug!("Influx metrics disabled (INFLUX_URL / INFLUX_TOKEN unset)");
        return;
    }
    let interval = Duration::from_secs(config.influx_interval_secs.max(5));
    tokio::spawn(async move {
        let http_client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!("Influx HTTP client failed: {e}");
                return;
            }
        };
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(e) = flush(&http_client, &config, &client, &http).await {
                warn!("Influx write failed: {e}");
            }
        }
    });
}

fn lp_escape_tag(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace(' ', "\\ ")
        .replace(',', "\\,")
        .replace('=', "\\=")
}

async fn flush(
    http_client: &reqwest::Client,
    config: &Config,
    client: &Client,
    http: &HttpMetrics,
) -> Result<(), String> {
    let cache = client.cache.stats();
    let hits = cache["hits"].as_u64().unwrap_or(0);
    let misses = cache["misses"].as_u64().unwrap_or(0);
    let files = cache["size"].as_u64().unwrap_or(0);
    let mem_mb: f64 = cache["memoryUsedMB"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    let index = client.index_stats();
    let reqs = http.requests.load(Ordering::Relaxed);
    let errs = http.errors.load(Ordering::Relaxed);
    let dur = http.duration_us.load(Ordering::Relaxed);
    let avg_us = if reqs == 0 { 0 } else { dur / reqs };
    let host = lp_escape_tag(&config.influx_host);
    let line = format!(
        "rodata,host={host},service=remoteclient2 requests_total={reqs}i,errors_total={errs}i,avg_latency_us={avg_us}i,cache_hits={hits}i,cache_misses={misses}i,cache_files={files}i,cache_memory_mb={mem_mb},index_files={idx}i,grf_count={grf}i",
        idx = index.total_files,
        grf = index.grf_count,
    );
    let url = format!(
        "{}/api/v2/write?org={}&bucket={}&precision=s",
        config.influx_url.trim_end_matches('/'),
        urlencoding(&config.influx_org),
        urlencoding(&config.influx_bucket),
    );
    let res = http_client
        .post(url)
        .header("Authorization", format!("Token {}", config.influx_token))
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(line)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = res.status();
    if !status.is_success() {
        let body = res.text().await.unwrap_or_default();
        return Err(format!("HTTP {status}: {body}"));
    }
    Ok(())
}

fn urlencoding(s: &str) -> String {
    s.replace(' ', "%20")
}
