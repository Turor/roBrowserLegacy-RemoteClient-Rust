//! Runtime config from environment variables.
//! In Micronaut this would be `@ConfigurationProperties` + `application.yml`.

use std::path::PathBuf;

fn env_string(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => default,
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub cors_any: bool,
    pub cors_origins: Vec<String>,
    pub client_respath: PathBuf,
    pub client_dataini: String,
    pub auto_extract: bool,
    pub enable_search: bool,
    pub grf_encoding: String,
    pub cache_max_files: usize,
    pub cache_max_memory_mb: usize,
    pub cache_warm_up: bool,
    pub cache_warm_up_limit: usize,
    pub enable_wsproxy: bool,
    pub ws_allowed_targets: Vec<String>,
    pub enable_static_serve: bool,
    pub robrowser_path: PathBuf,
    pub data_override_path: Option<PathBuf>,
    pub path_mapping_file: PathBuf,
    pub convert_bmp: bool,
    pub restrict_asset_paths: bool,
    pub esrgan_enabled: bool,
    pub esrgan_cache_dir: PathBuf,
    pub missing_log_file: PathBuf,
}

impl Config {
    pub fn from_env() -> Self {
        let cors_env = std::env::var("CORS_ORIGINS").unwrap_or_default();
        let cors_any = cors_env.trim() == "*";
        let mut cors = if cors_any || cors_env.is_empty() {
            vec![
                env_string("CLIENT_PUBLIC_URL", "http://localhost:8000"),
                "http://localhost:8000".into(),
                "http://127.0.0.1:8000".into(),
                "http://localhost:8080".into(),
                "http://127.0.0.1:8080".into(),
                "http://localhost:3338".into(),
                "http://127.0.0.1:3338".into(),
            ]
        } else {
            cors_env
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };
        cors.sort();
        cors.dedup();

        let ws_targets = env_string(
            "WS_ALLOWED_TARGETS",
            "127.0.0.1:6900,127.0.0.1:6121,127.0.0.1:5121",
        );
        let ws_allowed_targets: Vec<String> = ws_targets
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let override_path = std::env::var("DATA_OVERRIDE_PATH")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        Self {
            port: env_usize("PORT", 3338) as u16,
            cors_any,
            cors_origins: cors,
            client_respath: PathBuf::from(env_string("CLIENT_RESPATH", "resources")),
            client_dataini: env_string("CLIENT_DATAINI", "DATA.INI"),
            auto_extract: env_bool("CLIENT_AUTOEXTRACT", true),
            enable_search: env_bool("CLIENT_ENABLESEARCH", true),
            grf_encoding: env_string("GRF_ENCODING", "CP949"),
            cache_max_files: env_usize("CACHE_MAX_FILES", 5000),
            cache_max_memory_mb: env_usize("CACHE_MAX_MEMORY_MB", 1024),
            cache_warm_up: env_bool("CACHE_WARM_UP", true),
            cache_warm_up_limit: env_usize("CACHE_WARM_UP_LIMIT", 500),
            enable_wsproxy: env_bool("ENABLE_WSPROXY", true),
            ws_allowed_targets,
            enable_static_serve: env_bool("ENABLE_STATIC_SERVE", true),
            robrowser_path: PathBuf::from(env_string("ROBROWSER_PATH", "../roBrowserLegacy")),
            data_override_path: override_path,
            path_mapping_file: PathBuf::from(env_string("PATH_MAPPING_FILE", "path-mapping.json")),
            convert_bmp: env_bool("CONVERT_BMP", false),
            restrict_asset_paths: env_bool("RESTRICT_ASSET_PATHS", false),
            esrgan_enabled: env_bool("ESRGAN_ENABLED", false),
            esrgan_cache_dir: PathBuf::from(env_string("ESRGAN_CACHE_DIR", "./upscaled_cache")),
            missing_log_file: PathBuf::from(env_string(
                "MISSING_LOG_FILE",
                "logs/missing-files.log",
            )),
        }
    }
}
