//! Remote client daemon.
//!
//! Kotlin/Micronaut → Rust cheat sheet:
//! - `Arc<T>` ≈ a shared `@Singleton` (immutable/shared ownership, not a GC ref)
//! - `tokio::main` ≈ Micronaut event loop + `@Singleton` startup
//! - `axum::Router` ≈ `@Controller` route table
//! - `State<Arc<AppState>>` ≈ constructor injection of a bean
//! - `parking_lot::Mutex` ≈ a synchronized block around mutable fields
//! - errors are `Result` (no exceptions); `?` is like Kotlin's early return

mod bmp;
mod cache;
mod client;
mod config;
mod doctor;
mod grf;
mod http;
mod ini;
mod metrics;
mod paths;
mod ws;

use clap::{Parser, Subcommand};
use client::Client;
use config::Config;
use http::AppState;
use std::process::ExitCode;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "remoteclient2",
    about = "roBrowser Legacy remote client (Rust)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the HTTP + WS server (default)
    Serve,
    /// Validate GRFs and DATA.INI
    Doctor {
        #[arg(long)]
        deep: bool,
        #[arg(long)]
        json: bool,
    },
    /// Scan GRFs and write path-mapping.json
    ConvertEncoding {
        #[arg(long, default_value = "path-mapping.json")]
        output: std::path::PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Command::Serve) {
        Command::Doctor { deep, json } => ExitCode::from(doctor::run(deep, json) as u8),
        Command::ConvertEncoding { output } => {
            ExitCode::from(doctor::convert_encoding(&output) as u8)
        }
        Command::Serve => {
            if let Err(e) = serve().await {
                eprintln!("{e}");
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

async fn serve() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    let config = Config::from_env();
    info!(
        "Starting roBrowser Remote Client (Rust) on port {}",
        config.port
    );

    let client = Client::init(config.clone())?;
    let http_metrics = metrics::HttpMetrics::new();
    let state = Arc::new(AppState {
        config: config.clone(),
        client: client.clone(),
        metrics: http_metrics.clone(),
    });

    metrics::spawn_reporter(config.clone(), client.clone(), http_metrics);

    let app = http::router(state.clone());
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| e.to_string())?;

    info!(
        "Server ready on http://localhost{} | WS proxy: {} | static: {}",
        format!(":{}", config.port),
        config.enable_wsproxy,
        config.enable_static_serve
    );

    if config.cache_warm_up {
        let c = client.clone();
        let limit = config.cache_warm_up_limit;
        tokio::spawn(async move {
            let n = tokio::task::spawn_blocking(move || c.warm_cache(limit))
                .await
                .unwrap_or(0);
            info!("Cache warmed with {n} files");
        });
    }

    axum::serve(listener, app)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
