//! WebSocket → TCP bridge (replaces standalone wsproxy).
//! URL: `/ws/127.0.0.1:6900` — only allowlisted host:port.

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::http::AppState;

pub async fn upgrade(
    ws: WebSocketUpgrade,
    Path(target): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| proxy(socket, target, state))
}

async fn proxy(mut ws: WebSocket, target: String, state: Arc<AppState>) {
    if !state.config.enable_wsproxy {
        let _ = ws.send(Message::Close(None)).await;
        return;
    }
    let Some((host, port)) = parse_target(&target) else {
        warn!("WS proxy rejected malformed target: {target}");
        let _ = ws.send(Message::Close(None)).await;
        return;
    };
    let key = format!("{host}:{port}");
    if !state.config.ws_allowed_targets.iter().any(|t| t == &key) {
        warn!(
            "WS proxy blocked {key} (allowed: {})",
            state.config.ws_allowed_targets.join(", ")
        );
        let _ = ws.send(Message::Close(None)).await;
        return;
    }

    info!("WS proxy connecting to {key}");
    let mut tcp = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            warn!("WS proxy TCP connect failed: {e}");
            let _ = ws.send(Message::Close(None)).await;
            return;
        }
    };
    let _ = tcp.set_nodelay(true);

    // Drain pending WS frames that arrived conceptually "before connect"
    // (axum only hands us the socket after upgrade; still buffer if TCP write lags).
    let (mut reader, mut writer) = tcp.split();
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        tokio::select! {
            msg = ws.recv() => {
                match msg {
                    Some(Ok(Message::Binary(b))) => {
                        if writer.write_all(&b).await.is_err() { break; }
                    }
                    Some(Ok(Message::Text(t))) => {
                        if writer.write_all(t.as_bytes()).await.is_err() { break; }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(p))) => {
                        let _ = ws.send(Message::Pong(p)).await;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
            n = reader.read(&mut buf) => {
                match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if ws.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
    info!("WS proxy closed {key}");
}

fn parse_target(target: &str) -> Option<(String, u16)> {
    let target = target.trim_start_matches('/');
    let idx = target.rfind(':')?;
    let host = target[..idx].to_string();
    let port: u16 = target[idx + 1..].parse().ok()?;
    if host.is_empty() || port == 0 {
        return None;
    }
    Some((host, port))
}
