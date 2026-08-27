//! Live functional tests against the Turoran rodata + HAProxy + roBrowser stack.
//!
//! Offline `cargo test` skips these. To run:
//!
//! ```text
//! cargo test --test live_ecosystem -- --ignored --nocapture
//! ```
//!
//! Override targets with env vars (defaults match the current deployment):
//! - `RODATA_BASE_URLS`  comma-separated HTTP(S) asset bases
//! - `RODATA_WS_URLS`    comma-separated WebSocket proxy URLs including host:port
//! - `ROBROWSER_URL`     PWA origin (Config.local.js)
//! - `RODATA_EXPECT_GRFS` minimum GRF count (default 3)

use futures_util::StreamExt;
use reqwest::{header, Client, StatusCode};
use serde_json::Value;
use std::time::Duration;

fn bases() -> Vec<String> {
    env_list(
        "RODATA_BASE_URLS",
        "https://ro.turoran.com/client,http://rodata-dev.turoran.com:3338",
    )
}

fn ws_urls() -> Vec<String> {
    env_list(
        "RODATA_WS_URLS",
        "wss://ro.turoran.com/ws/192.168.11.110:6900,ws://rodata-dev.turoran.com:3338/ws/192.168.11.110:6900",
    )
}

fn robrowser_url() -> String {
    std::env::var("ROBROWSER_URL").unwrap_or_else(|_| "https://ro.turoran.com".into())
}

fn expect_grfs() -> usize {
    std::env::var("RODATA_EXPECT_GRFS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
}

fn env_list(key: &str, default: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_else(|_| default.to_string())
        .split(',')
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn http() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(false)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("remoteclient2-live-tests/0.1")
        .build()
        .expect("http client")
}

fn join(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn health_reports_loaded_grfs() {
    let client = http();
    for base in bases() {
        let url = join(&base, "/api/health");
        let body: Value = client
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("{url}: {e}"))
            .error_for_status()
            .unwrap_or_else(|e| panic!("{url}: {e}"))
            .json()
            .await
            .unwrap();
        assert_eq!(body["status"], "ok", "{url}: {body}");
        let total = body["grfs"]["total"].as_u64().unwrap_or(0) as usize;
        assert!(
            total >= expect_grfs(),
            "{url}: expected >= {} GRFs, got {total} ({body})",
            expect_grfs()
        );
        assert!(
            body["index"]["index_built"].as_bool().unwrap_or(false),
            "{url}: index not built"
        );
        let files = body["index"]["total_files"].as_u64().unwrap_or(0);
        assert!(files > 10_000, "{url}: index too small ({files})");
        eprintln!("ok health {url} grfs={total} index={files}");
    }
}

#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn clientinfo_xml_is_served() {
    let client = http();
    for base in bases() {
        let url = join(&base, "/data/clientinfo.xml");
        let res = client.get(&url).send().await.expect(&url);
        assert_eq!(res.status(), StatusCode::OK, "{url} {}", res.status());
        let bytes = res.bytes().await.expect(&url);
        assert!(bytes.len() > 50, "{url}: body too small ({})", bytes.len());
        let text = String::from_utf8_lossy(&bytes).to_lowercase();
        assert!(
            text.contains("clientinfo") || text.contains("address") || text.contains("server"),
            "{url}: not a clientinfo document"
        );
        eprintln!("ok clientinfo {url} {} bytes", bytes.len());
    }
}

#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn prontera_map_assets_exist() {
    let client = http();
    let names = [
        "data/prontera.gat",
        "data/prontera.gnd",
        "data/prontera.rsw",
    ];
    for base in bases() {
        for name in names {
            let url = join(&base, name);
            let res = client.get(&url).send().await.expect(&url);
            assert_eq!(
                res.status(),
                StatusCode::OK,
                "{url} {} (map data should be in the packed GRFs)",
                res.status()
            );
            let n = res.bytes().await.expect(&url).len();
            assert!(n > 100, "{url}: {n} bytes");
            eprintln!("ok map {url} {n} bytes");
        }
    }
}

/// GAT cell records are 20 bytes after a 14-byte `GRAT` header.
const GAT_HEADER: usize = 14;
const GAT_CELL: usize = 20;

/// kRO remade Izlude again after the 2012 Renewal (268×268) layout.
/// Hercules `PACKETVER=20190530` RE map-cache is the later 268×300 map.
/// Pre-RE is 128×128. The 2012 RE overlay in `translation.grf` is 268×268.
const IZLUD_MODERN_W: u32 = 268;
const IZLUD_MODERN_H: u32 = 300;
const IZLUD_PRE_RE_WH: (u32, u32) = (128, 128);
const IZLUD_RE_2012_WH: (u32, u32) = (268, 268);

fn parse_gat_size(bytes: &[u8]) -> (u32, u32) {
    assert!(
        bytes.len() >= GAT_HEADER,
        "GAT too small ({} bytes)",
        bytes.len()
    );
    assert!(
        bytes.starts_with(b"GRAT"),
        "GAT magic {:?}, expected GRAT",
        &bytes[..4.min(bytes.len())]
    );
    let w = u32::from_le_bytes(bytes[6..10].try_into().unwrap());
    let h = u32::from_le_bytes(bytes[10..14].try_into().unwrap());
    let expect = GAT_HEADER + (w as usize) * (h as usize) * GAT_CELL;
    assert_eq!(
        bytes.len(),
        expect,
        "GAT {w}x{h} should be {expect} bytes, got {}",
        bytes.len()
    );
    (w, h)
}

/// Fail if Izlude is still the Pre-RE island or the 2012 Renewal town.
/// Hercules RE 20190530 walks the later 268×300 remake from `data.grf`.
#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn izlude_is_modern_renewal_map() {
    let client = http();
    for base in bases() {
        let gat_url = join(&base, "data/izlude.gat");
        let res = client.get(&gat_url).send().await.expect(&gat_url);
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "{gat_url} {} (izlude.gat must be served)",
            res.status()
        );
        let gat = res.bytes().await.expect(&gat_url);
        let (w, h) = parse_gat_size(&gat);
        assert_ne!(
            (w, h),
            IZLUD_PRE_RE_WH,
            "{gat_url}: Pre-RE Izlude {w}x{h} — Hercules RE uses the remake"
        );
        assert_ne!(
            (w, h),
            IZLUD_RE_2012_WH,
            "{gat_url}: 2012 Renewal Izlude {w}x{h} — translation.grf/Data overlay is masking data.grf (need 268x300)"
        );
        assert_eq!(
            (w, h),
            (IZLUD_MODERN_W, IZLUD_MODERN_H),
            "{gat_url}: expected modern Izlude {IZLUD_MODERN_W}x{IZLUD_MODERN_H}, got {w}x{h}"
        );

        for name in ["data/izlude.gnd", "data/izlude.rsw"] {
            let url = join(&base, name);
            let res = client.get(&url).send().await.expect(&url);
            assert_eq!(res.status(), StatusCode::OK, "{url} {}", res.status());
            let n = res.bytes().await.expect(&url).len();
            assert!(n > 1000, "{url}: {n} bytes");
            eprintln!("ok izlude mesh {url} {n} bytes");
        }

        // Instance copies must match the same walkable size as izlude.gat.
        for inst in ["izlude_a", "izlude_b", "izlude_c", "izlude_d"] {
            let url = join(&base, &format!("data/{inst}.gat"));
            let res = client.get(&url).send().await.expect(&url);
            if res.status() != StatusCode::OK {
                eprintln!("skip {url}: {}", res.status());
                continue;
            }
            let bytes = res.bytes().await.expect(&url);
            let (iw, ih) = parse_gat_size(&bytes);
            assert_eq!(
                (iw, ih),
                (IZLUD_MODERN_W, IZLUD_MODERN_H),
                "{url}: instance GAT {iw}x{ih} must match modern izlude"
            );
            eprintln!("ok izlude instance {url} {iw}x{ih}");
        }

        eprintln!(
            "ok modern izlude {gat_url} {w}x{h} {} bytes",
            gat.len()
        );
    }
}

#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn etag_yields_304_on_revalidate() {
    let client = http();
    for base in bases() {
        let url = join(&base, "/data/clientinfo.xml");
        let res = client.get(&url).send().await.expect(&url);
        assert_eq!(res.status(), StatusCode::OK, "{url}");
        let etag = res
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let Some(etag) = etag else {
            eprintln!("skip 304 {url}: no ETag (file may be treated as non-static)");
            continue;
        };
        let res2 = client
            .get(&url)
            .header(header::IF_NONE_MATCH, &etag)
            .send()
            .await
            .expect(&url);
        assert_eq!(
            res2.status(),
            StatusCode::NOT_MODIFIED,
            "{url} If-None-Match {etag} -> {}",
            res2.status()
        );
        eprintln!("ok 304 {url}");
    }
}

#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn missing_asset_is_404_uncached() {
    let client = http();
    for base in bases() {
        let url = join(&base, "/data/__live_test_missing_file__.spr");
        let res = client.get(&url).send().await.expect(&url);
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{url}");
        let cc = res
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            cc.contains("no-store") || cc.contains("no-cache") || cc.is_empty(),
            "{url}: unexpected Cache-Control {cc}"
        );
        eprintln!("ok 404 {url}");
    }
}

#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn cors_allows_browser_origin() {
    let client = http();
    for base in bases() {
        let url = join(&base, "/api/health");
        let res = client
            .request(reqwest::Method::OPTIONS, &url)
            .header(header::ORIGIN, "https://ro.turoran.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .send()
            .await
            .expect(&url);
        assert!(
            res.status().is_success() || res.status() == StatusCode::NO_CONTENT,
            "{url} OPTIONS {}",
            res.status()
        );
        let allow = res
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            allow == "*" || allow == "https://ro.turoran.com",
            "{url}: ACAO={allow:?}"
        );
        eprintln!("ok cors {url} {allow}");
    }
}

#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn search_finds_prontera() {
    let client = http();
    for base in bases() {
        let url = join(&base, "/search");
        let res = client
            .post(&url)
            .json(&serde_json::json!({ "filter": r"prontera\.gat$" }))
            .send()
            .await
            .expect(&url);
        if res.status() == StatusCode::BAD_REQUEST {
            eprintln!("skip search {url}: feature disabled");
            continue;
        }
        assert_eq!(res.status(), StatusCode::OK, "{url} {}", res.status());
        let text = res.text().await.expect(&url);
        assert!(
            text.to_lowercase().contains("prontera"),
            "{url}: search missed prontera ({text})"
        );
        eprintln!("ok search {url}");
    }
}

/// roBrowser `ACT::load()` requires bytes starting with `AC`. `SP` is a SPR
/// (sprite) file — that error means the client parsed sprite data as animation.
/// roBrowser requests Korean UI dirs as CP949-as-Latin-1 (`À¯ÀúÀÎÅÍÆäÀÌ½º`).
#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn korean_ui_textures_resolve() {
    let client = http();
    let files = [
        "data/texture/À¯ÀúÀÎÅÍÆäÀÌ½º/scroll0down.bmp",
        "data/texture/À¯ÀúÀÎÅÍÆäÀÌ½º/basic_interface/dialscr_down.bmp",
        "data/texture/유저인터페이스/scroll0down.bmp",
    ];
    for base in bases() {
        for f in files {
            let url = join(&base, f);
            let res = client.get(&url).send().await.expect(&url);
            assert_eq!(
                res.status(),
                StatusCode::OK,
                "{url} {} (UI texture should resolve via mojibake/CP949 mapping)",
                res.status()
            );
            let n = res.bytes().await.expect(&url).len();
            assert!(n > 16, "{url}: {n} bytes");
            eprintln!("ok ui {url} {n} bytes");
        }
    }
}

#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn npc_act_is_not_a_sprite() {
    let client = http();
    let act_path = "/data/sprite/npc/4_m_nov_rumin.act";
    let spr_path = "/data/sprite/npc/4_m_nov_rumin.spr";
    for base in bases() {
        let act_url = join(&base, act_path);
        let spr_url = join(&base, spr_path);

        let act = fetch_bytes(&client, &act_url).await;
        let spr = fetch_bytes(&client, &spr_url).await;

        assert!(
            act.starts_with(b"AC"),
            "{act_url}: ACT must start with AC, got {:?} (SP means a .spr was served)",
            act.get(..2)
        );
        assert!(
            spr.starts_with(b"SP"),
            "{spr_url}: SPR must start with SP, got {:?}",
            spr.get(..2)
        );
        assert_ne!(
            act, spr,
            "{act_url} and {spr_url} returned identical bodies — ACT was probably the sprite"
        );

        // Identity encoding: workers that skip Content-Encoding must still see AC.
        let raw_act = client
            .get(&act_url)
            .header(header::ACCEPT_ENCODING, "identity")
            .send()
            .await
            .expect(&act_url);
        assert_eq!(raw_act.status(), StatusCode::OK, "{act_url}");
        let enc = raw_act
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("identity")
            .to_string();
        let raw = raw_act.bytes().await.expect(&act_url);
        assert!(
            raw.starts_with(b"AC"),
            "{act_url}: Accept-Encoding=identity still not AC (encoding={enc}, magic={:?})",
            raw.get(..2)
        );
        eprintln!(
            "ok act/spr {act_url} act={} spr={} encoding={enc}",
            act.len(),
            spr.len()
        );
    }
}

async fn fetch_bytes(client: &Client, url: &str) -> Vec<u8> {
    let res = client.get(url).send().await.expect(url);
    assert_eq!(res.status(), StatusCode::OK, "{url} {}", res.status());
    res.bytes().await.expect(url).to_vec()
}

#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn haproxy_strips_client_prefix() {
    let client = http();
    let url = "https://ro.turoran.com/client/api/health";
    let body: Value = client
        .get(url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("{url}: {e}"))
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["status"], "ok", "{body}");
    eprintln!("ok haproxy {url}");
}

#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn robrowser_config_points_at_rust_ws() {
    let client = http();
    let origin = robrowser_url();
    let url = join(&origin, "/Config.local.js");
    let res = client.get(&url).send().await.expect(&url);
    assert_eq!(res.status(), StatusCode::OK, "{url} {}", res.status());
    let text = res.text().await.expect(&url);
    assert!(
        text.contains("ro.turoran.com/client") || text.contains("remoteClient"),
        "{url}: missing remoteClient ({text})"
    );
    assert!(
        text.contains("wss://ro.turoran.com/ws") || text.contains("socketProxy"),
        "{url}: socketProxy should use /ws/ on the Rust proxy"
    );
    assert!(
        !text.contains(":5999"),
        "{url}: still references Java wsproxy port 5999"
    );
    eprintln!("ok config {url}");
}

#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn websocket_proxy_reaches_login_server() {
    for raw in ws_urls() {
        let result = tokio::time::timeout(
            Duration::from_secs(8),
            tokio_tungstenite::connect_async(raw.as_str()),
        )
        .await;
        match result {
            Ok(Ok((mut ws, _))) => {
                // Login servers often stay silent until a packet is sent; an open
                // socket means HAProxy + Rust allowlist + TCP connect succeeded.
                let _ = tokio::time::timeout(Duration::from_millis(400), ws.next()).await;
                let _ = ws.close(None).await;
                eprintln!("ok ws {raw}");
            }
            Ok(Err(e)) => panic!("ws connect failed {raw}: {e}"),
            Err(_) => panic!("ws connect timed out {raw}"),
        }
    }
}

#[tokio::test]
#[ignore = "live Turoran ecosystem"]
async fn websocket_proxy_rejects_non_allowlisted_target() {
    // A blocked target should fail the handshake or close immediately.
    let blocked = "ws://rodata-dev.turoran.com:3338/ws/8.8.8.8:6900";
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::connect_async(blocked),
    )
    .await;
    match outcome {
        Ok(Ok((mut ws, _))) => {
            let closed = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;
            match closed {
                Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))) | Ok(None) => {
                    eprintln!("ok ws blocked (server closed) {blocked}");
                }
                other => {
                    let _ = ws.close(None).await;
                    panic!("{blocked}: expected close after allowlist reject, got {other:?}");
                }
            }
        }
        Ok(Err(_)) => eprintln!("ok ws blocked (handshake refused) {blocked}"),
        Err(_) => panic!("{blocked}: timed out (allowlist should fail fast)"),
    }
}
