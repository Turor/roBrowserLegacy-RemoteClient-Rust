# remoteclient2

Rust reimplementation of the [PHP](https://github.com/MrAntares/roBrowserLegacy-RemoteClient-PHP) and [Node](https://github.com/FranciscoWallison/roBrowserLegacy-RemoteClient-JS) roBrowser Legacy **remote clients**.

It serves Ragnarok Online assets from GRF archives over HTTP and can proxy browser WebSockets to rAthena TCP (login/char/map).

If you know **Micronaut/Kotlin**, the mapping is:

| Micronaut | This crate |
|-----------|------------|
| `@Singleton` bean | `Arc<Client>` / `Arc<AppState>` |
| `@Controller` | `src/http.rs` `Router` |
| `@ConfigurationProperties` | `src/config.rs` (`Config::from_env()`) |
| Caffeine cache | `src/cache.rs` |
| Netty WebSocket | `src/ws.rs` + axum `ws` |
| `application.yml` | environment variables (same names as the Node `.env`) |

Rust has **no GC**: `Arc` is a thread-safe refcount (like sharing an immutable bean). `Mutex` is only around the LRU and missing-file log.

See `plan.md` for the full design.

## Requirements

- [Rust](https://rustup.rs/) (stable)
- Your GRF files + `DATA.INI` in `resources/`

## Setup

```text
resources/
  DATA.INI      # [Data] 0=custom.grf  1=rdata.grf  2=data.grf
  *.grf
```

GRF versions **0x200** and **0x300** are supported, including Gravity DES flags. GrfEditor `0x80` custom keys are not.

```powershell
# from this directory
cargo run --release
```

Default listen: `http://localhost:3338`

```powershell
cargo run -- doctor
cargo run -- doctor --deep --json
cargo run -- convert-encoding --output path-mapping.json
```

## roBrowserLegacy

In `Config.local.js`:

```javascript
remoteClient: 'http://127.0.0.1:3338/',
socketProxy:  'ws://127.0.0.1:3338/ws/',
```

Optional: set `ROBROWSER_PATH` to your roBrowserLegacy checkout and open:

`http://localhost:3338/applications/pwa/index.html`

## Environment (subset)

| Variable | Default | Role |
|----------|---------|------|
| `PORT` | `3338` | HTTP + WS |
| `CLIENT_RESPATH` | `resources` | GRF directory |
| `GRF_ENCODING` | `CP949` | Filename charset |
| `CACHE_MAX_FILES` / `CACHE_MAX_MEMORY_MB` | 5000 / 1024 | LRU |
| `ENABLE_WSPROXY` | `true` | `/ws/{host}:{port}` |
| `WS_ALLOWED_TARGETS` | localhost 6900/6121/5121 | TCP allowlist |
| `ENABLE_STATIC_SERVE` | `true` | Serve `ROBROWSER_PATH` |
| `DATA_OVERRIDE_PATH` | unset | Loose client `data/` |
| `CLIENT_AUTOEXTRACT` | `true` | Write GRF hits to disk |

## Layout

```text
src/main.rs      CLI + tokio server
src/http.rs      routes (health, search, files)
src/ws.rs        WebSocket → TCP
src/client.rs    lookup chain + index
src/grf/         GRF mmap + DES + zlib
src/paths.rs     CP949 / mojibake
src/cache.rs     LRU
src/doctor.rs    diagnostics CLI
```

## Tests

```powershell
cargo test
```

A synthetic 0x200 GRF is built in-memory (no Gravity files required).
