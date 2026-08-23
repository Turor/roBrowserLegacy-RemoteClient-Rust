# Implementation Plan: roBrowser Legacy Remote Client

This document describes how to reimplement the functionality of:

- [roBrowserLegacy-RemoteClient-PHP](https://github.com/MrAntares/roBrowserLegacy-RemoteClient-PHP)
- [roBrowserLegacy-RemoteClient-JS](https://github.com/FranciscoWallison/roBrowserLegacy-RemoteClient-JS)

in a new long-running process. The goal is a drop-in asset (and optional game-socket) server for [roBrowserLegacy](https://github.com/MrAntares/roBrowserLegacy): browsers fetch Ragnarok Online client files over HTTP without a local FullClient.

**Recommended stack: Rust.** Kotlin + Micronaut is a viable alternative; both are sketched below. The rest of the plan is written against Rust as the primary path, with a Micronaut mapping where it differs.

---

## 1. What these projects actually do

Both implementations are **HTTP file servers** that resolve a requested path through a layered lookup:

```
Request path (URL-decoded, often UTF-8 or Latin-1 mojibake)
    1. In-memory LRU content cache
    2. Loose files on disk (data/, BGM/, System/, AI/, auto-extracted cache)
    3. Optional DATA_OVERRIDE_PATH (JS only) — client `data/` not packed in GRF
    4. Unified GRF file index (O(1) path → archive + original filename)
    5. Korean path mapping / mojibake decode (CP949 ↔ ISO-8859-1)
    6. Sequential GRF scan (fallback)
    7. 404 + missing-file log
```

Then they:

- Optionally convert BMP → PNG (PHP, on auto-extract)
- Set ETag / Cache-Control / 304
- Optionally gzip/deflate
- Optionally persist extracted bytes to disk

PHP is a **request-scoped CGI/FPM-style** app (per-request GRF open unless you run a daemon). JS is a **long-lived Node process** that also embeds:

- Static serving of the roBrowserLegacy tree (`ENABLE_STATIC_SERVE`)
- WebSocket → rAthena TCP proxy (`ENABLE_WSPROXY`, `/ws/{host}:{port}`)
- Optional ESRGAN overlay (`@chicowall/robrowser-esrgan`)
- `POST /batch` (base64 multi-file)
- Vite `?raw` import middleware

**Compatibility contract with the browser client**

- Serve `data/...` and `BGM/...` (PHP also restricts URL to those trees).
- `DATA.INI` `[Data]` section lists GRFs in **priority order**. JS: first GRF wins. PHP index comment says later GRFs override; sequential search still walks in INI order. **Match JS: first listed GRF wins** (typical Gravity/DATA.INI: `0=custom.grf` overrides `1=rdata.grf` / `2=data.grf`).
- Paths are case-insensitive; `\` and `/` are equivalent.
- roBrowser often requests Korean directories as **CP949 bytes mis-decoded as Latin-1** (`À¯ÀúÀÎÅÍÆäÀÌ½º` vs `유저인터페이스`).
- `socketProxy` in `Config.local.js` is `ws://host:port/ws/` in unified mode.
- CORS must allow the PWA origin.

---

## 2. GRF format (must implement correctly)

Implement this in-process. Do not shell out to GRF Editor.

### Header (0x2E bytes)

| Offset | Size | Field |
|--------|------|--------|
| 0 | 16 | Signature `"Master of Magic\0"` or `"Event Horizon\0"` |
| 16 | 14 | Keys (unused for standard 0x200/0x300) |
| 30 | 4 or 8 | Table offset (u32 for 0x200, u64 for 0x300 at offset 30) |
| 34 | 4 | Seeds (0x200 only) |
| 38 | 4 | File count |
| 42 | 4 | Version `0x200` or `0x300` |

- **0x200:** `realfilecount = filecount - seeds - 7`. File table at `header_size + table_offset`.
- **0x300:** 64-bit table offset; skip **4 unknown bytes** before the packed table; filecount is real count.

Packed table: `u32 pack_size`, `u32 real_size`, then zlib blob.

### File table entries

Null-terminated filename (legacy encoding, usually CP949), then:

- **0x200 (17 bytes):** `pack_size u32`, `length_aligned u32`, `real_size u32`, `flags u8`, `position u32`
- **0x300 (21 bytes):** same but `position u64`

Data at `position + 0x2E`. Flags:

| Flag | Meaning |
|------|---------|
| `0x01` | FILE — zlib only |
| `0x02` | ENCRYPT_HEADER |
| `0x03` / `0x05` | MIXED encryption |
| `0x04` | ENCRYPT_FULL (rare) |
| `0x80` | GrfEditor custom — **reject with a clear error** |

JS (`@chicowall/grf-loader`) expects **unencrypted 0x200/0x300**. PHP implements Gravity DES (`GrfDES.php`). **Implement DES** so operators do not have to repack every GRF.

DES cycle (from PHP):

- Extensions `.gnd`, `.gat`, `.act`, `.str`: cycle `0`, data treated as “crypted type”
- Else cycle starts at 1 and increments for each decade of `pack_size`
- Mixed: decrypt header blocks by cycle; header-only: first blocks
- After decrypt, take first `pack_size` bytes, then `zlib inflate` to `real_size`

Safety: refuse `read_size > 100 MiB` per file (PHP).

Keep GRFs **memory-mapped** (`memmap` crate / NIO `MappedByteBuffer`) so extraction is a slice + inflate, not a full copy of multi-GB archives.

Parse the table **once** into a `HashMap` of normalized path → `{ archive_id, offset, pack_size, aligned, real_size, flags, original_bytes }`. Do **not** copy PHP’s `strpos` on the raw table at request time.

---

## 3. Encoding and path mapping

This is the highest-risk compatibility area.

**On index build (per GRF filename):**

1. Store original bytes as in the table.
2. Decode as configured encoding (`GRF_ENCODING`, default CP949) → Unicode.
3. Also index:
   - lowercase, `/` and `\`
   - **mojibake form:** CP949 bytes decoded as ISO-8859-1 (what roBrowser often sends)
4. Merge `path-mapping.json` (`korean UTF-8 path` → `GRF path`).

**On request:**

1. URL-decode as UTF-8 (lossy fallback Latin-1).
2. Lookup normalized Unicode, then mojibake, then mapping file, then `decode(latin1_bytes, cp949)`.

CLI: `convert-encoding` scans GRFs and writes `path-mapping.json` (same schema as PHP/JS).

Use `encoding_rs` + a CP949 mapping (Rust `encoding_rs` does not include CP949; use `encoding_index_korean` / `oem_cp` / a small `codepage` crate, or `iconv` via `encoding` crate). Kotlin: `Charset.forName("x-windows-949")` plus ISO-8859-1 round-trip.

---

## 4. HTTP surface (compatibility)

### Asset serving

| Method | Path | Behavior |
|--------|------|----------|
| GET | `/` | Landing `index.html` |
| GET | `/{path}` | File from lookup chain |
| GET | `/data/*`, `/BGM/*` | Primary asset trees |
| GET | `/System/*`, `/AI/*` | Loose client dirs if present |
| POST | `/search` | Body `filter` regex or substring; plaintext `\n`-joined list (PHP and JS) |
| GET | `/list-files` | JSON array of indexed paths (JS) |
| POST | `/batch` | JSON `{ files: string[] }` max 50; values base64 (JS) |

**Headers**

- CORS: configurable origins (JS default localhost:8000/8080/3338).
- Game assets: `ETag` (content hash, 16 hex chars is enough), `Cache-Control: public, max-age=86400, immutable` (JS) or longer (PHP 1y). Prefer JS 1-day unless you version assets.
- 304 on `If-None-Match`.
- 404: `Cache-Control: no-store`.
- Content-Type by extension (`.spr`, `.act`, `.gat`, `.rsw`, `.gnd`, `.rsm`, `.str`, `.pal`, `.lub`, `.lua`, `.bmp`, `.tga`, audio, xml, txt).
- Gzip/deflate/brotli for text and highly compressible binaries (JS also compresses `.spr`, `.rsm`, `.gnd`, etc. above 1 KiB). Let the HTTP stack do this (tower-http / Micronaut compression).

**PHP-only restriction:** reject paths outside `data` and `BGM`. Make this a config flag `RESTRICT_ASSET_PATHS` default **off** in unified mode (need to serve the PWA), **on** in asset-only mode.

**BMP → PNG:** PHP converts on auto-extract (magenta 255,0,255 transparent; 1/4/8/24-bit DIB). JS does not convert at request time. Implement conversion as **optional** (`CONVERT_BMP=true`) so existing PNG-expecting caches still work. Magenta-as-alpha is RO-specific — do not use a generic image crate default.

### Ops API

Parity with the richer of the two:

| Method | Path | Notes |
|--------|------|--------|
| GET | `/api/health` | Validation + cache + index + missing + optional ESRGAN |
| GET | `/api/health/simple` | Fast liveness |
| GET | `/api/cache-stats` | LRU + index |
| GET | `/api/missing-files` | Recent misses |
| POST | `/api/missing-files/clear` | |
| GET | `/api/validate?deep=` | Startup checks as JSON |
| GET | `/api/path-mapping` | Mapping stats |
| GET | `/api/warm-cache` | Stats |
| POST | `/api/warm-cache/run` | Trigger warm |

### Unified extras (from JS — include)

- `GET /applications/pwa/*` (or `ROBROWSER_PATH`) as static files.
- `WS /ws/{host}:{port}` → TCP, **allowlist only**.
- Buffer up to 64 WS messages until TCP `connect` (roBrowser sends the first packet in `onopen`; JS documents this race).
- `TCP_NODELAY`.
- Default allowlist: `127.0.0.1:6900`, `:6121`, `:5121`. Override `WS_ALLOWED_TARGETS`.
- Vite `?raw` query: if `ROBROWSER_PATH` file exists, serve as JS string module (only if you serve the PWA from this process).

### ESRGAN (phase 2)

If `ESRGAN_ENABLED`, intercept `.bmp/.tga/.png/.jpg/.spr/.act`: if `ESRGAN_CACHE_DIR` has a PNG, serve it with `X-ESRGAN-Upscaled: true`. Do not embed Real-ESRGAN inference in v1.

---

## 5. Language recommendation

| Concern | Rust | Kotlin + Micronaut |
|---------|------|-------------------|
| GRF mmap + zlib + DES | Natural (`memmap2`, `flate2`, small DES) | Possible but more GC/copying |
| 400k–1M path index | Cheap `HashMap` | Heap pressure; off-heap possible |
| 0.5–2 GiB LRU of bytes | Explicit; no GC pauses | JVM heap + G1/ZGC tuning |
| WS ↔ TCP proxy | `tokio` + `tokio-tungstenite` | Netty; extra moving parts |
| Single static binary | Yes | JRE or Graal native-image (harder with mmap) |
| HTTP ecosystem | axum / actix-web | Micronaut is excellent |
| Team familiarity | If you want JVM | Prefer Micronaut |

**Choose Rust** for a dedicated asset/proxy daemon: the hot path is “hash lookup + mmap slice + inflate + write HTTP body,” which is what Rust is for.

**Choose Micronaut** if this must live in an existing JVM ops stack, you want Micronaut config/metrics out of the box, and you accept heap sizing (~index + cache + mapped files).

Do **not** mix both for v1.

---

## 6. Proposed architecture (Rust)

```
remoteclient2/
  Cargo.toml                 workspace
  crates/
    grf/                     parse, DES, extract, list
    encoding-paths/          CP949, mojibake, path-mapping.json
    client-index/            DATA.INI, overlay dirs, LRU, warm, missing log
    http-server/             axum routes, headers, static, WS proxy
  resources/                 DATA.INI + *.grf (operator-supplied)
  data/ BGM/ System/ AI/
  tools/                     doctor, convert-encoding, validate-grf
  plan.md
```

**Runtime (tokio)**

- One `AppState`: GRF mmaps (never closed), `Arc<Index>`, `Mutex`/`parking_lot` LRU, config.
- Axum `Router`: API first, then `/ws` upgrade, then `ServeDir` for `ROBROWSER_PATH`, then catch-all asset GET.
- Compression: `tower-http` CompressionLayer.
- Config: `figment` or `config` crate from env (same names as JS `.env` where possible).

**Lookup order (lock in tests)**

1. LRU (key = lowercase requested path)
2. Local relative path (project `data/`, `BGM/`, …)
3. `DATA_OVERRIDE_PATH` (strip leading `data/`)
4. Index (normalized + mojibake + mapping)
5. Sequential GRF (should be rare; keep for unindexed edge cases)
6. Miss log (dedupe set, async append JSON lines)

**GRF priority:** iterate `DATA.INI` from index 0 upward; first hit wins.

**Auto-extract:** after GRF hit, spawn blocking write under `data/` (create parents). Optional BMP→PNG on write.

**Index persistence (optional, PHP-like):** serialize index keyed by `(encoding + mtime of each GRF)` to skip rebuild. Nice-to-have after mmap parse is fast enough.

**Warm cache:** after `listen`, background task preloads patterns (UI textures, prontera maps, player sprites, palettes, lub) up to `CACHE_WARM_UP_LIMIT`. Do not block bind.

**Doctor:** binary subcommand: PHP/Node version analog — GRF signatures, zlib table, encoding scan, DATA.INI, mmapability, WS allowlist parse. Exit non-zero on fatal.

---

## 7. Micronaut mapping (if chosen instead)

- `io.micronaut.http.server` + `micronaut-websocket`.
- `GrfArchive` as `@Singleton` at startup (`@EventListener StartupEvent`).
- File serve: `@Get("/{path:.*}")` `HttpResponse<StreamedFile>` / `byte[]`.
- LRU: Caffeine with weigher = byte length, max weight = `CACHE_MAX_MEMORY_MB`.
- mmap: `FileChannel.map`.
- WS: `@ServerWebSocket("/ws/{target}")` + `SocketChannel` to rAthena; same allowlist and pending queue.
- Static: `micronaut.router.static-resources`.
- Config: `application.yml` + env.

Same modules conceptually: `grf`, `encoding`, `index`, `http`.

---

## 8. Phased delivery

### Phase 0 — Scaffold (~1 day)

- Workspace, config structs, logging (`tracing`), `resources/` gitignored except `DATA.INI` example.
- Docker image (debian slim / distroless).
- Env parity table vs JS/PHP.

### Phase 1 — GRF crate + tests (core)

- Golden tests: tiny synthetic 0x200 and 0x300 GRFs (unencrypted).
- One encrypted mixed-flag fixture if license allows; otherwise unit-test DES against PHP `GrfDES` vectors.
- `get_file`, `list_files`, version detection, 64-bit offsets, 100 MiB cap.
- Property: round-trip zlib extract matches known bytes.

### Phase 2 — Index + encoding

- `DATA.INI` parser (`[Data]` / `[data]`, numeric keys, comments).
- Unified index + mojibake dual keys.
- `path-mapping.json` load/generate CLI.
- Overlay + override directories.

### Phase 3 — HTTP asset server

- Catch-all GET, ETag, 304, CORS, compression.
- `/search`, `/list-files`, `/batch`.
- LRU + warm + missing log.
- Health/cache/validate APIs.
- Restrict-path flag.

### Phase 4 — Unified process

- Static `ROBROWSER_PATH`.
- WS proxy with allowlist, pending buffer, `TCP_NODELAY`, cleanup-once.
- Dev vs prod log noise.

### Phase 5 — Polish

- BMP→PNG (RO magenta).
- Doctor CLI (`--deep`, `--json`).
- Optional index disk cache.
- ESRGAN overlay (read-only cache dir).
- HTTP tester like PHP `docker/test/tester.py` against a file list.

### Out of scope for v1

- GrfEditor `0x80` custom keys.
- Live GRF reload without restart (can add `notify` later).
- Embedding Real-ESRGAN.
- PHP FPM multi-worker semantics (we are a daemon).

---

## 9. Configuration (align names with JS)

| Variable | Default | Role |
|----------|---------|------|
| `PORT` | `3338` | HTTP + WS |
| `CLIENT_PUBLIC_URL` | `http://localhost:8000` | CORS |
| `CLIENT_RESPATH` | `resources/` | GRF + DATA.INI |
| `CLIENT_DATAINI` | `DATA.INI` | |
| `CLIENT_AUTOEXTRACT` | `true` | Write extracted files |
| `CLIENT_ENABLESEARCH` | `true` (JS) / `false` (PHP) | Prefer `true` |
| `GRF_ENCODING` | `CP949` | Filename charset |
| `CACHE_MAX_FILES` | `5000` | |
| `CACHE_MAX_MEMORY_MB` | `1024` | |
| `CACHE_WARM_UP` | `true` | |
| `CACHE_WARM_UP_LIMIT` | `500` | |
| `ENABLE_WSPROXY` | `true` | |
| `WS_ALLOWED_TARGETS` | localhost login/char/map | |
| `ENABLE_STATIC_SERVE` | `true` | |
| `ROBROWSER_PATH` | `../roBrowserLegacy` | |
| `DATA_OVERRIDE_PATH` | unset | Loose `data/` |
| `PATH_MAPPING_FILE` | `path-mapping.json` | |
| `CONVERT_BMP` | `false` | PHP behavior opt-in |
| `RESTRICT_ASSET_PATHS` | `false` | PHP sandbox |
| `ESRGAN_ENABLED` / `ESRGAN_CACHE_DIR` | off | Phase 5 |

---

## 10. Testing strategy

1. **Unit:** GRF header/table, DES cycles, path normalize, mojibake round-trip (`유저인터페이스` ↔ `À¯ÀúÀÎÅÍÆäÀÌ½º`).
2. **Fixture GRFs:** check into `crates/grf/tests/fixtures/` (tiny, no Gravity IP).
3. **HTTP:** axum `oneshot` — 200, 304, 404, CORS, search, batch size cap, path traversal (`../`).
4. **WS:** mock TCP echo; allowlist reject; pre-connect buffer.
5. **Interop:** point roBrowserLegacy `remoteClientUrl` at this server and load prontera + one Korean UI texture.
6. **Regression vs Node:** optional: hash-compare N files from both servers against the same `resources/`.

Path traversal: canonicalize under allowed roots; never `include` user path as raw OS path without a prefix check.

---

## 11. Performance notes

- Index ~450k files: store interned strings; dual slash keys can **double** map size — prefer **one** normalized form (`/` + lowercase) and normalize on request.
- Do not MD5 the body on every cache hit; store ETag next to LRU value (JS already does this).
- Extract on a `spawn_blocking` pool so zlib does not stall the reactor.
- mmap the GRF; only copy decompressed payload.
- Auto-extract turns the second hit into a normal static read — keep it default-on for HDD, optional-off for read-only containers.

---

## 12. Security

- WS target **allowlist** is mandatory; never proxy arbitrary `host:port`.
- Do not follow symlinks out of `ROBROWSER_PATH` / `resources/`.
- Search regex: compile with size/time limits (JS `RegExp` on 450k names can be abused). Cap result count.
- `/batch` max 50 files, max bytes per file.
- CORS: do not default to `*` if credentials are used.

---

## 13. Suggested first implementation slice

After scaffold, the smallest useful binary is:

1. Parse one 0x200 GRF from `resources/` via DATA.INI.
2. `GET /data/clientinfo.xml` (loose or GRF).
3. Health endpoint.
4. Then encoding + index, then WS + static.

That order lets you plug roBrowserLegacy `remoteClient` at the HTTP layer before encoding edge cases and the login proxy.

---

## 14. Source map (for implementers)

| Concern | PHP | JS |
|---------|-----|-----|
| Front controller / routes | `index.php` | `index.js`, `src/routes/index.js` |
| Lookup + cache + index | `Client.php` | `src/controllers/clientController.js` |
| GRF I/O | `Grf.php` | `src/controllers/grfController.js` + `@chicowall/grf-loader` |
| DES | `GrfDES.php` | (not in-tree; unencrypted GRFs) |
| BMP | `Bmp.php` | `src/utils/bmpUtils.js` |
| WS proxy | — | `index.js` upgrade handler |
| Static PWA | Docker/nginx | `express.static(ROBROWSER_PATH)` |
| Config | `configs.php` | `.env` + `src/config/configs.js` |

Treat **JS unified mode** as the product target and **PHP GRF/DES/BMP** as the format reference where JS is thinner.
