# Data version, change log, and signed manifests

remoteclient2 can stamp a monotonic `X-Data-Version` on every response and
answer `GET /version` and `GET /changes?since=<v>` so clients drop only the
files that changed. It also writes an unsigned two-level manifest of the
bytes it actually serves. A signature for that manifest is published
offline. This host never holds the signing seed.

## Enable

Set `DATA_VERSION=1`. Optional:

| Variable | Default | Role |
|---|---|---|
| `DATA_VERSION` | `false` | Stamp the header and serve the version, changes, and manifest routes |
| `DATA_VERSION_STATE_DIR` | `state` | `data-version.json`, `changes.jsonl`, and the hash cache |
| `DATA_MANIFEST_DIR` | `state/manifests` | Legacy `{version}.gdat` files and the v2 tree |
| `DATA_VERSION_LOOSE_ROOT` | process cwd when enabled | Loose `System/`, `SystemEN/`, `BGM/`, `AI/`, and `data/` trees |

The loose root must be the process working directory. The file handler
serves those paths relative to the working directory, and the exporter
hashes that same tree. The default is the working directory.

The first version is the Unix time in seconds. Later bumps are
`max(n + 1, now)`. A missing state file restarts from `max(now, last known)`
so versions never go backwards (clients treat that as "too old, full
recheck").

Rescans run when overlay directories, the loose trees, or GRF archives
change, debounced about 5 seconds. A replaced GRF whose entries cannot be
diffed cheaply is logged as `"full": true`.

## What is hashed

On startup and on each rescan that bumps the version, the process hashes
every file it would serve, in the same order the file handler uses. The
first hit wins:

1. Loose files under `DATA_VERSION_LOOSE_ROOT` (`data/`, `BGM/`, `System/`, `SystemEN/`, `AI/`).
2. Files under `OVERLAY_PATH`.
3. Files under `DATA_OVERRIDE_PATH` (requested as `data/<relative>`).
4. Every file entry in each GRF, in `DATA.INI` order.

GRF bytes are the decompressed payload the server returns, not the packed
record. Paths the server would not serve, and paths that fail manifest
normalization, are omitted. The manifest key is the normalized path:
Unicode lowercase, slashes, one leading `data/` removed, no `.` or `..`
segments. `data/texture/abc.bmp` and `System/itemInfo.lua` become
`texture/abc.bmp` and `system/iteminfo.lua`.

Hashes are cached in the state directory by source identity, mtime, and
size. A GRF entry also includes the archive path, archive mtime, offset,
packed size, unpacked size, flags, and entry name. A cached hash is reused
only when every key field matches.

## Manifest v2 files

```text
<DATA_MANIFEST_DIR>/<version>/root
<DATA_MANIFEST_DIR>/<version>/root.sig
<DATA_MANIFEST_DIR>/<version>/shards/00
...
<DATA_MANIFEST_DIR>/<version>/shards/ff
```

`root` is an unsigned canonical `GDAT2ROOT` document. It lists all 256
shards. Each shard is a canonical `GDAT2SHARD` document whose version line
is the root version. A new version writes a new root and every shard,
because the version line is part of the hashed shard bytes. Republishing
the same version leaves identical shard bytes in place (hard-linked when a
previous file is already byte-identical). `root.sig` is not written by
this process.

Clients check file bytes against the shard entry and check that the shard
version equals the root version. Fetch the shard whose id is the first
byte of `SHA-256` over the normalized path.

## Endpoints

Existing:

- `X-Data-Version: <n>` on every response, also in `Access-Control-Expose-Headers`
- `GET /version` (and `HEAD`) → `{"version": n}` (`Cache-Control: no-cache`)
- `GET /changes?since=<v>` → `{"version": n, "paths": [...]}` or `{"version": n, "full": true}` (`Cache-Control: public, max-age=5`)
- `GET /data-manifest` or `GET /data-manifest?version=<n>` → the legacy GDAT1 envelope, or 404

Manifest v2 (`Content-Type: text/plain; charset=utf-8`):

- `GET /data-manifest/v/<version>/root`
- `GET /data-manifest/v/<version>/root.sig` → 404 until the operator publishes it
- `GET /data-manifest/v/<version>/shards/<hh>` where `<hh>` is `00`–`ff`. Anything else is 400
- `GET /data-manifest/root`, `/data-manifest/root.sig`, and `/data-manifest/shards/<hh>` follow the live version (`Cache-Control: no-cache`)

Versioned shard and root responses use `Cache-Control: public, max-age=31536000, immutable`.
The signature response uses `no-cache`, so a signature can show up after
the root is already published. A missing version or signature is 404.

When `root.sig` appears or changes, the process checks it with the release
public key only and logs whether it verifies. An invalid signature is
still served. Clients decide what to do with it. No private key is
required to start or serve.

## Sign the root (offline)

On the machine that holds the seed, after this host has written
`<version>/root`:

```sh
scripts/sign-data-root \
  --private-key /path/to/seed \
  --root /path/to/manifests/N/root \
  --out /path/to/manifests/N/root.sig
```

`--private-key` is required. The file is a 32-byte Ed25519 seed or 64 hex
characters. The script asks OpenSSL for a raw Ed25519 signature and writes
128 lowercase hex characters plus a newline. Copy only `root.sig` into that
version directory on this host.
The script refuses a root that is not canonical `GDAT2ROOT` (optional
`next-keys` section included). Do not point it at a live data directory
from this host.

An optional `next-keys` section, after the 256 shard lines, lists
replacement public keys:

```text
next-keys
<count>
<64 lowercase hex>
```

Keys are strictly increasing, not all zero, at most 8. Empty `next-keys`
is omitted.

## Legacy GDAT1

`GET /data-manifest` still returns an operator-published `{version}.gdat`
or `manifest.gdat` when one of those files is present. v2 clients use the
routes above instead of that flat list.

Do not deploy this change from CI. Do not put a private key in any
environment variable on this host.
