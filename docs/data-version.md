# Data version, change log, and signed manifests

remoteclient2 can stamp a monotonic `X-Data-Version` on every response and
answer `GET /version` and `GET /changes?since=<v>` so clients drop only the
files that changed. A signed GDAT1 manifest for each version is **published
offline**; this host never holds the signing seed.

## Enable

Set `DATA_VERSION=1`. Optional:

| Variable | Default | Role |
|---|---|---|
| `DATA_VERSION` | `false` | Stamp the header and serve `/version`, `/changes`, `/data-manifest` |
| `DATA_VERSION_STATE_DIR` | `state` | `data-version.json` and `changes.jsonl` |
| `DATA_MANIFEST_DIR` | `state/manifests` | Operator-copied `{version}.gdat` files |
| `DATA_VERSION_LOOSE_ROOT` | process cwd when enabled | Extra `System/` and `data/` trees to scan |

The first version is the Unix time in seconds. Later bumps are `n+1`. A
missing state file restarts from `max(now, last known)` so versions never
go backwards (clients treat that as "too old, full recheck").

Rescans run when overlay directories or GRF archives change, debounced
about 5 seconds. Loose overlay files are listed by path; a replaced GRF
whose entries cannot be diffed cheaply is logged as `"full": true`.

## Endpoints

- `X-Data-Version: <n>` on every response, also in `Access-Control-Expose-Headers`
- `GET /version` (and `HEAD`) → `{"version": n}` (`Cache-Control: no-cache`)
- `GET /changes?since=<v>` → `{"version": n, "paths": [...]}` or `{"version": n, "full": true}` (`Cache-Control: public, max-age=5`)
- `GET /data-manifest` or `GET /data-manifest?version=<n>` → the operator-published GDAT1 envelope, or 404

## Publish a signed manifest (offline)

Sign on the machine that holds the seed. Never copy the seed to this host.

```sh
goro-sign-release sign-data \
  --private-key /path/to/seed \
  --version N \
  --root /path/to/served/tree \
  --out N.gdat
```

Copy only `N.gdat` into `DATA_MANIFEST_DIR` on this host (also as
`manifest.gdat` if you want `/data-manifest` without a version query).

To carry a next-key list before retiring the current key:

```sh
scripts/release/rotate-signing-key.sh \
  --private-key /path/to/seed \
  --new-public-key HEX \
  --kind data \
  --version N \
  --root /path/to/served/tree \
  --out N.gdat
```

Do not deploy this change from CI. Do not put a private key in any
environment variable on this host.
