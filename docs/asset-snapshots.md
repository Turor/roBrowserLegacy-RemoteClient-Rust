# Immutable allowlisted raw-asset snapshots (opt-in; not deployed)

The Rust client needs a finite file list and verifiable raw bytes so its local
copy can become complete and work offline. New endpoints:

- `GET /api/assets/v1/manifest`
- `GET /api/assets/v1/blobs/{lowercase_sha256}`

These routes return 404 unless a valid snapshot is explicitly configured.
Existing browser routes and BMP conversion behavior are unchanged. Snapshot
blobs are original raw asset bytes; browser image conversion is never applied.

## Explicit build and activation

Run from the normal remoteclient working directory with its normal GRF and
allowed overlay configuration, **while source files are not being edited**:

```sh
remoteclient2 build-asset-snapshot --output /var/cache/remoteclient-assets/snapshot-001
```

The parent directory must exist; the output directory must not. The command
never activates/deploys anything. Failed/interrupted output is not a snapshot:
a valid manifest is written last. Use a fresh directory for the next attempt.
No snapshot data or Gravity art belongs in git. Size the snapshot disk for all
extracted raw files (content-identical files share one blob); it is not a GRF.

Only after review and separate deployment approval, set
`ASSET_SNAPSHOT_PATH=/var/cache/remoteclient-assets/snapshot-001` and restart the
appropriate **test** service. Startup rehashes all blobs and fails closed for an
incomplete/invalid snapshot. Startup validation is proportional to total asset
size; build and validate on test before planning a service restart. Production
activation is intentionally not part of this PR.

Keep older snapshot directories available for clients already pinned to them,
or provide a dedicated origin per snapshot. The current server configuration
serves one snapshot; switching it can make an older client's still-missing blobs
unavailable. Existing complete client caches remain fully offline.

## Snapshot contract

`manifest.json` is compact JSON with fields in this order:

- `format_version`: integer `1`
- `revision`: SHA-256 hex of the compact JSON serialization of `files`
- `files`: strictly path-sorted, nonempty array of objects with fields in order:
  `path` (canonical lowercase forward-slash virtual path), `size` (raw byte
  count), `sha256` (lowercase raw-content SHA-256).

Filenames are Unicode, not URL-encoded strings. The client requests blobs by
hash, not virtual path, avoiding path-encoding ambiguity for Korean filenames.
Manifest maximum is 64 MiB; each asset maximum is 100 MiB. Files outside the
existing asset roots (`data`, `bgm`, `system`, `systemen`, `ai`) are never included.
Absolute paths, hidden segments, traversal, empty segments, percent escapes,
query/fragment characters, drive prefixes and control characters are rejected.

The builder preserves first-GRF-wins and applies declared loose-file precedence:
working-directory asset roots, configured OVERLAY_PATH, DATA_OVERRIDE_PATH, GRF.
It enumerates only those declared asset roots and never follows symlinks. It
prunes the internal `System/overlay` subtree from public System enumeration,
while processing the configured overlay root as virtual game files.

The HTTP handlers use a preloaded manifest and only its approved digest set,
not arbitrary path joining, live directory listing, or `Client::get_file`.
Every response is rechecked against the recorded size and hash. Manifest errors
and failed blob reads do not expose server paths or configuration. Blob storage
must remain administrator-owned and immutable while served. HTTP hashes are
integrity checks; production authentication relies on the trusted HTTPS origin.

## Tests

`cargo test --bin remoteclient2`: 17 passed. New coverage checks strict paths,
forbidden manifest entries, incomplete snapshots, tampered bytes, symlink blobs,
first-GRF-wins, overlay precedence, exclusion of service files, opt-in routes,
and digest authorization. Fixtures are synthetic, not Gravity assets.

Cross-repository test with Korangar's new `fetch_assets` example downloads two
raw synthetic assets from an actual instance of this binary, then succeeds again
after that instance terminates. No rodata-dev or live service was changed.
