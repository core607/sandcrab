# Files

```sh
sandcrab files mkdir --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID src/pkg --mode 750
sandcrab files put --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID ./input.bin nested/input.bin --parents
sandcrab files ls --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID . --depth 2
sandcrab files search --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID '*.bin' --path .
sandcrab files read --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID nested/input.bin --bytes 0-63
sandcrab files rm --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID nested --recursive
tar -cf project.tar -C ./project .
sandcrab files put --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID ./project.tar project --tar
sandcrab session exec --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID -- 'cd project; python3 main.py'
sandcrab files get --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID project ./result.tar --tar
sandcrab files status --socket /var/lib/sandcrab/runtime/control.sock UPLOAD_ID
sandcrab files cancel --socket /var/lib/sandcrab/runtime/control.sock UPLOAD_ID
sandcrab files forget --socket /var/lib/sandcrab/runtime/control.sock UPLOAD_ID
sandcrab files list --socket /var/lib/sandcrab/runtime/control.sock
```

Raw `files put` streams one request without hashing the source first. `--id`,
`--keep-result` or `--tar` selects a staged upload. Discovery exposes ordinary
transfers and workspace inspection under `capability=files` and staged operations
under `capability=uploads`.

```sh
curl --unix-socket /var/lib/sandcrab/runtime/control.sock --upload-file ./input.bin \
  'http://localhost/v1/sessions/SESSION_ID/files?path=nested/input.bin&parents=true'
```

`PUT /v1/sessions/ID/files?path=PATH` accepts fixed-length or chunked raw bytes,
including an empty file. It replaces a regular file atomically by default;
`replace=false` refuses an existing target. Optional `mode` is a decimal permission
mask, default 420 (0644). Optional `parents=true` (CLI `--parents`, also accepted on
staged `POST /v1/uploads`) creates missing relative parent directories with mode
0755 after validating existing ancestors; symlink or non-directory ancestors are
refused before mutating. The reply contains `path`, received `bytes` and `sha256`.
Publication and staging cleanup finish before success. The session keeps running;
concurrent commands can change the destination. A lost reply or `PUBLICATION_UNKNOWN`
requires destination inspection before another write. This route retains no upload ID.

`GET /v1/sessions/ID/files?path=PATH` (CLI `files read`, defaulting destination to
`-` stdout) streams a private snapshot of a workspace regular file, emitting
`X-Sandcrab-Server-Id` and a quoted SHA-256 `ETag` on full reads. Supplying `Range`
(`bytes=START-END`, `bytes=START-` or `bytes=-SUFFIX`, CLI `--bytes RANGE`) returns
HTTP 206 with `Content-Range` and `Accept-Ranges: bytes`; empty files, zero suffixes
and starts past EOF return 416. Supplying one-based `offset` and/or positive `limit`
(CLI `--offset` and `--limit`) returns HTTP 200 `text/plain; charset=utf-8` with
selected lines stripped of CR/LF endings and joined with LF. Symlinks, `If-Range`,
multiple byte ranges and combined byte/line selections are refused. Partial reads
omit `ETag`, bound selected and scanned bytes by `transfer_bytes`, and do not form
a multi-request transaction. Local file destinations on `files read` verify length
(and full-file `ETag`) and require `--replace` for an existing regular file.

For a subsequent edit, send `X-Sandcrab-Read-Version: sha256` with the GET.
Sandcrab freezes guest writers while capturing the requested bytes and the
whole-file digest. The response carries that digest in `X-Sandcrab-File-Sha256`,
including on byte and line selections. A selection from a file larger than
`transfer_bytes` returns its content without a digest.

`POST /v1/sessions/ID/files/edit` accepts a relative `path`, the
`expectedSha256` from the read, literal `old` text and its `new` replacement.
The helper checks the version, replaces exactly one occurrence and preserves
permissions while guest writers are frozen. A stale digest returns HTTP 409
`EDIT_CONFLICT`. Zero or multiple matches return HTTP 409 `EDIT_MATCH_COUNT`.
Both leave the file untouched. An overlapping file operation can return
`SESSION_FILES_BUSY`; retry that refusal with the original digest. If the
reply is lost, inspect the file before another edit.

`POST /v1/sessions/ID/files/mkdir`, `GET /v1/sessions/ID/files/list` (`path`, default
`.`; `depth` 0..64, default 1) and `GET /v1/sessions/ID/files/search` (`pattern` up
to 1024 bytes, optional `path`) run in the bounded frozen file helper without
traversing symlinks. Directory creation creates missing relative parents and applies
optional decimal `mode` (CLI `--mode OCTAL`, default 0755) to new directories.
Listing and search return workspace-relative paths, `type` (`file`, `directory`,
`symlink`, `other`), `size`, decimal permission bits (`mode`), `modifiedAt` and
`createdAt` within a 60,000-byte JSON response bound; search walks at most 10,000
entries and 64 levels matching non-directory basenames.
Add `contains` to select regular files containing up to 1,024 bytes of literal
UTF-8 search text. The profile's `transfer_bytes` bounds the total bytes
scanned across matching filenames. Exhaustion returns `FILE_LIMIT`.

Paths are relative to `/workspace`, preserving case and Unicode. Unless
`parents=true` or `--parents` is set, upload parents must already exist. Raw uploads
install one file; tar uploads install one complete directory. Existing staged or CLI
targets require `--replace`; tar replacement replaces the whole directory rather
than merging its entries. `--mode OCTAL` chooses ordinary permission bits for a raw
file or the tar root. Archive entries retain ordinary modes and links, with
ownership assigned to the profile. Special nodes, sparse entries, traversal paths
and writes through symlinks are refused. Symlinks remain opaque; snapshots never
follow them. Hard links must name an earlier regular entry inside the archive.
Extended attributes and original ownership are not preserved.

Staged uploads verify declared length and SHA-256 before publication. Native
transfers keep workspace processes running unless a snapshot requests `frozen=true`.
Otherwise callers coordinate writers when they need a consistent collection.
Tar downloads contain ordinary entries, with no
private manifest format. A transfer pins its
session and volume until helper containment and staging cleanup finish; cancellation,
expiry and shutdown cannot detach storage underneath it. Unconfirmed cleanup holds
admission until restart. Temporary staging counts against workspace or volume limits.
`DELETE /v1/sessions/ID/files?path=PATH` (CLI `files rm`, with `--recursive` for
`recursive=true`) removes a file or directory tree without executing shell source.
Paths follow the same workspace boundary and opaque-symlink rules. Deletion remains
available during storage overage.

| Request | Result |
|---|---|
| `GET /v1/sessions/ID/files?path=PATH` | Read a raw file, a single `Range` byte slice (206) or `offset`/`limit` UTF-8 lines |
| `PUT /v1/sessions/ID/files?path=PATH` | Stream one raw file; optional `replace`, `parents` and `mode` |
| `DELETE /v1/sessions/ID/files?path=PATH` | Remove a file, or a directory tree with `recursive=true` |
| `POST /v1/sessions/ID/files/mkdir` | Ensure `path` and missing relative parents with optional `mode` |
| `POST /v1/sessions/ID/files/edit` | Replace one exact match guarded by the whole-file digest |
| `GET /v1/sessions/ID/files/list` | List workspace entries under `path` (default `.`) up to `depth` (0..64, default 1) |
| `GET /v1/sessions/ID/files/search` | Search non-directory basenames under `path` matching glob `pattern` |
| `POST /v1/uploads` | Register `id`, `serverId`, `sessionId`, `path`, `format` (`raw` or `tar`), `bytes`, `sha256`, optional `replace`, `parents`, `mode`, `keepResult`; returns 201 |
| `PUT /v1/uploads/ID/content` | Send exactly the registered Content-Length; return the upload record |
| `GET /v1/uploads/ID` | Read outcome and publication certainty |
| `GET /v1/uploads?after=UUID` | Up to ten records in UUID order; continue with `nextAfter` |
| `POST /v1/uploads/ID/cancel` with `{}` | Cancel pending or active work; inspect the final record |
| `POST /v1/uploads/ID/forget` with `{}` | Forget a waiting or terminal record when no stage remains |
| `POST /v1/sessions/ID/snapshot` | Send `path`, `format` and optional `frozen`/`scope`; receive a fixed-length body with a quoted SHA-256 ETag |

Native snapshot replies include `X-Sandcrab-Server-Id`, the serving daemon epoch.
Clients retaining a session handle must match this header against its `serverId`
before exposing snapshot bytes; a missing or different epoch cannot identify that session.

Bulk requests close their connection. Upload bodies support `Expect: 100-continue`
after admission; other expectations are refused. Profile `transfer_bytes` bounds
both stream bytes and expanded regular-file content. Workspace file archives have a
10,000-entry limit including implicit parents; filesystem captures use the template limit. Upload body I/O, capture and publication each
have a 30-second budget; snapshot body writes have a separate 30-second budget.
Cleanup has a ten-second helper budget. Service `max_file_transfers` bounds active
operations; each session allows only one file operation. `max_file_records` bounds
retained upload identities independently of run and session records. Info exposes
the configured limits and whether file metadata is writable.

Use staged uploads for large build artifacts or archive imports when a dropped
reply must be reconciled by operation ID, including after daemon restart. Partial
bodies restart from zero; the retained receipt records publication state.
Retained records survive daemon restart while their configured storage survives. Reusing
an ID with the same plan returns its record, excluding `serverId` from the digest;
a different plan conflicts. Unknown IDs require the current epoch and a live session.
States are `waiting`, `receiving`, `publishing`, `published`, `succeeded`, `failed`,
`unknown` and `closing`. `publication` is `none`, `unknown` or `committed`.
Cancellation does not undo a committed write. After an ambiguous publication,
inspect the destination and receipt before choosing another write; replay never
reexecutes it. Forgetting or result expiry ends replay protection, so never reuse that ID.

Runtime and upload metadata follow the 0.x binary schema without migrations.
Before a schema-changing upgrade, export needed disposable workspaces and use the
old binary to reconcile and forget retained uploads. Stop and contain the old
service, back up runtime and configured storage roots, then rebuild affected
metadata as needed while preserving volume data.

For staged transfers, the CLI prints the upload ID before submission. It forgets successful or failed
uploads unless `--keep-result` is set, and retains uncertain outcomes. `--id UUID`
reconciles an explicit replay. Downloads verify length and ETag before atomically
installing a local file; `--replace` is required to replace an existing regular
file. A failed download preserves that file. A destination of `-` streams to stdout,
where already-written bytes cannot be withdrawn after a failure. Snapshots are
request-scoped and leave no retained artifact; consumers own downloaded copies.

### Filesystem capture

After preparing and validating a session, capture its files for template import:

```sh
sandcrab template capture --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID prepared.tar
sandcrab template import --socket /var/lib/sandcrab/runtime/control.sock --profile default prepared.tar
```

Capture uses the existing snapshot route with `path="."`, `format="tar"`,
`frozen=true` and `scope="filesystem"`. It freezes the owning session cgroup,
including child shells, while the bounded helper copies the merged tree. File
transfer admission excludes concurrent API file mutations. The session thaws
before body delivery; a failed thaw cancels it. Commands and expiry retain their
deadlines. External host writers and application-level transactions remain the
operator's responsibility.

For a workspace session, the tree is `/workspace`. For a rootfs session, it is the
template root with its current writable changes. Process-only mounts such as
`/proc`, `/dev`, private `/tmp`, host tools and control channels are absent;
protected rootfs mount anchors remain empty files or directories. Deletions are
already resolved in this complete view. Plain tar preserves supported links,
ordinary permission bits and file contents; import normalizes ownership as
documented under [templates](templates.md#templates). No process, shell variable or working
directory is saved. Avoid putting credentials or reference answers in the tree.

`filesystem` requires a frozen, whole-tree tar; callers cannot choose a host root.
It uses the profile's transfer-byte bound, the template entry limit and existing
helper resource/deadline bounds. Ordinary snapshots default to `scope="workspace"`
and `frozen=false`. `frozen=true` also works for a workspace file or directory.

The CLI verifies the serving epoch, length and SHA-256, then installs a new local
file with mode 0600. It never replaces a destination or automatically retries a
capture. A complete file can be retained and imported after the source session
ends. A partial or lost download does not publish a template; capturing again
observes a later filesystem state. Inspect the template catalog after a lost
import reply and retain the exact captured archive for reconciliation.

Filesystem capture replies also carry `X-Sandcrab-Template-Id`,
`X-Sandcrab-Profile` and `X-Sandcrab-Rootfs`. The ID predicts the normalized import
under that profile; source ownership and the root mode are normalized by the same
identity scan used for imports. The additional scan shares the existing frozen
helper's deadline and resource bound. The CLI includes this identity as `template`
in its JSON receipt. Retain that receipt and use `--expected-id` when importing.
The [Python extension](../../../sdk/python/README.md) performs this workflow with the
published OpenSandbox SDK and exposes read-only reconciliation after response loss.
