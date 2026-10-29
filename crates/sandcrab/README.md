# Sandcrab native service

`sandcrab` is a standalone Linux daemon and CLI for finite commands, persistent
bash sessions, durable volumes, streamed files and live command output. It needs no Poketto account, workspace, repository,
signing key or compiled extension. The service uses a Unix socket or optional
authenticated loopback TCP; host calls and the OpenSandbox adapter remain under the
[service proposal](../../../notes/proposed/2026-10-26-sandcrab-sandbox-service.md).

## Installation

Build with `./gradlew buildExecutorRust`; the static binary is
`build/executor-service/bin/sandcrab`. It is excluded from the Poketto worker bundle.
Install it with mode 0755 in a root-owned directory with root-owned ancestors. The host needs
systemd, cgroup v2, unprivileged user namespaces, bubblewrap and the pinned seccomp
helper from the executor's [tool preparation](../../prepare-tools.sh).

Copy [config.example.toml](config.example.toml) to a root-owned file with mode 0600
in a protected directory. Set the client's numeric UID/GID and a separate execution
account. Profiles choose readable paths, tools, finite resource limits and
`network = "none"`; calls can lower timeout and output limits but cannot select
accounts, mounts or isolation policy. Sessions need `/bin/bash` and its libraries
in the profile's read mounts. Read mounts cannot expose runtime storage.

Configure the slice with finite `MemoryMax`, `MemorySwapMax`, `TasksMax` and
`CPUQuota`, then run `sandcrab serve --config FILE` as root in `supervisor_unit`
under that slice. Give the supervisor its own memory/task limits. Startup requires
that unit's MainPID, verifies the pool and tools, takes the runtime lock and cleans
up previous runs. `sandcrab check --config FILE` checks protected configuration,
accounts and tools; it does not prove the runtime slice or sandbox works.

Each run executes as the profile's account in a fresh bounded tmpfs at
`/workspace`, with a private `/tmp`, isolated network and PID namespaces and
seccomp. It shares the host kernel; this is not a microVM boundary. Workspace bytes
are disposable unless a session attaches a durable volume. Read mounts are the operator's responsibility.

## CLI

```sh
sandcrab info --socket /run/sandcrab-demo/control.sock
sandcrab run --socket /run/sandcrab-demo/control.sock --profile python -- python3 -c 'print(6 * 7)'
sandcrab get --socket /run/sandcrab-demo/control.sock RUN_ID
sandcrab cancel --socket /run/sandcrab-demo/control.sock RUN_ID
sandcrab forget --socket /run/sandcrab-demo/control.sock RUN_ID
```

`run` prints its recovery ID to stderr before submission, polls to a terminal
result, prints JSON and forgets the record. Exit zero means the command succeeded;
other outcomes exit nonzero. SIGINT/SIGTERM requests cancellation. A lost response
does not submit a new run: inspect the printed ID. `closing` means containment or
workspace cleanup was not confirmed; its admission remains held until restart.
For Unix transport, the CLI authenticates the root-owned socket and root peer before sending commands.
If forgetting a terminal record fails, the CLI warns on stderr and preserves the
command's exit result. Inspect or forget the printed ID instead of rerunning it.

## Loopback TCP

Enable `[tcp]` in [config.example.toml](config.example.toml) with a literal
loopback address and nonzero port. Wildcard addresses, nonlocal IPs and DNS names
are refused. The Unix socket remains available; both listeners share the same
server epoch, records, connection limit and observer limit. Failure to bind either
listener fails startup.

`token_file` must be outside runtime and volume storage, owned by root, singly
linked and mode 0600 or 0400, beneath protected nonsymlink directories. Generate
its 64 lowercase hexadecimal bytes with `openssl rand -hex 32` under `umask 077`.
An optional final newline is accepted. Read mounts cannot expose this file.
Distribute a private copy to each authorized client; holders can use every
configured profile and control every record in this service.

Every TCP request requires `Authorization: Bearer TOKEN`, including info,
OpenAPI, events and file bodies. Missing or incorrect credentials return 401
`AUTH_REQUIRED` and close the connection before body admission or `100 Continue`.
Authentication is checked again on each reused connection request. The daemon
loads the token at startup; replacing its file takes effect after restart, which
also ends live runs and sessions under the existing lifecycle contract.

Any client command can replace `--socket PATH` with `--endpoint URL`:

```sh
sandcrab --token-file ./client.token info --endpoint http://127.0.0.1:9011
sandcrab --token-file ./client.token run --endpoint http://127.0.0.1:9011 --profile python --stream -- python3 -c 'print(6 * 7)'
```

`SANDCRAB_TOKEN_FILE` supplies the client path when the global flag is absent.
The client copy and every directory above it must belong to root or that client;
the file has no group/other permissions and directories are not writable by other
accounts. Symlinks, hard-linked files and parent traversal are refused. Credentials
are read once per command and sent only to a literal loopback TCP endpoint; there
is no transport fallback or automatic request replay.

TCP uses plaintext HTTP and does not attest the listener's process identity.
The operator must keep the selected endpoint exclusive and trust other host
processes; the sandbox's isolated network cannot reach host loopback. Token
authentication does not provide remote TLS, per-client roles or tenant isolation.

## HTTP

HTTP/1.1 connections accept sequential requests until `Connection: close`, an
invalid message, the 128th response or shutdown. Reading a request, including idle
time, and writing its JSON response each have a five-second deadline. An idle connection
closes without sending an unsolicited error. File bodies use the limits below. The CLI reuses connections while
polling and reconnects after a declared close; transport failures are returned
without replay. `max_connections` defaults to 32. POST bodies declare a content
length of 1 to 65536 bytes; GET requests have no body. Headers are at most 8192 bytes
and 32 fields. Only event responses use chunked framing; requests and other responses
require fixed lengths. Duplicate headers and upgrades are rejected; pipelining is unsupported. Only `client_uid` is accepted, even if another
account can connect to the socket. TCP uses the bearer credential above.

| Request | Result |
|---|---|
| `GET /v1/info` | API version, server epoch, capabilities and profile limits |
| `GET /v1/openapi` | The bundled [OpenAPI contract](openapi.json); `?capability=runs`, `sessions`, `volumes`, `files` or `events` selects a bounded view with its referenced schemas |
| `POST /v1/runs` | Admit a run; return 202 with its state |
| `GET /v1/runs/ID` | Read current state and any terminal result |
| `POST /v1/runs/ID/cancel` with `{}` | Request cancellation; poll until terminal |
| `POST /v1/runs/ID/forget` with `{}` | Release a terminal result and its replay identity |

Submit JSON with `id` (a fresh UUID), `serverId` from info, `profile`, and an argv
array `command`. Optional `timeoutMillis` and `outputLimitBytes` only narrow the
profile. Unknown fields are errors. Within one epoch, repeating the same ID and
request returns the existing run; changed arguments give `ID_CONFLICT`. A stale
epoch gives `SERVER_CHANGED`. After restart old outcomes are unknown, not proof of
nonexecution. Forgetting explicitly ends replay protection; never reuse that ID.

States are `running`, `succeeded`, `failed`, `cancelled`, `timed_out`, `output_limit`,
`resource_limit` and `closing`. Terminal results include exit code, stdout, stderr
and truncation, or a failure code. Output bounds apply to combined raw stdout and
stderr; invalid UTF-8 becomes replacement characters. Runs continue after HTTP
disconnect and remain bounded by their timeout. Cancellation does not undo work.

`max_sandboxes` bounds live runs and sessions together; it replaces `max_runs` in
native TOML configurations. `RUN_CAPACITY` or `SESSION_CAPACITY` refuses before execution. `RESULT_CAPACITY` means retained records
or output reservations must be forgotten. Session records and command results share
`max_records`; command output remains reserved until its result is forgotten. `max_output_bytes` bounds reserved raw
output, not total process memory; the slice bounds runtime, tmpfs and overhead.
Reserve enough supervisor memory for encoded responses and retained output.

## Command events

Add `--stream` before `--` to `run` or `session exec` to print exact stdout and
stderr bytes as they arrive. Recovery IDs and CLI diagnostics also use stderr.
The command's terminal outcome still controls the CLI exit status and forgetting.
To observe a retained run without cancelling or forgetting it, use:

```sh
sandcrab events --socket /run/sandcrab-demo/control.sock RUN_ID
sandcrab events --socket /run/sandcrab-demo/control.sock RUN_ID --after CURSOR
```

This observer prints newline-delimited JSON containing `event`, `id` and `data`.
HTTP clients use `GET /v1/runs/ID/events`, a chunked SSE response. Each complete
event carries an opaque `id`; explicit reconnects send it as `Last-Event-ID`.
The initial `state` carries run metadata without output. `stdout` and `stderr`
carry a starting byte `offset` and `base64` block of at most 4096 raw bytes. Ordering
is per stream; blocks need not end at UTF-8 boundaries. `result` carries the
terminal summary and both total byte counts after command containment is confirmed.
EOF, heartbeat comments and `error` events do not acknowledge completion.

An observer owns no command lifetime. Disconnect, a five-second frame write
deadline or the 350-second observation deadline ends only the subscription.
Keep the run record until observation finishes. Resume cursors bind its incarnation
and both byte offsets; malformed cursors return 400, mismatches 409, and forgotten
records 404. The CLI never reconnects or submits another command automatically.
An observation error reports the last complete cursor for explicit recovery.
A complete terminal frame remains acknowledged even if the final HTTP zero chunk
is lost; consume that zero chunk before reusing the connection.

`max_event_streams` defaults to 16 and must leave at least four of
`max_connections` for control calls. A full observer pool returns 429
`EVENT_CAPACITY`. Info exposes these limits and `events.activeStreams` as a
concurrent snapshot. Observers read bounded retained output; they never hold a
command's capture loop waiting for a reader. Output is retained once after completion;
while executing, capture and progress buffers can each hold the reserved bytes.

## Persistent sessions

```sh
sandcrab session open --socket /run/sandcrab-demo/control.sock --profile python --ttl-ms 60000
sandcrab session exec --socket /run/sandcrab-demo/control.sock SESSION_ID -- 'mkdir project; cd project; export VALUE=42'
sandcrab session exec --socket /run/sandcrab-demo/control.sock SESSION_ID -- 'printf "%s\n" "$VALUE"; pwd'
sandcrab session renew --socket /run/sandcrab-demo/control.sock SESSION_ID --ttl-ms 60000
sandcrab session close --socket /run/sandcrab-demo/control.sock SESSION_ID
sandcrab session forget --socket /run/sandcrab-demo/control.sock SESSION_ID
```

`open` prints its recovery ID before submission and waits for `ready`. `exec`
accepts one quoted bash source argument, prints a run recovery ID, waits for its
outcome and forgets that command result. `close` waits for confirmed termination
and also succeeds for an already expired or failed session whose cleanup finished.
`get` reads state without waiting. The [build/test example](../../../examples/sandcrab-build-test.sh)
uses ordinary Python files and shell state across separate client connections.

A session preserves its working directory, environment, shell functions, files,
`/tmp` and background processes. Only one command may run at a time. A nonzero
command exit preserves the session while its shell remains alive. A shell exit,
command cancellation, timeout, output overflow or runtime failure ends the session.
A kernel OOM kill ends the whole session and reports `resource_limit`, even when
the shell catches a child's failure. Exit code 137 alone is not OOM evidence.
The daemon never silently resets its state. Closing or expiry also stops background
processes before releasing storage and admission. Without a volume, copying data
into a session is not a durable save.

`session_ttl_millis` is the profile's default and maximum lifetime per open or
renewal, from 100 ms through one day. Expiry uses a monotonic clock and includes
startup and idle time. Renewal moves a live deadline from the current time; it
cannot revive an expired or closed session. Disconnects do not stop or renew it.
A run's timeout and output limits still apply to each command independently.

| Request | Result |
|---|---|
| `POST /v1/sessions` | Open with `id`, `serverId`, `profile`, optional `ttlMillis` and `volumeId`; returns 202 |
| `GET /v1/sessions/ID` | State, expiry estimate and any active run ID |
| `POST /v1/sessions/ID/commands` | Execute `command` bash source with a fresh `id`, `serverId` and optional `timeoutMillis`/`outputLimitBytes`; returns 202 |
| `POST /v1/sessions/ID/renew` | Renew with `ttlMillis` |
| `POST /v1/sessions/ID/close` with `{}` | Request closure; poll until terminal |
| `POST /v1/sessions/ID/forget` with `{}` | Forget a terminal session's identity |

Use `/v1/runs/RUN_ID` to inspect, cancel or forget a session command. Exact command
replays return their retained record even after the session ends or is forgotten;
changed commands or another session using the ID conflict. `SESSION_NOT_READY`
refuses commands while starting, busy or ended. A record's `sessionId` identifies
its session; names, profiles and IDs confer no authority beyond the socket's peer.

Session states are `starting`, `ready`, `busy`, `stopping`, `closed`, `expired`,
`failed` and `closing`. Only the first three accept renewal. `closing` means
containment or storage cleanup is unconfirmed; it cannot be forgotten and holds
admission until restart. Result records are forgotten separately from sessions.
A restart terminates sessions and removes their ephemeral workspaces. The changed
server epoch refuses old create/command requests; a missing result does not prove
that the command never ran.

## Durable volumes

Enable the optional `[storage]` section in the example configuration. Provision a
dedicated XFS mount at `storage.root/data` with reflinks, enforced project quotas
(`prjquota` or `pquota`), `nosuid` and `nodev`. Its filesystem size must not exceed
`pool_bytes`. Install `xfsprogs` under `/usr/sbin`. The root and its ancestors must
be root-owned, non-writable by other accounts and searchable by execution accounts.
The daemon creates private control metadata at `root/state` on a different filesystem.
It never formats a disk, remounts a filesystem or adopts a nonempty unowned store.
Profiles cannot expose this storage through their read mounts.

```sh
sandcrab volume create --socket /run/sandcrab-demo/control.sock --profile python --bytes 8388608 --inodes 256
sandcrab session open --socket /run/sandcrab-demo/control.sock --profile python --volume VOLUME_ID
# Execute commands, then close the session before cloning or deleting its volume.
sandcrab volume create --socket /run/sandcrab-demo/control.sock --profile python --clone-from VOLUME_ID
sandcrab volume list --socket /run/sandcrab-demo/control.sock
sandcrab volume get --socket /run/sandcrab-demo/control.sock VOLUME_ID
sandcrab volume delete --socket /run/sandcrab-demo/control.sock VOLUME_ID
sandcrab volume forget --socket /run/sandcrab-demo/control.sock VOLUME_ID
```

A volume is an ordinary directory mounted at `/workspace`. Session closure,
expiry and daemon restart retain its files; shell state and `/tmp` remain
ephemeral. Application writes follow normal filesystem synchronization semantics;
closing a session is not an atomic snapshot or a power-loss commit for those writes.
The selected profile must use the volume's execution UID/GID. One session owns a
volume exclusively until confirmed cleanup; a failed cleanup retains that ownership.
Cloning requires an unattached source and holds it for the operation. Reflinks
preserve hard links and symlinks without following them, and subsequent writes
are independent. Clone work uses the selected profile's bounded unit and timeout.

Byte quotas count allocated XFS blocks, including managed metadata, rather than
sparse logical lengths. Inode quotas also count managed metadata. Requests may
only lower the configured maxima; byte limits are multiples of 1024. Quota failure
can report `ENOSPC` or `EDQUOT` inside a session. `max_volumes` bounds live volumes;
storage `max_records` separately bounds durable records. `STORAGE_CAPACITY`
allows one mutation at a time. A full data pool still permits recording deletion
on the separate control filesystem.

| Request | Result |
|---|---|
| `POST /v1/volumes` | Create with a UUID `id`, current `serverId`, `profile`, optional `cloneFrom`, `byteLimit` and `inodeLimit`; returns 202 |
| `GET /v1/volumes/ID` | Read state, quotas, plan digest and ownership |
| `GET /v1/volumes?after=UUID` | Up to 100 records in UUID order; continue with `nextAfter` |
| `POST /v1/volumes/ID/delete` with `{}` | Persist deletion intent, then remove an unattached volume |
| `POST /v1/volumes/ID/forget` with `{}` | Forget a failed or deleted record after its data is absent |

States are `creating`, `ready`, `deleting`, `deleted`, `failed` and `closing`.
Only `ready` can attach. Creation IDs bind a normalized plan digest across daemon
restarts; `serverId` is excluded. An existing ID with the same plan replays its
current state, including failure or deletion; different plans conflict. An unknown
ID needs the current server epoch. The CLI prints its recovery ID before submission;
`--id UUID` permits an explicit replay. Never substitute a new ID after a lost response.
Forgetting ends replay protection; never reuse that client ID.

Startup contains prior units before recovering unfinished creation or deletion.
Published volumes remain intact. Uncertain metadata or volume cleanup fences
mutations (`STORAGE_UNCERTAIN`, `storage.available=false`) until restart and
reconciliation; it never exposes uncommitted data as ready. Unexpected data,
mounts or a changed cleanup namespace require operator reconciliation and are
preserved. Keep the store and its matching runtime configuration together.

## Files

```sh
sandcrab files put --socket /run/sandcrab-demo/control.sock SESSION_ID ./input.bin input.bin
tar -cf project.tar -C ./project .
sandcrab files put --socket /run/sandcrab-demo/control.sock SESSION_ID ./project.tar project --tar
sandcrab session exec --socket /run/sandcrab-demo/control.sock SESSION_ID -- 'cd project; python3 main.py'
sandcrab files get --socket /run/sandcrab-demo/control.sock SESSION_ID project ./result.tar --tar
sandcrab files status --socket /run/sandcrab-demo/control.sock UPLOAD_ID
sandcrab files cancel --socket /run/sandcrab-demo/control.sock UPLOAD_ID
sandcrab files forget --socket /run/sandcrab-demo/control.sock UPLOAD_ID
sandcrab files list --socket /run/sandcrab-demo/control.sock
```

Paths are relative to `/workspace`, preserving case and Unicode. Upload parents
must already exist. Raw uploads install one file; tar uploads install one complete
directory. Existing targets require `--replace`; tar replacement replaces the
whole directory rather than merging its entries. `--mode OCTAL` chooses ordinary
permission bits for a raw file or the tar root. Archive entries retain ordinary
modes and links, with ownership assigned to the profile. Special nodes, sparse
entries, traversal paths and writes through symlinks are refused. Symlinks remain
opaque; snapshots never follow them. Hard links must name an earlier regular entry
inside the archive. Extended attributes and original ownership are not preserved.

Uploads stage and verify length and SHA-256 before publication. By default the
session freezes briefly for atomic installation, and while a snapshot is captured.
`--no-freeze` requires the caller to coordinate workspace writers; a snapshot can
then observe different files at different times. The session is thawed before sending snapshot bytes.
Command timeouts and session expiry continue while frozen. A transfer pins its
session and volume until helper containment and staging cleanup finish; cancellation,
expiry and shutdown cannot detach storage underneath it. Unconfirmed cleanup holds
admission until restart. Temporary staging counts against workspace or volume quotas.

| Request | Result |
|---|---|
| `POST /v1/uploads` | Register `id`, `serverId`, `sessionId`, `path`, `format` (`raw` or `tar`), `bytes`, `sha256`, optional `replace`, `freeze`, `mode`; returns 201 |
| `PUT /v1/uploads/ID/content` | Send exactly the registered Content-Length; return the upload record |
| `GET /v1/uploads/ID` | Read outcome and publication certainty |
| `GET /v1/uploads?after=UUID` | Up to ten records in UUID order; continue with `nextAfter` |
| `POST /v1/uploads/ID/cancel` with `{}` | Cancel pending or active work; inspect the final record |
| `POST /v1/uploads/ID/forget` with `{}` | Forget a waiting or terminal record when no stage remains |
| `POST /v1/sessions/ID/snapshot` | Send `path`, `format`, optional `freeze`; receive a fixed-length body with a quoted SHA-256 ETag |

Bulk requests close their connection. Upload bodies support `Expect: 100-continue`
after admission; other expectations are refused. Profile `transfer_bytes` bounds
both stream bytes and expanded regular-file content. Archives also have a 10,000-entry
limit including implicit parents. Upload body I/O, capture and publication each
have a 30-second budget; snapshot body writes have a separate 30-second budget.
Cleanup has a ten-second helper budget. Service `max_file_transfers` bounds active
operations; each session allows only one file operation. `max_file_records` bounds
retained upload identities independently of run and session records. Info exposes
the configured limits and whether file metadata is writable.

Records survive daemon restart while their configured storage survives. Reusing
an ID with the same plan returns its record, excluding `serverId` from the digest;
a different plan conflicts. Unknown IDs require the current epoch and a live session.
States are `waiting`, `receiving`, `publishing`, `published`, `succeeded`, `failed`,
`unknown` and `closing`. `publication` is `none`, `unknown` or `committed`.
Cancellation does not undo a committed write. After an ambiguous publication,
inspect the destination and receipt before choosing another write; replay never
reexecutes it. Forgetting ends replay protection, so never reuse that ID.

The CLI prints the upload ID before submission. It forgets successful or failed
uploads unless `--keep-result` is set, and retains uncertain outcomes. `--id UUID`
reconciles an explicit replay. Downloads verify length and ETag before atomically
installing a local file; `--replace` is required to replace an existing regular
file. A failed download preserves that file. A destination of `-` streams to stdout,
where already-written bytes cannot be withdrawn after a failure. Snapshots are
request-scoped and leave no retained artifact; consumers own downloaded copies.

## Verification

`executorRustCheck` checks the binary and its configuration/request tests.
`native_probe.py --binary FILE --tools DIRECTORY --report FILE`, run as root on
Linux, creates its own bounded slice and service and exercises real CLI/HTTP,
containment, cancellation, replay, capacity, session build/repair, renewal, expiry, restart and cleanup. It uses no
model API and reports deterministic evidence only. It does not establish agent
usability, OpenSandbox compatibility or Poketto adoption. Injected cleanup failure
must retain session admission, and delayed unit registration must remain cancellable.
`volume_probe.py` takes the same binary/tools/report arguments and additionally
requires `xfsprogs`. It owns a disposable 512 MiB XFS image, verifies file readback,
reflinks, quotas, durable replay and failure recovery, and unmounts it only after
its fixture's processes stop.
`file_probe.py` uses the same arguments and an independent XFS fixture for raw/tar
readback, safe local CLI installation, quotas, cancellation and publication recovery.
`events_probe.py` uses those arguments for live command output, binary resume,
observer admission, CLI cancellation and containment faults in a disposable native fixture.
`tcp_probe.py` additionally exercises authentication, private credential files,
both IP families, TCP CLI/files/events and data retention through token rotation.
Independent agent tasks and their budgeted runner live in the
[Inspect suite](../../../evals/README.md).
