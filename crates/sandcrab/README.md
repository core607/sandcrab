# Sandcrab native service

`sandcrab` is a standalone Linux daemon and CLI for finite commands, persistent
bash sessions and durable volumes. It needs no Poketto account, workspace, repository,
signing key or compiled extension. The service uses a Unix socket; file transfer, SSE,
TCP and the OpenSandbox adapter remain under the
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
The CLI authenticates the root-owned socket and root peer before sending commands.
If forgetting a terminal record fails, the CLI warns on stderr and preserves the
command's exit result. Inspect or forget the printed ID instead of rerunning it.

## HTTP

One HTTP/1.1 exchange uses one connection. Requests have a declared content length,
at most 64 KiB; pipelining and chunked bodies are rejected. Only `client_uid` is
accepted, even if another account can connect to the socket.

| Request | Result |
|---|---|
| `GET /v1/info` | API version, server epoch, capabilities and profile limits |
| `GET /v1/openapi` | The bundled [OpenAPI contract](openapi.json); `?capability=runs`, `sessions` or `volumes` selects a bounded view with its referenced schemas |
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
Independent agent tasks and their budgeted runner live in the
[Inspect suite](../../../evals/README.md).
