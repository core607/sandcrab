# Sandcrab native service

`sandcrab` is a standalone Linux daemon and CLI for finite commands, persistent
bash sessions, durable volumes, streamed files, live command output and opaque host calls. It needs no Poketto account, workspace, repository,
signing key or compiled extension. The service uses a Unix socket or optional
authenticated loopback TCP. An optional [OpenSandbox adapter](opensandbox.md)
implements the documented OpenSandbox 1.1.0 subset, verified through
[published Python and Kotlin clients](../../../evals/sdk/README.md).
The [threat model](THREAT-MODEL.md) describes the shared-kernel boundary, client
authority and resource-exhaustion risks.
Consumer adoption and extraction remain under the
[service proposal](../../../notes/proposed/2026-10-26-sandcrab-sandbox-service.md).

## Get started

On x86-64 Ubuntu 22.04, Ubuntu 24.04 or Debian 12, use a root shell on a systemd host
with curl, bash and Python 3. Set `SANDCRAB_BUNDLE_URL` to the download URL for the
chosen release ZIP. Development builds provide `sandcrab-linux-x86_64.zip` in the
[installer workflow](../../../.github/workflows/sandcrab-readiness.yml). You can also download
that artifact in a signed-in browser and start at the second command.

<!-- sandcrab-quickstart -->
```sh
curl --fail --silent --show-error --location --output sandcrab-linux-x86_64.zip "$SANDCRAB_BUNDLE_URL"
python3 -I sandcrab-linux-x86_64.zip
/var/lib/sandcrab-release/sandcrab run --socket /var/lib/sandcrab/runtime/control.sock --profile default -- python3 -c 'print(6 * 7)'
```

The last command prints a terminal JSON record with `state` equal to `succeeded` and
`42` in `result.stdout`. The installer provisions the service, execution account and
private loopback token. The [installation reference](install/README.md) covers dry run,
doctor and the [container quickstart](install/README.md#standalone-container).

## Try the clients

Read the installed service's profiles with curl over its Unix socket:

```sh
curl --fail --unix-socket /var/lib/sandcrab/runtime/control.sock http://localhost/v1/info
```

The [build-and-test agent](../../../examples/sandcrab-build-test.sh) creates a Python
project and runs its unit tests in a retained shell. The [batch runner](../../../examples/sandcrab-batch.py)
runs each input file in a fresh sandbox and emits one JSON result per file. Run these
in an account with access to the socket. The [SDK examples](opensandbox.md#connection-and-ownership)
use the published Python and Kotlin clients with a private loopback token.

```sh
bash examples/sandcrab-build-test.sh
python3 examples/sandcrab-batch.py first.py second.py
```

## Custom installation

Build with `./gradlew buildExecutorRust`. In `build/executor-service/bin`,
`sandcrab` and `bwrap` are static executables; install both with mode 0755 in
the same root-owned directory with protected ancestors. Keep `bwrap-notices.txt`
and `bwrap-source.tar.xz` alongside them with mode 0644. The
[helper build](../sandcrab-launch/bwrap/README.md) owns its version, source and
reproduction instructions. The native daemon is excluded from the Poketto worker bundle.

Startup and every launch verify the helper beside the resolved executable,
including its protected path and pinned SHA-256. A missing, modified or mismatched
helper refuses execution. The host needs writable delegated cgroup v2,
unprivileged user namespaces, Linux 5.11+ and `mount`/`umount`.
Startup tests overlay mounting and copy-up on `runtime_root` storage before
serving clients; use a supported local filesystem such as ext4 or XFS. Unsupported
mount syscalls, helpers or backing storage refuse startup. There is no copy fallback.
[Tool preparation](../../prepare-tools.sh) supplies optional workload utilities; the helper
comes from the release. The seccomp filter is compiled into Sandcrab, which needs
no Node.js, npm or SRT runtime.

For a custom service, copy [config.example.toml](config.example.toml) to a root-owned file with mode 0600
in a protected directory. Set the client's numeric UID/GID and a separate execution
account. Profiles choose readable paths, tools, finite resource limits and
[network policy](#network-egress); calls can lower timeout and output limits but cannot select
accounts, mounts or isolation policy. Sessions need `/bin/bash` and its libraries
in the profile's read mounts. Read mounts cannot expose runtime storage.
Before starting, create the root-owned parent of `runtime_root` with mode 0755
(`/var/lib/sandcrab-demo` for the example).

Workloads have private mount, user, PID, IPC, UTS, cgroup and network namespaces.
Their hostname is `sandcrab`, the sandbox sees its own cgroup root, and sibling
sessions cannot look up each other's SysV shared memory. The bundled bwrap disables
nested user namespaces. A profile with a proxy retains the disconnected network
created for that workload. Fixed file helpers use host UID mappings to publish files
with the owner's identity.

The x86-64 workload filter denies new Unix and VSOCK sockets, io_uring, BPF,
keyrings, perf events, userfaultfd, kernel and module loading, mount operations,
setns, namespace flags in clone/unshare, ptrace and nondefault personality changes.
Unix socketpairs, ordinary processes and threads, and personality queries remain
available. `clone3` returns `ENOSYS` so runtimes can use `clone`.

Workload processes use the profile's execution UID and primary GID with empty
supplementary groups and capability sets. The launcher sets `no_new_privs` before
dropping identity. The guest cannot open its cgroup controls for writing or raise
a process hard resource limit.

Each session has a child cgroup under the configured delegation. Its
aggregate memory, CPU and task limits apply to every process in the session.
Memory caps round down to whole kernel pages; swap is disabled. File freezing
covers that child cgroup. Closing and restart recovery confirm process containment
before releasing the workspace or attached volume.

Set `service.cgroup_root` to a root-owned cgroup whose effective ancestors bound
memory, CPU and tasks and disable swap. Delegate `cpu`, `memory` and `pids`.
The daemon creates separate `daemon` and `workloads` subtrees; its own limits are
`daemon_memory_bytes` and `daemon_tasks_max`. It moves itself before enabling
controllers, so the delegation must contain no unrelated processes.
For systemd, use `Delegate=yes`, `TasksMax=infinity` and `OOMPolicy=continue` on
the service, with aggregate limits on its enclosing slice. Set `cgroup_root` to
the service's full cgroup path; a per-service memory cap also caps its sandboxes.
An already delegated container or root host can run `sandcrab serve --config FILE`
directly. No per-sandbox service manager invocation is required.
The daemon creates launchers directly in their configured leaves with
`clone3(CLONE_INTO_CGROUP)`. It also requires `close_range` and `cgroup.kill`;
unsupported or filtered operations fail without an uncontained fallback.
Child setup or executable failure exits 127 without running the workload.
Startup locks the runtime and contains old owned leaves before publishing a new
epoch. The protected ownership marker binds the runtime to its delegation;
pre-delegation runtime/storage directories require a fresh location.
`sandcrab check --config FILE` checks configuration, accounts and tools; it does
not prove that delegation or a sandbox works.

Finite runs use a fresh bounded tmpfs at `/workspace`; sessions use ordinary
directories beneath `runtime_root`, or an attached volume. Choose a disk-backed
runtime location to keep session data off tmpfs. Every run uses the profile's
account, a private bounded `/tmp`, isolated network and PID namespaces, and seccomp.
It shares the host kernel; this is not a microVM boundary. Workspace data is
disposable unless supplied by a durable volume. Read mounts are the operator's responsibility.

## Network egress

Use `network = "none"` to disable egress, as in the installed default profile. To permit selected
destinations, use `network = { allow = ["pypi.org", "files.pythonhosted.org"] }`.
Names match exactly, case-insensitively, with an optional final dot; list each
subdomain separately. Use ASCII DNS names or encoded internationalized names.
IP literals, wildcards, URLs, ports in names and duplicate entries are refused.
There may be 1..256 entries. Callers and SDK clients cannot change this policy.

Enabled profiles receive `http_proxy`/`https_proxy` and uppercase equivalents
pointing to an HTTP CONNECT proxy, plus `all_proxy`/`ALL_PROXY` using `socks5h`.
`no_proxy`/`NO_PROXY` are empty. HTTPS clients such as Python's `urllib` use
CONNECT automatically. Plain HTTP forwarding is unsupported; select SOCKS5
with remote DNS or explicitly request a CONNECT tunnel, for example curl's
`--proxytunnel`. SOCKS5 supports domain-name CONNECT with no authentication;
IP-address requests, BIND and UDP association are refused.

Each workload has a private loopback-only network. The trusted launcher creates
its proxy listener and transfers the socket to the daemon before credential
drop and guest seccomp enforcement. It requires a positive acknowledgement;
setup failure runs no workload. No veth, external route or host DNS socket enters
the workload. Unsetting proxy variables gives no direct egress. The daemon must
itself have outbound access; a container started with `--network none` cannot
reach external destinations.

The daemon resolves allowed names through the first three literal nameservers
in `/etc/resolv.conf`, using bounded UDP queries and TCP on truncation. It uses
no search suffix, hosts-file override or NSS lookup. Recursive answers may use
CNAMEs. Local, private, metadata, multicast and special-use addresses are denied;
IPv6 destinations must be in supported global unicast space. Each connection
uses the checked numeric address, with no second name lookup. This controls the
requested destination; tunnels do not inspect TLS names, application contents
or relay behavior at an allowed remote service.

`service.max_proxy_connections` bounds the whole daemon to 1..128 concurrent
connections, default 16; each workload can hold at most eight. Handshake,
resolution and connection setup share five seconds. CONNECT headers are limited
to 8 KiB; each relay direction buffers 16 KiB, and an idle tunnel expires after
60 seconds. Capacity refusal closes the new connection. Proxy threads, buffers
and DNS work consume the daemon's resource limits. Closing, expiry, cancellation
and restart close the owned bridge and outbound connections before releasing
workload admission. Structured `networkDecision` logs record each allow/refusal
with execution ID, requested domain/port and reason, without payloads or credentials.

## CLI

```sh
sandcrab info --socket /var/lib/sandcrab-demo/runtime/control.sock
sandcrab run --socket /var/lib/sandcrab-demo/runtime/control.sock --profile python -- python3 -c 'print(6 * 7)'
sandcrab get --socket /var/lib/sandcrab-demo/runtime/control.sock RUN_ID
sandcrab cancel --socket /var/lib/sandcrab-demo/runtime/control.sock RUN_ID
sandcrab forget --socket /var/lib/sandcrab-demo/runtime/control.sock RUN_ID
```

`run` prints its recovery ID to stderr before submission, polls to a terminal
result, prints JSON and forgets the record. Exit zero means the command succeeded;
other outcomes exit nonzero. SIGINT/SIGTERM requests cancellation. A lost response
does not submit a new run: inspect the printed ID. `closing` means containment or
workspace cleanup was not confirmed; its admission remains held until restart.
For Unix transport, the CLI authenticates the root-owned socket and root peer before sending commands.

If forgetting a terminal record fails, the CLI warns on stderr and preserves the
command's exit result. Inspect or forget the printed ID instead of rerunning it.
`--keep-result` on `run`, `session exec`, `session open`, `session shell` or
`files put` retains the result until explicit forgetting; it also works with streaming commands.

## Templates

Import a plain tar archive or an already unpacked OCI root tree through the
authenticated API. Sandcrab stores each normalized tree once beneath
`runtime_root/templates`; published objects survive daemon restart and remain
until explicitly deleted. Sessions attach a template as a shared read-only base
with their own disposable writable layer at `/workspace`, or use it as the root
filesystem. Export a parent's writable layer before closing it:

```sh
sandcrab session diff --socket /var/lib/sandcrab-demo/runtime/control.sock SESSION_ID changes.tar
```

`GET /v1/sessions/{id}/diff` captures a tar changeset from the upper layer.
Paths are relative to `/workspace`, or to `/` for rootfs sessions; all contexts'
changes are included through their parent. Deletions become empty `.wh.NAME`
files; `.wh..wh..opq` hides a directory's base children. Apply these markers to
the matching template before installing additions. Ordinary tar extraction does
not apply deletion semantics. An unchanged workspace produces an empty archive.

The changeset preserves contents, numeric UID/GID, modes, second-resolution
mtime, symlinks and hard links among upper files. It omits xattrs and ACLs;
overlay redirects and metadata-only copies return `UNSUPPORTED_OVERLAY_METADATA`.
Literal upper names starting with `.wh.` return `DIFF_NAME_CONFLICT`; other
special nodes return `UNSUPPORTED_FILE_TYPE`. Rootfs exports include runtime
anchor metadata but exclude mounted runtime files, private `/tmp` and transfer
staging. Sessions without a template return `TEMPLATE_REQUIRED`.

Coordinate writers during capture. [File transfer](#files) admission, byte/entry
limits, deadlines, cancellation and cleanup also apply to diff downloads.
Validate Content-Length, SHA-256 ETag and the session's serverId; the CLI checks
length/hash and installs local output atomically. Use `-` for stdout or
`--replace` to replace an existing regular destination.

```sh
sandcrab template import --socket /var/lib/sandcrab-demo/runtime/control.sock --profile python environment.tar
sandcrab template import --socket /var/lib/sandcrab-demo/runtime/control.sock --profile python --directory unpacked-image/rootfs
sandcrab template list --socket /var/lib/sandcrab-demo/runtime/control.sock
sandcrab template get --socket /var/lib/sandcrab-demo/runtime/control.sock SHA256
sandcrab session open --socket /var/lib/sandcrab-demo/runtime/control.sock --profile python --template SHA256
sandcrab template delete --socket /var/lib/sandcrab-demo/runtime/control.sock SHA256
```

The equivalent import is `POST /v1/templates?profile=python` with a plain tar body,
using Content-Length or chunked framing. `GET /v1/templates` returns up to 64
objects and a `nextAfter` cursor; continue with `?after=SHA256`.
`GET` and `DELETE /v1/templates/SHA256` inspect and remove an object.
The CLI packs a directory locally; it neither contacts an image registry nor
interprets OCI layer archives. Supply the merged, unpacked root tree. Coordinate
source writers before packaging it.

Set `templateId` on `POST /v1/sessions`, or use `session open --template`.
It is mutually exclusive with `volumeId` and requires the template's execution
UID/GID to match the selected profile. Named contexts share the parent's view;
independent parent sessions share only the immutable base. The daemon creates
one overlay mount per parent in its private mount namespace. File APIs and plain
tar snapshots operate on the merged view. Temporary-storage accounting charges
the writable layer and overlay work directory; the template pool owns the base.
These periodic limits cannot prevent transient overshoot.

An attached template returns `TEMPLATE_BUSY` on deletion. Closing contains all
contexts and file helpers, unmounts the view and deletes its writable data before
releasing the template pin. Unconfirmed cleanup retains the pin until recovery.
Restart contains prior workloads and removes disposable layers while retaining
templates. Before a 0.x upgrade from a daemon with host-visible runtime mounts,
stop and reconcile those mounts with that binary; startup refuses existing
submounts beneath `runtime_root`.

For a custom environment, add `rootfs: true` to the session request, or use
`session open --template SHA256 --rootfs`. The template must contain `/bin/bash`
and its loader/libraries. Its programs and libraries replace the profile's host
read mounts and tools; the profile still controls execution identity, resource
limits, network isolation and optional host calls. The command starts in
`/workspace`, which is also the scope of file APIs and plain tar snapshots.
Seed files there when packaging the template.

Rootfs sessions share the parent's full filesystem view across contexts. Writes
to image directories and `/workspace` use the same overlay. Sandcrab protects
`/` and runtime mount anchors with root ownership; `/workspace` is writable by
the execution identity, and its name cannot be replaced. `/tmp`, `/dev`, `/proc`
and `/sandcrab-driver` are supplied by the runtime. Host-call profiles also
reserve `/sandcrab` and `/sandcrab-calls`. Symlinks or incompatible node types at
these targets refuse session setup with `ROOTFS_UNAVAILABLE`. Reserved file
targets must be absent or empty regular files with one link; populated files
are refused before ownership changes can copy them into the writable layer. Transfer staging
stays outside the guest root. These metadata changes affect only the writable
layer; the template content and identity remain unchanged.

Rootfs-aware file-stage metadata uses a new 0.x format. Drain and reconcile old
file transfers and template imports with the old binary before stopping it, back
up runtime and volume-store metadata, and rebuild affected upload records for the
new binary. Upload metadata
may live under `runtime_root/uploads` or the configured storage's `state/uploads`;
changing `runtime_root` alone does not rebuild the latter. Preserve volume data
and immutable templates.

SHA-256 identifies normalized paths, contents, permission bits, symlink targets,
hard-link topology and the selected profile's execution UID/GID. Archive order,
timestamps and original owners do not affect identity. Import strips special
permission bits and extended attributes, assigns the profile identity and uses
a 0755 root directory. It accepts regular files, directories, symlinks and
hard links to earlier regular entries. Devices, FIFOs, sparse archives,
duplicate paths and traversal through symlinks are rejected. Template directories
remain behind the root-only store; workload accounts cannot edit the shared base.

One import runs at a time and shares `max_file_transfers` admission with file
operations. It uses the profile's memory, CPU and task bounds. Both archive bytes
and extracted regular-file bytes are bounded by `transfer_bytes`, with at most
100,000 entries, a 30-second body deadline and bounded helper execution.
`service.max_templates` defaults to 128; `service.template_pool_bytes` defaults
to 4 GiB of allocated blocks in committed trees, including directories and
counting hard links once. The list response includes pool limits and current
logical/allocated totals. Reserve extra space for store records and one incoming
archive/tree. These are
application limits; they do not enforce a filesystem quota.

Interrupted imports publish no partial object. Restart contains old helpers before
removing incoming stages. Uncertain publication or cleanup reports
`TEMPLATE_STATE_UNCERTAIN` and fences further mutations; inspect the catalog after
restart. Identical imports return the existing object even at catalog capacity.
Include the template store in runtime backups before rebuilding 0.x metadata.

## Host calls

Profiles can enable opaque requests from a command to its caller. The
[host-call reference](host-calls.md) owns caller authorization, CLI/HTTP operation,
limits and recovery, with an independent build-signing example.

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
without replay. `max_connections` defaults to 32. Ordinary POST bodies declare a content
length of 1 to 65536 bytes; [host-call replies](host-calls.md#http-and-observation) have a separate bound.
GET requests have no body. Headers are at most 8192 bytes
and 32 fields. Only event responses use chunked framing; requests and other responses
require fixed lengths. Duplicate headers and upgrades are rejected; pipelining is unsupported. Only `client_uid` is accepted, even if another
account can connect to the socket. TCP uses the bearer credential above.

| Request | Result |
|---|---|
| `GET /v1/info` | API version, server epoch, capabilities and profile limits |
| `GET /v1/openapi` | The bundled [OpenAPI contract](openapi.json); `?capability=runs`, `sessions`, `volumes`, `files`, `uploads`, `events`, `calls` or `templates` selects a bounded view with its referenced schemas. Views describe common discovery fields and selected capability metadata; the response also carries the other fields documented by the full contract. |
| `GET /v1/runs` or `GET /v1/sessions` | List up to 64 retained IDs, with `serverId` and `nextAfter`; continue with `?after=UUID` |
| `POST /v1/runs` | Admit a run; return 202 with its state |
| `GET /v1/runs/ID` | Read current state and any terminal result |
| `POST /v1/runs/ID/cancel` with `{}` | Request cancellation; poll until terminal |
| `POST /v1/runs/ID/forget` with `{}` | Release a terminal result and its replay identity |

Submit JSON with `id` (a fresh UUID), `serverId` from info, `profile`, and an argv
array `command`. Optional `timeoutMillis` and `outputLimitBytes` only narrow the
profile. Runs and session creation also accept `resources` with optional
`memoryBytes` and `cpuQuotaPercent`. These only lower the profile's hard caps;
memory must be at least the larger of 16 MiB and the profile's temporary filesystem
bound. Info publishes these limits per profile. CPU percentages use 100 for one
CPU. The CLI exposes `--memory-bytes N` and `--cpu-percent N` on `run` and
`session open`. Unknown fields are errors. Within one epoch, repeating the same ID and
request returns the existing run; changed arguments give `ID_CONFLICT`. A stale
epoch gives `SERVER_CHANGED`. After restart old outcomes are unknown, not proof of
nonexecution. Forgetting or result expiry ends replay protection; never reuse that ID.

States are `queued`, `running`, `succeeded`, `failed`, `cancelled`, `timed_out`, `output_limit`,
`resource_limit`, `refused` and `closing`. Terminal results include exit code, stdout, stderr
and truncation, or a failure code. Output bounds apply to combined raw stdout and
stderr; invalid UTF-8 becomes replacement characters. Runs continue after HTTP
disconnect and remain bounded by their timeout. Cancellation does not undo work.

`max_sandboxes` accepts 1 through 512 and bounds live runs and workspace-owning sessions together; child
shells share their parent's reservation. Commands wait when execution is busy;
session creation still refuses with `SESSION_CAPACITY`. `RESULT_CAPACITY` means retained records
or output reservations must be forgotten. Session records and command results share
`max_records`; command output remains reserved until its result is forgotten. `max_output_bytes` bounds reserved raw
output, not total process memory; the slice bounds runtime, tmpfs and overhead.
Reserve enough supervisor memory for encoded responses and retained output.

## Command queue

`service.max_queued` defaults to 256 (range 1–4096) across finite runs and session
commands. `queue_timeout_millis` defaults to 2000 (range 1–30000). Finite runs use
one FIFO; each shell has its own FIFO. Independent shells can progress while
finite runs wait for a sandbox slot. Waiting reserves the ID, record and output
budget, so those bounds can reduce available queue capacity. A full queue returns
429 `QUEUE_CAPACITY` without creating a run.

Accepted work returns 202 with `queued` or `running`. Queue expiry retains
`state: refused` and `result: {"code":"QUEUE_TIMEOUT","executed":false}`. It never
starts that command, even when capacity later recovers. Execution timeout starts
after dispatch. Cancelling a queued command retains `cancelled` with
`COMMAND_CANCELLED` and `executed:false`; the active command and shell continue.
Closing or expiring its session cancels pending commands. Dispatched cancellation
keeps the usual containment behavior. Retained outcomes remain replayable until
forget or result expiry; clients never automatically resubmit work.

Runs and events expose `queueWaitMillis`, fixed when waiting ends. Info publishes
`limits.maxQueued`, `limits.queueTimeoutMillis` and an `admission` snapshot of
`activeSandboxes` and `queuedCommands`. CLI polling and streaming wait through
queued states and return a nonzero status for refusal.

Run and session inventories include active and terminal IDs, without command output.
Use `sandcrab list --socket PATH` or `sandcrab session list --socket PATH`, with
`--after UUID` for the next page. Listing neither renews nor forgets records.
Pages are not a snapshot: an ID inserted before the cursor appears on a fresh
scan; deleting the cursor record does not invalidate its cursor. Discard an
inventory if its server epoch changes. Consumers must establish ownership before
closing or forgetting listed records; discovery alone grants no ownership.

## Result retention

`service.result_ttl_millis` defaults to 300000 (five minutes), accepts 1000 through
86400000, and appears as `limits.resultTtlMillis` in info. Once a run, session or
upload is terminal and cleanup is confirmed, maintenance removes its result
after this interval. Output reservations are released with run results.
Active sessions, unfinished uploads, cleanup failures and owned staging never expire
through this policy. Session lifetime and result retention are separate.

Creation requests accept `keepResult: true` to preserve the terminal identity.
Explicit forget still works. Upload result age survives restart using the protected
record's modification time; collection never deletes the uploaded workspace data.
An expired result is missing, not evidence that execution did not happen.
Observers needing longer retention must request it before submission. No expiry
replays a command or write.

## Command events

Add `--stream` before `--` to `run` or `session exec` to print exact stdout and
stderr bytes as they arrive. Recovery IDs and CLI diagnostics also use stderr.
The command's terminal outcome still controls the CLI exit status and forgetting.
To observe a retained run without cancelling or forgetting it, use:

```sh
sandcrab events --socket /var/lib/sandcrab-demo/runtime/control.sock RUN_ID
sandcrab events --socket /var/lib/sandcrab-demo/runtime/control.sock RUN_ID --after CURSOR
```

This observer prints newline-delimited JSON containing `event`, `id` and `data`.
HTTP clients use `GET /v1/runs/ID/events`, a chunked SSE response. Each complete
event carries an opaque `id`; explicit reconnects send it as `Last-Event-ID`.
The initial `state` carries run metadata without output. `stdout` and `stderr`
carry a starting byte `offset` and `base64` block of at most 4096 raw bytes. Ordering
is per stream; blocks need not end at UTF-8 boundaries. `result` carries the
terminal summary and both total byte counts. A finite run publishes it after
its process tree stops. A normal session command may leave background processes
alive; close the session to stop that tree, or use a frozen snapshot to capture
files while it remains open. EOF, heartbeats and `error` do not acknowledge completion.

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
sandcrab session open --socket /var/lib/sandcrab-demo/runtime/control.sock --profile python --ttl-ms 60000
sandcrab session exec --socket /var/lib/sandcrab-demo/runtime/control.sock SESSION_ID -- 'mkdir project; cd project; export VALUE=42'
sandcrab session exec --socket /var/lib/sandcrab-demo/runtime/control.sock SESSION_ID -- 'printf "%s\n" "$VALUE"; pwd'
sandcrab session renew --socket /var/lib/sandcrab-demo/runtime/control.sock SESSION_ID --ttl-ms 60000
sandcrab session close --socket /var/lib/sandcrab-demo/runtime/control.sock SESSION_ID
sandcrab session forget --socket /var/lib/sandcrab-demo/runtime/control.sock SESSION_ID
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
dispatched-command cancellation, timeout, output overflow or runtime failure ends the session.
A kernel OOM kill ends the whole session and reports `resource_limit`, even when
the shell catches a child's failure. Exit code 137 alone is not OOM evidence.
The daemon never silently resets its state. Closing or expiry also stops background
processes before releasing storage and admission. Without a volume, copying data
into a session is not a durable save.

Session directories use the profile's `temporary_bytes` and `temporary_inodes`
as [periodic storage limits](#storage-accounting). Private `/tmp` and finite-run
workspaces retain their separate bounded tmpfs mounts. Child shells share the
parent's directory and accounting; only confirmed parent cleanup removes it.

`session_ttl_millis` is the profile's default and maximum lifetime per open or
renewal, from 100 ms through one day. Expiry uses a monotonic clock and includes
startup and idle time. Renewal moves a live deadline from the current time; it
cannot revive an expired or closed session. Disconnects do not stop or renew it.
A run's timeout and output limits still apply to each command independently.

| Request | Result |
|---|---|
| `POST /v1/sessions` | Open with `id`, `serverId`, `profile`, optional `ttlMillis` and `volumeId`; returns 202 |
| `GET /v1/sessions/ID` | State, expiry estimate, active run ID and `parentSessionId` (null for a workspace owner) |
| `POST /v1/sessions/ID/shells` | Create a child shell with `id` and `serverId`; returns 202 |
| `POST /v1/sessions/ID/commands` | Execute `command` bash source with a fresh `id`, `serverId` and optional `timeoutMillis`/`outputLimitBytes`; returns 202 |
| `POST /v1/sessions/ID/renew` | Renew with `ttlMillis` |
| `POST /v1/sessions/ID/close` with `{}` | Request closure; poll until terminal |
| `POST /v1/sessions/ID/forget` with `{}` | Forget a terminal session's identity |

`sandcrab session shell --socket PATH PARENT_SESSION_ID` creates an independent
persistent shell in a live workspace-owning session. Use its returned ID with
`session exec`, `get`, `close` and `forget`. Each shell retains its own variables,
functions, working directory, `/tmp` and background processes; shells may run
commands concurrently against the shared `/workspace`. Callers coordinate shared
file edits. A child's exit, timeout or cancellation closes that child and preserves
the parent's files and other shells.

Children inherit the parent's effective profile, aggregate memory/CPU/process
limits and expiry; they cannot select another profile or create grandchildren.
Renewal and file operations use the parent ID. Frozen file operations cover every
shell in that workspace. Kernel OOM victims are selected within the aggregate
budget; an unaffected shell's results do not inherit another leaf's OOM history.
Every child consumes a retained `max_records` entry until explicitly forgotten.
Parent closure, expiry, primary-shell failure or shutdown contains all children
before releasing storage. Unconfirmed child cleanup fences the parent and keeps
its storage and sandbox reservation until restart cleanup.

Use `/v1/runs/RUN_ID` to inspect, cancel or forget a session command. Exact command
replays return their retained record even after the session ends or is forgotten;
changed commands or another session using the ID conflict. Starting or busy shells
queue commands; `SESSION_NOT_READY` refuses ended shells. A record's `sessionId` identifies
its session; names, profiles and IDs confer no authority beyond the socket's peer.

Session states are `starting`, `ready`, `busy`, `stopping`, `closed`, `expired`,
`failed` and `closing`. Only the first three accept renewal. `closing` means
containment or storage cleanup is unconfirmed; it cannot be forgotten and holds
admission until restart. Result records are forgotten separately from sessions.
A restart terminates sessions and removes their ephemeral workspaces. The changed
server epoch refuses old create/command requests; a missing result does not prove
that the command never ran.

## Durable volumes

Enable optional `[storage]` in the example configuration. Ordinary directories
work without a dedicated filesystem or quota tools. The root and its ancestors
must be root-owned, non-writable by other accounts and searchable by execution
accounts. The daemon creates data at `root/data` and private metadata at `root/state`.
For a new store, prepare `root/data` as an empty protected directory.
It never formats a disk, remounts a filesystem or adopts a nonempty unowned store.
Profiles cannot expose this storage through their read mounts.

For enforced quotas, provision a dedicated XFS mount at `root/data` with reflinks,
`prjquota` or `pquota`, `nosuid` and `nodev`, and a filesystem size no larger than
`pool_bytes`. Install `xfsprogs` under `/usr/sbin` and keep `root/state` on another
filesystem. `require_quota = true` refuses startup without verified enforcement;
its default is false. `/v1/info` reports the actual `storage.quotaEnforced` mode.
Existing plain volumes retain periodic accounting; enabling host quotas does not
silently assign projects to their data.

```sh
sandcrab volume create --socket /var/lib/sandcrab-demo/runtime/control.sock --profile python --bytes 8388608 --inodes 256
sandcrab session open --socket /var/lib/sandcrab-demo/runtime/control.sock --profile python --volume VOLUME_ID
# Execute commands, then close the session before cloning or deleting its volume.
sandcrab volume create --socket /var/lib/sandcrab-demo/runtime/control.sock --profile python --clone-from VOLUME_ID
sandcrab volume list --socket /var/lib/sandcrab-demo/runtime/control.sock
sandcrab volume get --socket /var/lib/sandcrab-demo/runtime/control.sock VOLUME_ID
sandcrab volume delete --socket /var/lib/sandcrab-demo/runtime/control.sock VOLUME_ID
sandcrab volume forget --socket /var/lib/sandcrab-demo/runtime/control.sock VOLUME_ID
```

A volume is an ordinary directory mounted at `/workspace`. Session closure,
expiry and daemon restart retain its files; shell state and `/tmp` remain
ephemeral. Application writes follow normal filesystem synchronization semantics;
closing a session is not an atomic snapshot or a power-loss commit for those writes.
The selected profile must use the volume's execution UID/GID. One session owns a
volume exclusively until confirmed cleanup; a failed cleanup retains that ownership.
Cloning requires an unattached source and holds it for the operation. It uses
reflinks where supported and ordinary copying otherwise, preserving hard links
and opaque symlinks; subsequent writes are independent. Clone work uses the
selected profile's bounded cgroup and timeout.

Limits count allocated blocks and inodes, including managed metadata, rather than
sparse logical lengths. Requests may only lower configured maxima; byte limits
are multiples of 1024. Enforced quota failure can report `ENOSPC` or `EDQUOT`
inside a session. `max_volumes` bounds live volumes;
storage `max_records` separately bounds durable records. `STORAGE_CAPACITY`
allows one mutation at a time. A full quota data pool still permits recording deletion
on its separate control filesystem. Plain storage can exhaust data and metadata
together; uncertain publication fences mutations rather than inventing a successful record.

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

Startup contains owned cgroups before recovering unfinished creation or deletion.
Published volumes remain intact. Uncertain metadata or volume cleanup fences
mutations (`STORAGE_UNCERTAIN`, `storage.available=false`) until restart and
reconciliation; it never exposes uncommitted data as ready. Unexpected data,
mounts or a changed cleanup namespace require operator reconciliation and are
preserved. Keep the store and its matching runtime configuration together.

## Storage accounting

Without enforced quotas, `Volume.usage`, `Session.storageUsage` and
`storage.poolUsage` in `/v1/info` report periodic allocated-byte/inode observations.
An attached session also exposes `storagePoolUsage`; it is null for an ephemeral
directory. The pool sums owned volume observations and its directory overhead,
not unrelated files on the host filesystem. Its timestamp is the oldest constituent
observation, so it is not an atomic snapshot. These fields are null where accounting
does not apply or the session has no live workspace.

One background worker refreshes active directories and new volumes at most once per second
per directory, then enforces the measured limits. `exceeded` refuses new commands,
child shells, uploads and other growth with `STORAGE_LIMIT`, cancels active growth
helpers and freezes existing workspace processes. `pending` or `unavailable` also
refuses growth, with `STORAGE_USAGE_UNAVAILABLE`. Reads and deletion remain available;
after a complete below-limit observation, processes and admission resume. Command
timeouts and session expiry keep running while frozen.

Each scan limits depth to 64, directory entries to 1,000,001, retained hard-link
identities to 16,384 and time between syscalls to five seconds. Incomplete scans
never report zero or successful usage. Kernel I/O can exceed that deadline;
many active directories lengthen the refresh cycle. Concurrent writes, reflinks,
in-flight copying and open unlinked files prevent a hard physical disk bound.
Keep filesystem headroom or enable enforced quotas when a hard bound is required.
End background writers before deleting their files: unlinking an open file does
not reclaim its blocks. Closing an ephemeral session removes its data; a volume
retains data and can be reattached for recovery.

## Files

```sh
sandcrab files put --socket /var/lib/sandcrab-demo/runtime/control.sock SESSION_ID ./input.bin input.bin
tar -cf project.tar -C ./project .
sandcrab files put --socket /var/lib/sandcrab-demo/runtime/control.sock SESSION_ID ./project.tar project --tar
sandcrab session exec --socket /var/lib/sandcrab-demo/runtime/control.sock SESSION_ID -- 'cd project; python3 main.py'
sandcrab files get --socket /var/lib/sandcrab-demo/runtime/control.sock SESSION_ID project ./result.tar --tar
sandcrab files status --socket /var/lib/sandcrab-demo/runtime/control.sock UPLOAD_ID
sandcrab files cancel --socket /var/lib/sandcrab-demo/runtime/control.sock UPLOAD_ID
sandcrab files forget --socket /var/lib/sandcrab-demo/runtime/control.sock UPLOAD_ID
sandcrab files list --socket /var/lib/sandcrab-demo/runtime/control.sock
```

Raw `files put` streams one request without hashing the source first. `--id`,
`--keep-result` or `--tar` selects a staged upload. Discovery exposes ordinary
transfers under `capability=files` and staged operations under `capability=uploads`.

```sh
curl --unix-socket /var/lib/sandcrab-demo/runtime/control.sock --upload-file ./input.bin \
  'http://localhost/v1/sessions/SESSION_ID/files?path=input.bin'
```

`PUT /v1/sessions/ID/files?path=PATH` accepts fixed-length or chunked raw bytes,
including an empty file. It replaces a regular file atomically by default;
`replace=false` refuses an existing target. Optional `mode` is a decimal permission
mask, default 420 (0644). The reply contains `path`, received `bytes` and `sha256`.
Publication and staging cleanup finish before success. The session keeps running;
concurrent commands can change the destination. A lost reply or `PUBLICATION_UNKNOWN`
requires destination inspection before another write. This route retains no upload ID.

Paths are relative to `/workspace`, preserving case and Unicode. Upload parents
must already exist. Raw uploads install one file; tar uploads install one complete
directory. Existing targets require `--replace`; tar replacement replaces the
whole directory rather than merging its entries. `--mode OCTAL` chooses ordinary
permission bits for a raw file or the tar root. Archive entries retain ordinary
modes and links, with ownership assigned to the profile. Special nodes, sparse
entries, traversal paths and writes through symlinks are refused. Symlinks remain
opaque; snapshots never follow them. Hard links must name an earlier regular entry
inside the archive. Extended attributes and original ownership are not preserved.

Staged uploads verify declared length and SHA-256 before publication. Native
transfers keep workspace processes running. Callers coordinate writers when they
need a consistent collection, for example by producing an archive inside one
command before downloading it. Tar downloads contain ordinary entries, with no
private manifest format. A transfer pins its
session and volume until helper containment and staging cleanup finish; cancellation,
expiry and shutdown cannot detach storage underneath it. Unconfirmed cleanup holds
admission until restart. Temporary staging counts against workspace or volume limits.
`DELETE /v1/sessions/ID/files?path=PATH` removes a file without executing shell
source; add `recursive=true` for a directory tree. Paths follow the same workspace
boundary and opaque-symlink rules. Deletion remains available during storage overage.

| Request | Result |
|---|---|
| `PUT /v1/sessions/ID/files?path=PATH` | Stream one raw file; optional `replace` and `mode` |
| `POST /v1/uploads` | Register `id`, `serverId`, `sessionId`, `path`, `format` (`raw` or `tar`), `bytes`, `sha256`, optional `replace`, `mode`, `keepResult`; returns 201 |
| `PUT /v1/uploads/ID/content` | Send exactly the registered Content-Length; return the upload record |
| `GET /v1/uploads/ID` | Read outcome and publication certainty |
| `GET /v1/uploads?after=UUID` | Up to ten records in UUID order; continue with `nextAfter` |
| `POST /v1/uploads/ID/cancel` with `{}` | Cancel pending or active work; inspect the final record |
| `POST /v1/uploads/ID/forget` with `{}` | Forget a waiting or terminal record when no stage remains |
| `POST /v1/sessions/ID/snapshot` | Send `path` and `format`; receive a fixed-length body with a quoted SHA-256 ETag |

Native snapshot replies include `X-Sandcrab-Server-Id`, the serving daemon epoch.
Clients retaining a session handle must match this header against its `serverId`
before exposing snapshot bytes; a missing or different epoch cannot identify that session.

Bulk requests close their connection. Upload bodies support `Expect: 100-continue`
after admission; other expectations are refused. Profile `transfer_bytes` bounds
both stream bytes and expanded regular-file content. Archives also have a 10,000-entry
limit including implicit parents. Upload body I/O, capture and publication each
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

## Verification

`executorRustCheck` covers the Rust programs and their configuration/request
contracts. The [conformance runner](conformance.py) exercises real Linux
sandboxes through CLI, native HTTP and published SDK clients:

```sh
python3 executor-service/rust/sandcrab/conformance.py --list
sudo python3 executor-service/rust/sandcrab/conformance.py \
  --suite native queue --binary build/executor-service/bin/sandcrab \
  --tools /prepared/tools --output /var/lib/sandcrab-results
```

Run on a disposable root Linux/systemd host with the workload tools prepared by
`executor-service/prepare-tools.sh`. The binary and verified bwrap must remain
beside each other. Fixtures own bounded slices, services, storage and credentials.
`SANDCRAB_PROBE_ROOT` selects a protected root-owned parent on an overlay-capable
filesystem, default `/var/lib`; container fixtures need a data volume for it.
XFS suites need `xfsprogs`, plain-storage needs `mkfs.ext4`, rootfs needs `ldd`,
and egress needs OpenSSL. The fault controller uses kernel fork/exec/exit stops
only on its fixture's daemon; it is absent from the installed service.

Omit `--suite` or select `all` to run every suite. This requires both published
SDK environments described in the [SDK reference](../../../evals/sdk/README.md):

```sh
sudo python3 executor-service/rust/sandcrab/conformance.py \
  --binary build/executor-service/bin/sandcrab --tools /prepared/tools \
  --python /prepared/sdk-python/bin/python --java /prepared/jdk/bin/java \
  --jvm-libs evals/sdk/jvm/build/install/sandcrab-sdk-conformance/lib \
  --output /var/lib/sandcrab-all-results
```

Selected native suites can run without SDK environments. `sdk` requires both;
`rootfs` requires both when SDK coverage is enabled. Passing `--python` also
exercises published Python clients in `egress` and `queue`. `--sdk-clients` and
`--examples` override the repository's consumer/example directories.

Each suite has its own process so network-namespace changes stay isolated.
The new output directory retains per-suite receipts, logs, failure diagnostics
and `summary.json`. A test or unconfirmed cleanup makes the command fail; no
later suite starts. Earlier attempts are never overwritten. No suite calls a
model API. Independent agent tasks and their budgeted runner live in the
[Inspect suite](../../../evals/README.md).

`delegation` takes `--parent CGROUP`, an existing parent delegating cpu, memory
and pids, and runs the daemon directly without a service manager. In a disposable
container, run only that suite as PID 1 with `--initialize-container --parent
/sys/fs/cgroup`. Its tested Docker bounds are `--privileged --cgroupns private
--memory 512m --memory-swap 512m --cpus 2 --pids-limit 512 --network none
--mount type=volume,destination=/var/lib`, with `/run` and `/tmp` as 64 MiB tmpfs
mounts. Copy the runner package, binary and tools into protected container paths;
no host cgroup bind mount is used. The [release container](install/README.md#standalone-container)
is a separate operator entrance.
