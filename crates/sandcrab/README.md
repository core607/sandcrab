# Sandcrab native runs

`sandcrab` is a standalone Linux daemon and CLI for finite commands. It needs no
Poketto account, workspace, repository, signing key or compiled extension. This
entrance currently supports runs on a Unix socket; persistent sessions, file
transfer, SSE, TCP and the OpenSandbox adapter remain under the
[service proposal](../../../notes/proposed/2026-10-26-sandcrab-sandbox-service.md).

## Installation

Build with `./gradlew buildExecutorRust`; the static binary is
`build/executor-service/bin/sandcrab`. It is excluded from the Poketto worker bundle.
Install it in a root-owned directory with root-owned ancestors. The host needs
systemd, cgroup v2, unprivileged user namespaces, bubblewrap and the pinned seccomp
helper from the executor's [tool preparation](../../prepare-tools.sh).

Copy [config.example.toml](config.example.toml) to a root-owned file with mode 0600
in a protected directory. Set the client's numeric UID/GID and a separate execution
account. Profiles choose readable paths, tools, finite resource limits and
`network = "none"`; calls can lower timeout and output limits but cannot select
accounts, mounts or isolation policy. Read mounts cannot expose runtime storage.

Configure the slice with finite `MemoryMax`, `MemorySwapMax`, `TasksMax` and
`CPUQuota`, then run `sandcrab serve --config FILE` as root in `supervisor_unit`
under that slice. Give the supervisor its own memory/task limits. Startup requires
that unit's MainPID, verifies the pool and tools, takes the runtime lock and cleans
up previous runs. `sandcrab check --config FILE` checks protected configuration,
accounts and tools; it does not prove the runtime slice or sandbox works.

Each run executes as the profile's account in a fresh bounded tmpfs at
`/workspace`, with a private `/tmp`, isolated network and PID namespaces and
seccomp. It shares the host kernel; this is not a microVM boundary. Workspace bytes
are disposable after the run. Read mounts are the operator's responsibility.

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
| `GET /v1/openapi` | The bundled [OpenAPI contract](openapi.json) |
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

`RUN_CAPACITY` refuses before execution. `RESULT_CAPACITY` means retained records
or output reservations must be forgotten. `max_output_bytes` bounds reserved raw
output, not total process memory; the slice bounds runtime, tmpfs and overhead.
Reserve enough supervisor memory for encoded responses and retained output.

## Verification

`executorRustCheck` checks the binary and its configuration/request tests.
`native_probe.py --binary FILE --tools DIRECTORY --report FILE`, run as root on
Linux, creates its own bounded slice and service and exercises real CLI/HTTP,
containment, cancellation, replay, capacity, restart and cleanup. It uses no
model API and reports deterministic evidence only. It does not establish agent
usability, OpenSandbox compatibility or Poketto adoption.
Independent agent tasks and their budgeted runner live in the
[Inspect suite](../../../evals/README.md).
