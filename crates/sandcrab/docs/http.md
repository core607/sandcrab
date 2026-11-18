# Client connections and HTTP

## Loopback TCP

Enable `[tcp]` in [config.example.toml](../config.example.toml) with a literal
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
sudo sandcrab client-token --user app --output /etc/sandcrab-client/token
sandcrab --token-file /etc/sandcrab-client/token info --endpoint http://127.0.0.1:9011
sandcrab run --endpoint http://127.0.0.1:9011 --token-file /etc/sandcrab-client/token --profile python --stream -- python3 -c 'print(6 * 7)'
```

`client-token` validates `--config` (default `/etc/sandcrab/config.toml`), refuses
root and configured sandbox execution accounts or groups, and writes an atomic
`0600` copy owned by `--user` outside configured mounts. Provision the copy in a
root-owned directory the client can traverse. Only root may write that directory or
any of its ancestors. Use `--replace` to rotate an existing regular file.
`--token-file` may appear anywhere before `--`. `SANDCRAB_TOKEN_FILE` supplies the
client path when the flag is absent.
`--endpoint` and `SANDCRAB_ENDPOINT` accept `http://LOOPBACK:PORT` or `LOOPBACK:PORT`.
When reading an existing copy, the client accepts ownership by root or that client
for the file and its ancestors. The file must have mode `0400` or `0600`,
and other accounts must lack write access to the directories. Symlinks, hard-linked files and parent traversal are refused. Credentials
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
length of 1 to 65536 bytes; [host-call replies](../host-calls.md#http-and-observation) have a separate bound.
GET requests have no body. Headers are at most 8192 bytes
and 32 fields. Only event responses use chunked framing; requests and other responses
require fixed lengths. Duplicate headers and upgrades are rejected; pipelining is unsupported. Only `client_uid` is accepted, even if another
account can connect to the socket. TCP uses the bearer credential above.

| Request | Result |
|---|---|
| `GET /v1/info` | API version, server epoch, capabilities and profile limits |
| `GET /v1/openapi` | The bundled [OpenAPI contract](../openapi.json); `?capability=runs`, `sessions`, `volumes`, `files`, `uploads`, `events`, `calls` or `templates` selects a bounded view with its referenced schemas. Views describe common discovery fields and selected capability metadata; the response also carries the other fields documented by the full contract. |
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

An operator may set `cpu_weight = 10` in a background profile to give runnable
peer workloads a smaller CPU share under contention. The range is 1..10000;
omitting it keeps the equal-weight default of 100. `cpuWeight` in info is read-only:
callers select an operator-defined profile and cannot override its weight. A
session's parent cgroup bounds all its named shells together. Finite runs and
bounded profile helpers also use the profile weight. The daemon verifies each
weight before execution; failure refuses startup. Weights do not reserve CPU or
relax CPU, memory, task or zero-swap limits. See the [measured service-class
comparison](../../../evidence/sandcrab-service-classes-2026-11-09/summary.json) for its
synthetic workload and the separate startup/execution-bound decision.

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
