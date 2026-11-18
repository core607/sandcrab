# Persistent sessions

```sh
sandcrab session open --socket /var/lib/sandcrab/runtime/control.sock --profile default --ttl-ms 60000
sandcrab session exec --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID -- 'mkdir project; cd project; export VALUE=42'
sandcrab session exec --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID -- 'printf "%s\n" "$VALUE"; pwd'
sandcrab session renew --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID --ttl-ms 60000
sandcrab session close --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID
sandcrab session forget --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID
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
as [periodic storage limits](volumes.md#storage-accounting). Private `/tmp` and finite-run
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
