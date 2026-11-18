# Commands and results

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
sandcrab events --socket /var/lib/sandcrab/runtime/control.sock RUN_ID
sandcrab events --socket /var/lib/sandcrab/runtime/control.sock RUN_ID --after CURSOR
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
