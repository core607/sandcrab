# Host calls

Host calls let a sandbox program ask its caller to perform an application operation.
Sandcrab relays opaque request and reply bytes; it runs no host handler and interprets
no business fields. The caller authorizes each request and owns any outside effect.

Enable `host_calls = true` in the selected operator-owned profile, then restart the
service under its normal lifecycle. The default is false. Enabled finite runs and
session commands receive the `sandcrab call` helper and a protected mailbox. Profiles
cannot mount over `/sandcrab`, `/sandcrab-driver` or `/sandcrab-calls`.

The [build-signing example](../../../examples/sandcrab-host-calls.py) uses the public CLI
as an ordinary client. It authorizes one artifact digest, signs it with a caller-owned
key, and verifies the sandbox's returned signature:

```sh
python3 examples/sandcrab-host-calls.py --binary /usr/local/bin/sandcrab \
  --socket /run/sandcrab-demo/control.sock --profile python
```

The example generates an ephemeral key unless `--key-file FILE` supplies exactly 32
bytes. It does not send the key to Sandcrab; keep a supplied key private to the caller
and outside profile read mounts. Its reply ledger lasts only for that process;
applications with durable outside effects need persistent idempotency and recovery.
It cancels a failed command and retains its result for inspection.

## CLI

Inside an enabled sandbox, `sandcrab call FILE` sends the file's bytes and writes the
reply bytes to stdout. `FILE` may be `-` for stdin through EOF. The send/reply timeout
defaults to 60000 milliseconds; `--timeout-ms N` accepts 1 through 300000. The command's
own timeout and session expiry still apply. A timeout or lost reply reports an unknown
outcome and never resends the request. Stderr includes `requestId` and `runId` for
correlation with the caller's records.

The caller observes and replies through separate commands:

```sh
sandcrab calls events --socket /run/sandcrab-demo/control.sock RUN_ID
sandcrab calls reply --socket /run/sandcrab-demo/control.sock RUN_ID CALL_ID ./reply.bin
sandcrab calls list --socket /run/sandcrab-demo/control.sock RUN_ID
```

`CALL_ID` is the daemon-generated `id` in a call event, distinct from the guest's
`requestId`. Guest-selected IDs cannot select a reply handle in a later command.
`reply` also accepts `-` for stdin. These commands support the documented
[TCP endpoint and token options](README.md#loopback-tcp).

Use the CLI's [result-retention option](README.md#cli) when another observer or
caller still needs the result. Forget the run after both observations and caller
reconciliation finish.

## HTTP and observation

The [OpenAPI contract](openapi.json) defines the schemas; request the bounded
`/v1/openapi?capability=calls` view for discovery.

| Request | Behavior |
|---|---|
| `GET /v1/runs/ID/calls` | List call IDs, guest request IDs, sequence numbers, states and SHA-256 digests |
| `GET /v1/runs/ID/calls/events` | Stream unresolved requests and command completion as SSE |
| `POST /v1/runs/ID/calls/CALL_ID/reply` | Supply `{"base64":"..."}` with canonical base64 reply bytes |

SSE starts with `state`, carries `call` events with request bytes in `base64`, and
ends with `result` after confirmed command containment. An `error`, heartbeat or
EOF does not prove completion. Request IDs, payloads and digests are observations,
not a grant to perform an outside action.

Each complete frame carries a command incarnation and request sequence. Reconnect
explicitly with `Last-Event-ID`, or CLI `calls events --after CURSOR`, to continue
after delivered requests. Starting without a cursor offers unresolved calls again
with the same IDs. Requests already recorded as replied are skipped when selecting
events, but an in-flight event can be stale. Observers do not claim work exclusively:
callers coordinate handlers and reconcile duplicate IDs before repeating effects.

Each request and reply is at most 65536 decoded bytes. A command allows at most 64
calls and four unacknowledged requests, including replies awaiting the guest's
acknowledgement. Malformed guest frames or excess calls fail the command. Output
and host-call streams share observer admission and observation deadlines. A host-call
frame is at most 131072 bytes and can span multiple HTTP chunks; only the host-call
reply route accepts a JSON body up to that bound. Other request limits remain in the
[native HTTP contract](README.md#http).

## Outcomes and recovery

Calls are `pending`, `replied`, `uncertain` or `abandoned`. Listing returns metadata;
only request events include payloads. Payloads are released when a reply is attempted
or the command ends. Metadata lasts until the run is forgotten or the daemon restarts.

`replied` confirms publication of the reply file. It does not prove guest consumption
or commit an outside business transaction. An identical reply returns its retained
receipt without publishing again, even after command completion. Different reply
bytes return `CALL_REPLY_CONFLICT`.

An uncertain publication returns `CALL_REPLY_UNCERTAIN` and cancels the command.
Repeating that reply stays uncertain. Cancellation, expiry and command closure refuse
new replies with `CALL_CLOSED`; unanswered calls become abandoned. Reconnects never
restart a command. Missing records after forgetting or restart do not prove an outside
effect did not occur: reconcile against the caller's durable business records.
