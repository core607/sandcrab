# OpenSandbox adapter

Set `service.opensandbox = true` with the authenticated loopback TCP listener in
[config.example.toml](config.example.toml). The adapter is disabled by default.
It targets the published OpenSandbox 1.1.0 Python and Kotlin SDKs. The
[independent SDK clients](../../../evals/sdk/README.md) exercise both against
the native daemon, including named shell contexts.

## Connection and ownership

Configure the SDK with `protocol="http"`, the literal loopback `host:port` and
the service token as its API key. Lifecycle requests use
`OPEN-SANDBOX-API-KEY`; native requests still use Bearer authentication. Endpoint
lookup returns a distinct `X-EXECD-ACCESS-TOKEN` for each sandbox. The SDK forwards
that header to its execd requests. Endpoint addresses come from the operator's
listener configuration. Deletion, expiry and service restart revoke the scoped
credentials, including when a native client reuses a sandbox's public ID.

The lifecycle key controls the service's sandboxes; it is not a tenant identity.
The transport and host trust requirements are those of [native TCP](README.md#loopback-tcp).
The SDK's Kubernetes `secureAccess` option is unsupported; scoped endpoint
credentials are always required by this adapter.

Install the [pinned Python dependencies](../../../evals/sdk/requirements.txt), set
`SANDCRAB_TOKEN_FILE` to your private client token file, and enable the `python`
profile and TCP example above. `SANDCRAB_ENDPOINT` defaults to `127.0.0.1:9011`.
This client writes a program, runs it and reads its output file:

```python
import asyncio
import os
from datetime import timedelta
from pathlib import Path

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig


async def main():
    connection = ConnectionConfig(
        domain=os.environ.get("SANDCRAB_ENDPOINT", "127.0.0.1:9011"), protocol="http",
        api_key=Path(os.environ["SANDCRAB_TOKEN_FILE"]).read_text().strip(),
    )
    sandbox = await Sandbox.create(
        "python", connection_config=connection, timeout=timedelta(seconds=60),
        resource={"cpu": "0.25", "memory": "32Mi"},
    )
    try:
        await sandbox.files.write_file(
            "answer.py", "from pathlib import Path\nPath('answer.txt').write_text(str(6 * 7))\n"
        )
        result = await sandbox.commands.run(["python3", "answer.py"])
        if result.exit_code != 0:
            raise RuntimeError("The sandbox command did not succeed")
        print(await sandbox.files.read_file("answer.txt"))
    finally:
        try:
            await sandbox.kill()
        finally:
            await sandbox.close()


asyncio.run(main())
```

## Lifecycle

`image.uri` selects an operator profile. The SDK default entrypoint
`["tail", "-f", "/dev/null"]` selects an idle managed shell; it does not launch
that executable. Other entrypoints and image authentication are refused.

Create, get, filtered list, renew and delete use `/v1/sandboxes`. Endpoint lookup
maps ports 44772 and 18080 to path-routed command and read-only egress services.
The returned network policy is the enforced deny-all policy. Custom networking,
images, snapshots, templates, scheduling, credential proxies and volume requests
are refused. Unused snapshot, template, platform, resource-request, lifecycle,
network, credential-proxy and volume options may be omitted or null. Unknown
fields fail.

Supply an explicit timeout between 60 and 86400 seconds within the profile's
session lifetime limit. Renewal sets an absolute expiry and remains bounded by
the profile. Manual cleanup with no expiry is unsupported. Call `kill()` to
delete the remote sandbox and close the SDK client's local resources separately.
Deletion waits for containment; an uncertain cleanup returns an error and keeps
ownership reserved.

Resource limits must include CPU and memory. CPU accepts whole cores, at most two
decimal places or millicores divisible by ten. Memory accepts integer bytes or
`Ki`, `Mi`, `Gi`, `Ti`, `k`, `M`, `G`, `T` suffixes. Requests may lower the profile's
limits within its memory floor and cannot raise them. The SDK defaults can exceed
a small profile, so set limits explicitly.

## Commands

Foreground command strings and literal argument arrays return SDK SSE events.
Each command starts in `/workspace` unless given a literal working directory;
command-specific environment values override creation values. Changes to shell
variables and working directory do not persist between these foreground calls.
Environment expansion in a working-directory option, caller UIDs/GIDs and detached
execution are refused. Native timeout and output limits still apply.

Command status retains at most `service.max_records` outcomes across SDK
sandboxes, evicting completed, unobserved entries first. Native result records are
reclaimed after observation ends. Disconnecting the SSE stream does not replay
or cancel a command. Timeout and explicit cancellation terminate the command's
internal shell while preserving the sandbox workspace. A subsequent independent
command creates another internal shell. Unconfirmed cleanup fences the entire
workspace and retains its storage and admission until restart recovery.

Output is decoded incrementally as UTF-8; invalid bytes become U+FFFD. Use file
downloads for binary results. An uncertain command outcome emits an error without
a successful completion event. The [native host-call interface](host-calls.md)
has separate result ownership; composing it with SDK command retention is not
yet supported by the adapter.

## Shell contexts

Use `commands.create_session(working_directory=...)`, `run_in_session(id, command)`
and `delete_session(id)` in Python; Kotlin exposes `createSession`, `runInSession`
and `deleteSession`. The wire paths are `POST /session`, `POST /session/ID/run`
and `DELETE /session/ID` beneath the sandbox's execd endpoint. Creating a context
accepts an empty body and returns `session_id`.

A named context retains variables, functions, working directory and background
processes. Its initial environment comes from sandbox creation. A literal
working-directory override persists for subsequent commands; that directory must
exist. Contexts share `/workspace` and the parent's aggregate resource limits,
while each has its own `/tmp`. Different contexts may execute concurrently;
another command in a busy context is refused.

Deleting, exiting, cancelling or timing out a named context preserves shared
files and other contexts. An ended named context never silently restarts; delete
its retained identity and create a new context. Sandbox expiry or deletion closes
every context. Context identities count against native `max_records`; their
generations prevent an old SDK handle from reaching a reused native ID. Omitted
or zero session-run timeouts use the bounded profile default.

OpenSandbox Python 1.1.0 loses the HTTP status of a parsed `create_session` error:
an HTTP 400 becomes a `SandboxApiException` with `status_code=200`. Treat that
exception as failure. The conformance receipt records this SDK limitation;
independent wire checks verify Sandcrab's actual status and resource cleanup.

## Files

SDK uploads accept fixed-length and chunked multipart bodies. Downloads return
fixed-length raw bytes. Paths are relative to `/workspace` or start with
`/workspace/`; traversal, symlink parents and other absolute roots are refused.
Upload parents must already exist. File ownership remains the execution profile's UID
and GID. SDK decimal octal permissions, such as `640`, select ordinary permission
bits; owner/group overrides and special bits are refused.

A request contains at most 128 files, with aggregate content bounded by the
profile's `transfer_bytes`. Multipart metadata and headers have separate bounds.
Transfers use the native file admission limits. Body ingestion and download
transmission each have a 30-second deadline; helpers and cleanup have separate
bounded deadlines.
The bounded file helper stages the complete request before freezing the sandbox
to validate destinations and publish. A malformed or incomplete body publishes
nothing. Each file replacement is atomic; the entire batch is not a transaction.
An I/O failure during publication may leave a partial batch and returns
`PUBLICATION_UNKNOWN`. Inspect file contents before deciding whether to retry.

Downloads freeze only while making their private snapshot; a slow reader does
not keep the sandbox frozen. Byte and line selections also use private snapshots.
Closing, expiry and cancellation retain workspace ownership until transfer
helpers and cleanup finish. An uncertain cleanup fails the request and fences
the affected workspace until service recovery.

### Partial downloads

The SDK's `Range` option accepts one closed byte range (`bytes=3-7`), an open
range (`bytes=3-`) or a suffix (`bytes=-4`). A successful selection returns HTTP
206 with the exact `Content-Range` and `Content-Length`. An empty file, zero suffix
or starting position beyond EOF returns 416. The selected byte count, rather than
the source file's size, must fit `transfer_bytes`; this permits bounded reads of
larger files. Multiple ranges and `If-Range` are refused.

Line reads use a positive, one-based `offset` and an optional positive `limit`.
Providing only a limit starts at line one; providing only an offset reads to EOF.
Following the pinned SDK contract, each selected line loses its trailing CR/LF
bytes and the selected lines are joined with LF. An offset beyond EOF returns an
empty body. Range and line options cannot be combined. Line scanning and output
are each bounded by `transfer_bytes`, and long lines are processed incrementally.

Byte ranges and line selections do not expose the full-file ETag. Each request
observes its own snapshot; separate selections do not establish a consistent
multi-request view of a file that changes between calls.

## Directory and file management

The SDK can create directories, list and search entries, read metadata, move files or
directories, remove files or directory trees, change permissions and replace
literal file content. These operations use the same workspace lease and bounded
file helper as transfers; the sandbox is frozen for each operation.

Directory creation makes missing parents in normalized path order. Requested
modes apply to new directories; existing directories keep their modes. Listing
defaults to one child level, accepts depths from zero to 64, and reports entries
in lexical order with descendants following their parents. Links appear as
`symlink` entries and are never traversed. Metadata reports numeric UID/GID strings;
`created_at` uses filesystem birth time when available and inode change time
otherwise. Directory sizes are zero. Metadata responses are bounded at 60,000
JSON bytes and fail explicitly when they exceed the bound.

Search walks recursively and matches the pattern against each non-directory
entry's basename, as in the pinned OpenSandbox endpoint. It returns symlinks as
entries without traversing their targets. Patterns support `*`, `**`, Unicode
`?`, character classes and ranges, brace alternatives, backslash escapes and
whole-name negation such as `!(lock.json)`. Negation inside a larger expression is
refused. Patterns are bounded at 1024 bytes, 16 brace levels and eight whole-name
negations; compilation and matching run in the bounded file helper. A search
visits at most 10,000 entries and 64 levels and shares the metadata response bound.
Invalid patterns fail even when no entries would match.

JSON mutation requests accept at most 128 entries. Metadata and removal queries
use the native query bounds of 32 parameters and 4096 encoded bytes. Duplicate
normalized paths are rejected, as are overlapping removal paths, overlapping
move sources or destinations, and moves into their own descendant. A move
replaces an existing compatible destination; replacing a nonempty directory
fails. Recursive removal unlinks child symlinks without following them and visits
at most 10,000 descendants across the requested trees, with at most 64 levels.

Every request validates its parameters and filesystem preconditions before its
first mutation. Mutations are not batch transactions: an I/O failure, interruption
or uncertain helper outcome may follow partial changes and returns
`FILE_OPERATION_UNKNOWN`. Inspect the affected paths before retrying. Successful
mutation calls without a result have an empty response body.

Content replacement matches nonempty literal UTF-8 pattern bytes without decoding
the file, preserving unrelated binary bytes and ordinary permission bits. Files
with special permission bits are refused. Aggregate input and staged output are
each bounded by `transfer_bytes`; the entire batch is staged before publication.
Detailed calls return a replacement count for every requested path, including
zero matches. A zero-match file is not rewritten.
