# Sandcrab Python SDK and MCP server

The `sandcrab` package provides synchronous and asynchronous clients for Sandcrab's
native control API (`SandcrabClient`, `AsyncSandcrabClient`), declarative caller-side
host-call dispatch (`HostCallDispatcher`, `AsyncHostCallDispatcher`), a standard-library
JSON-RPC 2.0 stdio MCP server (`sandcrab-mcp`), and the `sandcrab_templates` extension
used alongside the published OpenSandbox SDK. It requires Python 3.11+ and `httpx>=0.28.1,<1`.

Install the SDK version matching the service release. The client discovers
`/v1/info` before its first operation and warns if the service advertises a
different release version. Older services may omit this field.

## Run your first session

Run this example on the Linux host where Sandcrab is installed. Use the application
account that owns the token from the [service setup](https://github.com/core607/sandcrab#connect-an-application).
In an empty directory, create a virtual environment. Use the PyPI command below
for a published version. For a version awaiting publication, give pip the
absolute path to `sdk/python` in the [matching checkout](https://github.com/core607/sandcrab/tree/v0.3.0)
in place of `sandcrab==0.3.0`.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install sandcrab==0.3.0
```

Save this as `example.py`.

```python
from sandcrab import SandcrabClient

with SandcrabClient(
    endpoint="http://127.0.0.1:9011",
    token_file="/etc/sandcrab-client/token",
    default_profile="default",
) as client:
    with client.open_session() as session:
        session.write_file("src/main.py", "print(6 * 7)\n", parents=True)
        session.exec("python3 src/main.py > answer.txt", check=True)
        print(session.read_text("answer.txt").strip())
```

Run the example. It prints `42` and closes and forgets the session on exit.

```sh
.venv/bin/python example.py
```

## Bind tools to an agent

On a service advertising `workspaces`, authorize the user and choose their
workspace key in the application. Use the same key to resume its files later.

```python
from sandcrab import open_workspace_tools

with open_workspace_tools("example-project", endpoint="http://127.0.0.1:9011",
                          token_file="/etc/sandcrab-client/token") as tools:
    tools.call("write_file", {"path": "hello.py", "content": "print(42)\n"})
    print(tools.call("exec", {"command": "python3 hello.py"})["stdout"].strip())
```

For an async framework, call `await client.workspace_tools(key)` on
`AsyncSandcrabClient`. Register each entry in `tools.schemas` with its
corresponding async callable in `tools.handlers`. The six tools cover commands,
reading, writing, exact edits, listing and search. Replace the application's
host file tools along with its shell tool.

`read_file` returns the whole-file version for `edit_file`. On `EDIT_CONFLICT`,
read the file again. After `OUTCOME_UNKNOWN`, inspect the affected files before
another write. `freshShell` on a successful command means the shell was newly
opened. Closing the client keeps the files. The application can call
`tools.dispose()` (await it on the async client) for permanent deletion.

For the same tools through stdio, start `sandcrab-mcp --workspace example-project
--endpoint http://127.0.0.1:9011 --token-file /etc/sandcrab-client/token`.

## Native client

Connect over a root-owned Unix control socket or a literal loopback HTTP endpoint with a
64-hex service token. Redirects and environment proxies are disabled. When neither
`socket_path` nor `endpoint` is passed, the client reads `SANDCRAB_SOCKET` or
`SANDCRAB_ENDPOINT` (plus `SANDCRAB_TOKEN_FILE` and `SANDCRAB_PROFILE`), and refuses
implicit selection if both transport variables are set.

Exiting `with client.open_session() as session:` (or `async with await client.open_session()`)
closes and forgets the session unless `keep_result=True` or `auto_close=False` is set.
`run()` and `session.exec()` stream output when `on_output` is supplied, forget completed
records unless `keep_result=True`, and raise `CommandFailedError` when `check=True` and
the command does not succeed.

If transport fails after submitting a mutating request (`submit_run`, `open_session`,
`submit_session_command`, `create_volume`), the client raises `TransportUncertainError`
carrying `recovery_id` and never reposts under a new ID.

Workspace file helpers (`write_file`, `read_file`, `read_text`, `mkdir`, `list_files`,
`search_files`, `remove_file`, `diff`, `snapshot`) enforce normalized relative paths,
verify `ETag` digests on complete downloads, and support HTTP byte ranges (`byte_range`)
or 1-based line ranges (`offset`, `limit`). `import_template()` streams plain `.tar`
archives directly and gunzips `.tar.gz` / `.tgz` archives on the client before sending
bounded `application/x-tar` bytes.

## Caller-owned host calls

`HostCallDispatcher` and `AsyncHostCallDispatcher` run handlers in the caller's process
while Sandcrab relays opaque bytes; see [host calls](https://github.com/core607/sandcrab/blob/main/crates/sandcrab/host-calls.md).

```python
import hashlib, hmac
from sandcrab import HostCallDispatcher, SandcrabClient

dispatcher = HostCallDispatcher()

@dispatcher.on_json("sign-sha256")
def sign_digest(request: dict, context) -> dict:
    digest = request["digest"]
    if digest != expected_digest:
        raise PermissionError("outside build grant")
    sig = hmac.new(signing_key, bytes.fromhex(digest), hashlib.sha256).hexdigest()
    return {"digest": digest, "signature": sig}

with SandcrabClient(socket_path="/run/sandcrab/sandcrab.sock", default_profile="python") as client:
    client.run(["python3", "build_and_sign.py"], dispatcher=dispatcher, check=True)
```

Each event's `requestSha256` and serving epoch are checked before invoking a handler.
Dispatchers sharing an `InMemoryReplyLedger` share the result of overlapping
observations of the same `(run_id, call_id)` and reject changed payloads. With a
custom ledger, share one dispatcher to coordinate concurrent calls. For durable
external effects, record the reply in the transaction that commits the effect.
Any unhandled handler exception cancels the sandbox
command and leaves its record retained for inspection.

## Stdio MCP server

`sandcrab-mcp` (or [examples/sandcrab-mcp.py](https://github.com/core607/sandcrab/blob/main/examples/sandcrab-mcp.py)) serves
MCP `2024-11-05` and `2025-03-26` JSON-RPC 2.0 over stdio using only the Python standard
library alongside `SandcrabClient`:

```sh
sandcrab-mcp --endpoint http://127.0.0.1:9011 --token-file /etc/sandcrab-client/token --profile default
```

Exposed tools are bounded to sandbox execution and workspace-relative files:
`sandcrab_run`, `sandcrab_session_open`, `sandcrab_session_exec`,
`sandcrab_session_close`, `sandcrab_write_file`, `sandcrab_read_file`, `sandcrab_mkdir`,
`sandcrab_list_files`, and `sandcrab_search_files`. File tool payloads are capped at
1 MiB per call; larger files require `offset`/`limit` or `byte_range`. Sessions opened
through MCP are closed and forgotten automatically when stdin closes.

## Template publication alongside OpenSandbox (`sandcrab_templates`)

`sandcrab_templates` remains importable directly (and re-exported from `sandcrab`) for
filesystem capture and immutable publication beside the published OpenSandbox SDK.
From a source checkout, install both for the examples below.

```sh
python -m pip install ./sdk/python -r evals/sdk/requirements.txt
```

Create an authenticated `TemplateClient` with the literal loopback endpoint and service
token used by the OpenSandbox connection:

```python
async with TemplateClient("http://127.0.0.1:9011", token) as templates:
    checkpoint = await templates.capture(sandbox.id, "prepared.tar")
    # The builder may now be killed and its client closed.
    template = await templates.publish(checkpoint)
    fresh = await Sandbox.create(checkpoint.image, connection_config=config,
                                 timeout=timedelta(seconds=60),
                                 resource={"cpu": "0.25", "memory": "32Mi"})
```

Prepare and validate files before capture. `checkpoint.image` selects a rootfs
template in OpenSandbox; workspace captures use native session `templateId`.
The [native reference](https://github.com/core607/sandcrab/blob/main/crates/sandcrab/README.md#filesystem-capture) owns
freeze semantics, supported metadata, limits and omitted runtime state.
`Checkpoint.to_dict()` and `Checkpoint.from_dict()` save and load a trusted local
receipt; keep it with the captured archive outside the sandbox.

Capture checks the serving epoch, profile, filesystem kind, byte length and SHA-256
before atomically installing a new file without replacing an existing destination
(mode 0600 on POSIX). Cancellation closes the response and removes partial staging;
capture never publishes a template.

Publication verifies the local archive and sends `expectedId` to the server. Existing
matching objects are reused. After a lost transport reply, the client performs one read
to reconcile that ID and never reposts automatically; if absent, `PublicationUncertain`
carries its ID and `await templates.reconcile(checkpoint)` checks visibility later.

The [independent environment example](https://github.com/core607/sandcrab/blob/main/examples/sandcrab-environment.py) builds,
validates, captures, publishes, and starts two independent instances:

```sh
python examples/sandcrab-environment.py --base-image PROFILE@sha256:ID \
  --token-file ./client.token --archive ./prepared.tar --receipt ./prepared.json
```

Compose independently imported layers with `await templates.compose([base_id,
toolkit_id, workspace_id])`; the [native recipe
contract](https://github.com/core607/sandcrab/blob/main/crates/sandcrab/README.md#composable-recipes) owns ordering, whiteouts,
limits and reference lifetimes. `recipe_id(layers)` computes the expected ID locally, and
[examples/sandcrab-recipe.py](https://github.com/core607/sandcrab/blob/main/examples/sandcrab-recipe.py) validates composed layers:

```sh
python examples/sandcrab-recipe.py --token-file ./client.token --profile default \
  --validate 'bash /workspace/test.sh' BASE_ID TOOLKIT_ID WORKSPACE_ID
```

## Development

Run the SDK checks from the repository root.

```sh
python -m pip install ./sdk/python
python -m unittest discover -s sdk/python/tests -v
```
