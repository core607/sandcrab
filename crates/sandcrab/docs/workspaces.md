# Persistent workspaces

A workspace keeps files in a managed volume and opens a shell on the first
command. The daemon closes an idle shell after the profile's
`session_ttl_millis`. Files survive idle close and restart. A new shell starts
with the profile's working directory and environment. Look for `workspaces` in
`GET /v1/info` on an installation with storage enabled.

An authenticated application uses one key per working directory, up to 128 ASCII
letters, digits, periods, underscores and hyphens, starting with a letter or
digit. Keys are case-sensitive and installation-wide. The application owns user
authorization and the mapping to keys.

| Request | Result |
|---|---|
| `POST /v1/workspaces/KEY` with `{"profile":"default"}` | Create or reopen the workspace. Specify an imported `templateId` to start from an immutable base. The profile and base must match on reopen. |
| `GET /v1/workspaces/KEY` | Read `state`, `generation`, `serverId` and `submissionWindow`. Wait for `ready` after creation. |
| `POST /v1/workspaces/KEY/commands` | Submit a [session command](sessions.md) with its own UUID, plus the workspace's `generation` and `submissionWindow`. |
| `GET /v1/runs/ID` | Read the command outcome and `freshShell`. A successful command after reopening has `freshShell: true`. |
| `GET /v1/workspaces/KEY/diff` | Send `X-Sandcrab-Workspace-Generation` to export a consistent [upper-layer changeset](files.md) against the workspace's template. |
| `POST /v1/workspaces/KEY/delete` with `{"generation":"…"}` | Record deletion, close the shell and remove storage after confirmed cleanup. Poll until `deleted`. |
| `POST /v1/workspaces/KEY/forget` with the same generation | Remove a deleted or failed record. Reusing the key creates a different generation. |

Use the [native file operations](files.md) under `/v1/workspaces/KEY/files`
and pass `X-Sandcrab-Workspace-Generation` from workspace discovery. The daemon
opens a shell when needed and pins its generation through the transfer. File
reads, writes, exact edits, directory creation, listing, search and removal
use the same payloads as the session routes. The `workspace-files` OpenAPI
view contains their request and response schemas.

`GET /v1/workspace-tools` returns the tool names, descriptions and JSON input
schemas used by both native SDKs and the stdio MCP server. The application
binds a workspace before passing schemas and handlers to a model.

Template workspaces pin their base across idle close and service restart. Their
owned volumes retain edits and deletions. Store the downloaded changeset before
acknowledging application writes or deleting the workspace. The service keeps
the upper layer after a download.

Commands admitted to one workspace run in order. Set `freshChild: true` to
start with the profile's initial shell state for that command. Optionally pass `shellInit` to set its
working directory or environment first. Initialization and command have
separate 16 KiB source limits and share the command deadline. The service
enables host calls for the command after initialization succeeds. A
`SHELL_INIT_FAILED` result can include effects from setup; the command body
has not started.

Sandcrab contains the child and its descendants before reporting completion.
A full queue refuses a submission
before execution. The idle window extends on admission and after a command
finishes. Guest commands keep their own execution timeout. Empty workspaces
reserve the smaller of the profile's temporary storage limits and the
[volume limits](volumes.md).

For a new command, read the current workspace. Keep the command ID, server ID,
generation and submission window with the command body. If the submission
reply is lost, look up the run or resubmit the exact
request. A retained run returns the original result. Once a workspace run is
forgotten or expires, its submission window closes to new admissions. An old
ticket with no retained result returns `WORKSPACE_SUBMISSION_EXPIRED`.
`SERVER_CHANGED` after a daemon restart also leaves the previous outcome
unknown. Inspect the affected files or application state before deciding whether
to start a new command. Deleting and recreating a key fences old generations.
