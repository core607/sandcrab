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
| `POST /v1/workspaces/KEY` with `{"profile":"default"}` | Create or return the same workspace. A different profile conflicts. |
| `GET /v1/workspaces/KEY` | Read `state`, `generation`, `serverId` and `submissionWindow`. Wait for `ready` after creation. |
| `POST /v1/workspaces/KEY/commands` | Submit a [session command](sessions.md) with its own UUID, plus the workspace's `generation` and `submissionWindow`. |
| `GET /v1/runs/ID` | Read the command outcome and `freshShell`. A successful command after reopening has `freshShell: true`. |
| `POST /v1/workspaces/KEY/delete` with `{"generation":"…"}` | Record deletion, close the shell and remove storage after confirmed cleanup. Poll until `deleted`. |
| `POST /v1/workspaces/KEY/forget` with the same generation | Remove a deleted or failed record. Reusing the key creates a different generation. |

Commands admitted to one workspace run in order. A full queue refuses a submission
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
