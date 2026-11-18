# Agent Workspace Tools

Date: 2026-11-18

## Problem

Agent frameworks give a model a command tool and a few file tools. Applications
commonly implement them on the host: a shell subprocess guarded by pattern deny
lists, plus direct reads and writes of host paths. Moving such an application onto
Sandcrab only helps if every one of those tools moves. Replacing the command tool
alone leaves file tools writing the host directly.

The [stdio MCP server](../../sdk/python/README.md#stdio-mcp-server) exposes
session-scoped tools: a one-shot run, session open, exec and close, and file write,
read, mkdir, list and search. The model must create sessions, carry their IDs and
manage their lifetime, and there is no edit tool. Applications that register tools
through their own function-calling layer rather than MCP have no reusable schemas
or handlers and write their own.

## Proposal

This is an unimplemented design that depends on
[persistent workspaces](2026-11-18-persistent-workspaces.md).

The Python and TypeScript SDKs provide a framework-neutral tool set bound to one
workspace:

| Tool | Behavior |
|---|---|
| `exec` | Run a shell command with a bounded timeout |
| `read_file` | Read all or part of a file and return the version of that snapshot |
| `write_file` | Create or replace a file |
| `edit_file` | Replace exact text, guarded by the file digest the model last read |
| `list_dir` | List a bounded tree |
| `search` | Search names or contents with bounded results |

Each tool ships a JSON schema, an async handler and a bounded text result with an
explicit truncation marker. Failures distinguish refusal before execution, timeout,
unknown execution outcome and edit conflict. `freshShell` is execution metadata,
including when a command succeeds. Reopening a workspace does not replay a command.
The workspace read returns a digest of the complete frozen version, including
for a range when the complete digest fits the read budget. A read without a
version is ineligible for a conditional edit. The handler passes the expected
digest to the daemon, which compares it and publishes the edit atomically.

The application authorizes its user and binds the tool set to a workspace key
before the model sees any tool. The model never sees or chooses keys, session IDs
or volume IDs. The MCP server offers the same set, bound to a workspace chosen when
the server starts.

An integration guide shows how to replace host subprocess and file tools together,
and states that a partial replacement leaves the host exposed.

Acceptance criteria:

- An application replaces host command and file tools with a few dozen lines of
  SDK calls.
- Python and TypeScript return identical result shapes and error codes.
- Two edits from the same version yield one success and one conflict. A change
  made by a shell command after a partial read also produces a conflict.
- A successful append after idle reopen returns success with `freshShell` and
  appends once.

Remaining design questions: result size limits and binary content handling; whether
search runs a tool inside the sandbox or a daemon helper; and whether thin adapters
for specific frameworks belong in the SDKs or in examples.

The [toolbox proposal](2026-11-10-optional-toolbox-and-isolation-backends.md)
addresses discovering application-defined tools inside a sandbox. This tool set is
the fixed base those applications start from, and the two do not depend on each
other.

## Alternatives

- Keep the session-scoped MCP tools. Models would keep managing sandbox lifetimes,
  and applications without MCP would keep writing their own handlers.
- Ship adapters for each agent framework in the SDK core. Each framework's release
  cadence would become SDK maintenance work.
- Leave tool design to integrators. Every integration would repeat the same edit,
  truncation and partial-replacement mistakes.

## Consequences

The SDK surface grows and the tool contract becomes something that must change
consistently across languages. File versioning and conditional writes belong to
the native workspace API so independently connected clients share the guarantee.
Applications still own user authorization, credentials and effects outside the
sandbox.

## Verification

SDK tests run every tool against a native fixture, including truncation, timeouts,
edit conflicts and fresh-shell reporting. The integration guide's quickstart runs
in CI like the existing [SDK quickstarts](../../sdk/python/README.md#run-your-first-session).
[Evaluations](../../evals/README.md) compare the session-scoped MCP tools with the
workspace tools on the fixed programming tasks.
