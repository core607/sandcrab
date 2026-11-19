# Agent workspace tools

Date: 2026-11-18

## Decision

Applications bind one authorized [workspace](2026-11-18-persistent-workspaces.md) before giving an agent shell or file tools. Moving both kinds of tool keeps the agent's commands, reads and edits inside the same filesystem boundary. The daemon provides the six input schemas. Python, TypeScript and the stdio MCP server expose bounded results and the same error codes. The application owns authorization and credentials.

A read supplies a version of the frozen file, including for a partial read when the whole-file digest fits the transfer budget. An exact edit requires that version. The [native file operation](../../crates/sandcrab/docs/files.md) compares and replaces under one freeze, so another client or a guest command can invalidate an edit. A successful append after idle reopen reports a fresh shell. An unverifiable write receipt asks the caller to inspect the workspace before another submission.

The session-scoped catalog remains useful to clients that manage sessions explicitly. A workspace-bound model can work without choosing service IDs. Keeping the base schemas independent of an agent framework lets applications register the same handlers with their own tool dispatcher. The separate [optional toolbox proposal](../proposed/2026-11-10-optional-toolbox-and-isolation-backends.md) addresses application-defined tools.

## Verification

The [packaged client checks](../../evals/sdk/workspace_checks.py) exercise Python, TypeScript and MCP against the native service. The [scripted comparison](../../evidence/sandcrab-workspace-tools-scripted-2026-11-18/summary.json) checks the grader and cleanup. The [GPT-6 Luna comparison](../../evidence/sandcrab-workspace-tools-luna-2026-11-19/summary.json) records one independently graded trial per catalog on each of the same six tasks.
