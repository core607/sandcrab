# Persistent Workspaces

Date: 2026-11-18

## Problem

Agent applications keep one working directory per user or conversation for hours
or days. A Sandcrab session is a bounded process tree. The profile's
`session_ttl_millis` caps each open or renewal, the
[installed default profile](../../crates/sandcrab/install/default.toml) uses 60
seconds, and renewal cannot revive an expired or closed session. Disconnects
neither stop nor renew it ([persistent sessions](../../crates/sandcrab/README.md#persistent-sessions)).
Durable files live in volumes, and one session owns a volume exclusively until
confirmed cleanup ([durable volumes](../../crates/sandcrab/README.md#durable-volumes)).

A caller that wants a long-lived agent directory therefore composes volume
creation, session open, renewal, reopening after expiry, serialization of
concurrent requests, restart reconciliation and orphan cleanup. Poketto implements
this composition in its executor, for example its
[session pool](https://github.com/core607/poketto/blob/main/src/main/java/io/github/core607/poketto/executor/internal/NativeRepositoryPool.java)
and [lease](https://github.com/core607/poketto/blob/main/src/main/java/io/github/core607/poketto/executor/internal/NativeRepositoryLease.java).
An application replacing host subprocess and file tools with Sandcrab must rebuild
the same state machine before its first useful command.

The namespace backend cannot checkpoint processes or release an idle sandbox's
memory. Keeping one live session per user does not fit the two-CPU, 4 to 8 GB
reference host in the [provider decision](../implemented/2026-11-02-sandcrab-lightweight-service.md).

## Proposal

This is an unimplemented design. Sessions, volumes and templates remain supported
interfaces; a workspace composes them rather than adding a second storage system.

- **Identity.** The caller supplies a bounded opaque key. Within one authenticated
  client identity, the same key always resolves to the same workspace and its stable
  ID. The daemon never interprets a key as a user, tenant or grant.
- **Storage.** Each workspace owns one volume, created on first use within the
  profile's byte and inode bounds. Files persist until the caller deletes the
  workspace or an operator-configured retention policy expires it.
- **Execution.** A workspace command attaches the live session when one exists and
  otherwise opens one on the volume first. Each admitted command moves the session
  deadline to the later of its current value and the profile's idle window. An
  idle session closes; its files remain. Every result states whether the command
  started in a fresh shell, because working directory, variables and processes do
  not survive a reopen.
- **Concurrency.** Commands for one workspace run in admission order through its
  shell, behind a bounded per-workspace queue. Overflow is refused with a distinct
  error and never dropped silently or turned into a volume ownership failure.
- **Files.** Read, write, list and search operate on the workspace. They use the
  attached session or a short-lived helper, so callers never hold session IDs.
- **Recovery.** After a restart the daemon reconciles workspace records with
  volumes and sessions under the existing containment rules. Uncertain cleanup
  keeps capacity reserved, as it does today. Host calls behave as they do for
  session commands.

Acceptance criteria:

- A caller runs commands across simulated days of idleness knowing only its key,
  without renewal calls, and observes the fresh-shell signal after each reopen.
- Concurrent submissions to one workspace complete in order or receive the
  overflow error; none fails on volume ownership.
- A daemon restart preserves files and reports a fresh shell on the next command.
- Poketto can replace its session pool and lease renewal with workspace calls in
  a separate consumer change.

Remaining design questions: key scope across client identities and the OpenSandbox
adapter; seeding a workspace from a template or overlay checkpoint; default idle
window, maximum lifetime and retention; queue bounds; whether parallel child shells
are needed; and how hard storage quotas, proposed in
[hard workspace quotas](2026-11-18-hard-workspace-quotas.md), apply to workspaces.

## Alternatives

- Keep the composition in callers. Each integrator rebuilds leases, renewal and
  recovery, which Poketto's executor shows is the bulk of integration work.
- Implement workspaces in the SDKs only. Python, TypeScript and any later client
  would duplicate the state machine, and a restarted client cannot reconcile
  server-owned containment and ownership.
- Raise session lifetimes to a day. Idle shells would hold memory and tasks on the
  reference host, and expiry or restart would still break callers.
- Keep one long-lived sandbox per user, as OpenSandbox does. On Kubernetes its
  [pause and resume](https://github.com/opensandbox-group/OpenSandbox/blob/main/docs/guides/pause-resume.md)
  commits the root filesystem, drops processes and keeps a stable sandbox ID. This
  proposal adopts the stable identity and filesystem-only resume without the
  cluster dependency.

## Consequences

The daemon gains durable workspace records and a scheduler for attaching and
closing idle sessions, which enlarges its trusted surface. Shell state stays
best-effort and callers must handle the fresh-shell signal. Workspace keys do not
add tenant isolation: as the [threat model](../../THREAT-MODEL.md) states, a party
holding the service credential controls every sandbox in an installation, so
callers authorize their users before choosing keys. Before 1.0 the workspace API
replaces caller composition without compatibility shims.

## Verification

Native conformance covers idle reopen with a short idle window, restart, ordered
concurrent submissions, queue overflow, volume exhaustion, retained reservations
after failed cleanup, host calls through workspace commands and key isolation
between client identities. Python and TypeScript SDK acceptance exercise the same
cases. The density benchmark confirms that an idle workspace keeps no resident
processes and measures reopen latency against a plain session open. Poketto's
adoption runs through the downstream release check.
