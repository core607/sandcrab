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
concurrent requests, restart reconciliation and orphan cleanup. Poketto also
[seeds new copies from a scoped immutable template, runs each command in a fresh
shell and journals its writable layer before acknowledgement](https://github.com/core607/poketto/blob/b3121102991fb26ecd87cbc327042d202c9a8126/notes/implemented/2026-11-05-native-repository-consumer.md#decision).
Imported volumes use a renewable lease.
An application replacing host subprocess and file tools with Sandcrab must rebuild
the same state machine before its first useful command.

The namespace backend cannot checkpoint processes or release an idle sandbox's
memory. Keeping one live session per user does not fit the two-CPU, 4 to 8 GB
reference host in the [provider decision](../implemented/2026-11-02-sandcrab-lightweight-service.md).

## Proposal

The [native workspace API](../../crates/sandcrab/docs/workspaces.md) and the
Python and TypeScript SDKs support empty and template-backed workspaces. The
final acceptance is a separate consumer change exercising the normal
template-backed repository command path described below.

- **Identity.** A workspace key belongs to one installation. Authenticated native
  clients using the same key reach the same workspace across connections, daemon
  restarts and service-token rotation. Applications allocate distinct opaque keys
  and authorize access before using them. Reopening a key with a different
  profile or base must fail without altering the original workspace.
- **Storage.** An empty workspace owns a volume within the profile's byte and inode
  bounds. A template-backed workspace pins its immutable base and retains its
  writable layer across idle close and restart. The caller can export a consistent
  checkpoint. Files persist until explicit deletion or configured retention expiry.
- **Execution.** A workspace command attaches the live session when one exists and
  otherwise opens one on the volume first. Each admitted command moves the session
  deadline to the later of its current value and the profile's idle window. An
  idle session closes; its files remain. Every result states whether the command
  started in a fresh shell, because working directory, variables and processes do
  not survive a reopen. A caller may request a fresh child shell per command while
  keeping the same files. Shell freshness is result metadata on successful commands
  too. A caller can reconcile an interrupted submission by its operation ID;
  reconnecting must never execute an uncertain write a second time.
- **Concurrency.** Commands for one workspace run in admission order through its
  shell, behind a bounded per-workspace queue. Overflow is refused with a distinct
  error and never dropped silently or turned into a volume ownership failure.
- **Files.** Read, write, list and search operate on the workspace. A conditional
  edit compares the caller's file version and replaces content in one protected
  operation, including against guest writers. Callers never hold session IDs.
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
- An independent application creates an empty workspace, writes a file, goes
  idle and resumes from another client without managing sessions.
- Final acceptance includes a separate Poketto change after the provider ships.
  Its normal repository command path delegates session acquisition, renewal and
  reopening to Sandcrab. Consumer acceptance covers template scope, fresh child
  shells, journaled changes, host-call authorization and interrupted commands.
  Poketto keeps repository authorization, publication and write acknowledgement.

Remaining design questions include OpenSandbox adapter exposure, the default idle
window, maximum lifetime and retention, queue bounds, and how
[hard quotas](2026-11-18-hard-workspace-quotas.md) apply to workspaces.

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
after failed cleanup, host calls, shared-key reopening, distinct keys, conflicting
profiles and bases, and replay after a lost reply. Python and TypeScript SDKs exercise the same
cases. The density benchmark confirms that an idle workspace keeps no resident
processes and measures reopen latency against a plain session open. Poketto's
adoption runs through the consumer-triggered downstream release check after the
provider implementation. The consumer PR identifies the lifecycle code it deletes
and verifies the normal template-backed execution path.
