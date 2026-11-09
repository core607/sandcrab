# Optional Toolbox and Isolation Backends

Date: 2026-11-10

## Problem

An application exposing many tools must teach a model their discovery, invocation
and changing availability. A large static tool schema consumes context even when
most tools are irrelevant. Applications using models with unreliable structured
tool calling also need an explicit invocation format without moving application
state, credentials or authorization into the sandbox service.

## Proposal

This is an unimplemented design. The namespace service, current CLI and
[opaque host-call contract](../../crates/sandcrab/host-calls.md) remain the supported
interfaces. The [provider decision](../implemented/2026-11-02-sandcrab-lightweight-service.md)
continues to govern the small-host default and consumer ownership.

### Optional toolbox

Offer an optional toolbox package whose in-sandbox entry point is `sb`. An
application opts a workspace into that package; the base daemon does not acquire
a runtime interpreter, extra resident service or mandatory tool catalog. A small
dice example demonstrates discovery without making game semantics part of the
daemon. The toolbox is the default entry point within opted-in workspaces.

Users extend the package with function files beneath a tools directory. Directory
components form command namespaces and function names form subcommands. Function
signatures and docstrings supply bounded help, with `sb --help` showing namespaces
and deeper help revealing individual commands. A model can start with one command
execution tool and discover the rest progressively. Help generation must not
import or execute untrusted tool code on the host; tool execution remains inside
the sandbox. Package contents and manifests have immutable identities.

The first supported function language, parameter-to-argument mapping and package
layout remain design questions to settle before implementation. Multiple languages
and plugin frameworks are not prerequisites for the first useful package.

### Caller-owned state and visibility

A per-directory manifest declares `when` conditions over caller-owned state.
The caller evaluates a bounded, declarative condition language outside the sandbox,
validates manifests and selects the tool files for a new workspace. Unknown state,
invalid conditions and failed validation refuse preparation. Conditions cannot
execute arbitrary host expressions. Only selected files and corresponding help
metadata enter that workspace; hidden tools are absent rather than undocumented.

The visibility decision binds a state version, package digest, caller identity
and execution. State reads and writes use host calls. The caller validates request
and reply schemas, rechecks current grants and state preconditions, and owns
transactions and durable deduplication. Schemas describe shapes; they do not grant
permission. Guest-supplied identities, tool names and manifest conditions cannot
authorize an effect. Calls made directly through `sandcrab call` receive the same
checks as calls made through `sb`.

Visibility describes a newly prepared workspace. Once disclosed, tool bytes may
have been copied into its upper layer or retained by a process; changing a mount
does not erase that disclosure. A state change that requires stopping local work
closes affected sessions and descendants before admitting replacement work.
Recreate the workspace from an authorized base instead of reusing an upper or
checkpoint containing revoked tool material. Caller-side host operations recheck
authorization even while cancellation is in progress. The integration must state
whether a change applies on the next invocation or requires immediate cancellation;
it must never claim that hiding filenames alone supplies revocation.

### Invocation and effects

Use native tool calling when available. The optional text fallback belongs to
the caller: accept exactly one explicitly framed command block under a documented
grammar, validate it and route it through the same `sb` invocation path. A proposed
minimal grammar is one `sb` fence containing a JSON argument array for the fixed
`sb` executable. Ordinary prose, quoted examples, extra command blocks and malformed output are not execution
requests. Streaming output is buffered until the complete frame is validated.

The caller supplies the invocation identity and binds it to the conversation turn,
current grants, timeout, output limits and budget before execution. Repeated model
output or a lost reply cannot silently repeat an outside effect. Native and text
paths share cancellation, outcome reconciliation and caller-owned idempotency.
An untrusted tool's output cannot enqueue another command merely by containing a
fenced block. The exact framing and retry contract must be reviewed before enabling
the fallback for a model.

Secrets stay outside read mounts, tool packages, environment variables and guest
checkpoints. Prefer existing host calls to a caller-owned request adapter for
credentialed services; add a separate injecting proxy only when an integration
requires HTTP compatibility. That adapter restricts destination, method, credential
scope, redirects, request/reply size and time, and returns only authorized response
data. It rechecks caller grants and keeps credentials out of guest replies and
diagnostics. The daemon's ordinary egress proxy does not acquire application keys.

### Independent consumer

The first proposed integration is a SillyTavern server plugin using the existing
Unix socket API and host calls. Example character cards exercise conditional
discovery and authorized state changes. The plugin owns users, conversations,
state schemas, tool policy and credentialed handlers; these remain an optional
consumer package rather than daemon configuration concepts.

Unix peer credentials authenticate the plugin's server process, not each chat
user. The plugin maps each request to its authenticated user and conversation,
authorizes it and binds its sandbox and host-call observer accordingly. A second
small caller example should use the same toolbox without SillyTavern state or
character-card semantics, demonstrating the package boundary.

### Optional future isolation backend

The current namespace backend remains the default. A KVM microVM backend is a
future optional extension, not an implemented capability or a new installation
requirement. It would extend the present same-kernel scope for explicitly opted-in
hosts while leaving the no-KVM reference workload and default unchanged.

Wait for a concrete second-backend workload and prototype before designing a
shared interface. First identify genuine differences in availability, trust,
resource accounting, file transfer, networking, checkpoint semantics, cancellation
and recovery. Do not force VM process snapshots into the existing filesystem-only
checkpoint contract or advertise namespace and VM isolation as equivalent.

Explicitly requesting an unavailable backend must fail rather than fall back to
a weaker boundary. The default install must retain three commands, under five
minutes on its supported reference hosts, no KVM or container runtime requirement,
and no additional resident controller. Optional components must be separately
selected and measured; an abstract backend layer alone supplies no performance gain.

## Alternatives

- Put every tool and state condition into the daemon. This makes other consumers
  inherit application policy and expands the privileged service's trusted surface.
- Send the full catalog in the model's initial schema. This avoids a CLI discovery
  step but retains the context and visibility-management cost motivating this design.
- Hide tool names only in help. This leaves executable files available and fails
  the proposed workspace visibility contract.
- Treat filesystem hiding as authorization. Copies and surviving processes can
  retain code, while host calls remain reachable independently of the wrapper.
- Interpret arbitrary fenced model output. Examples, streaming fragments and
  retries would become unintended executions without a caller-owned frame contract.
- Require a microVM or implement a general backend framework first. This changes
  the reference host or adds abstraction before a second backend establishes its needs.

## Consequences

The caller owns more policy, state and recovery work, while the daemon remains a
generic execution and transport service. Progressive discovery adds help calls;
repreparing workspaces after revocation has a cost. Tool confidentiality cannot be
recovered after disclosure, and pure local computations remain possible within
the authority of an already admitted sandbox until it is terminated.

The proposal authorizes no implementation. The package layout, first language,
condition grammar, frame grammar and revocation timing need explicit acceptance
before building the toolbox. A microVM prototype and backend interface require
their own workload evidence and implementation decision.

## Verification

Before accepting an implementation, exercise the real plugin and an independent
caller through the public API. Verify hierarchical help and function discovery,
absence of hidden files and metadata in fresh workspaces, state validation,
cross-user denial, revoked direct host calls, retained tool copies, session teardown,
duplicate effects and uncertain outcomes. Use malformed, quoted, multiple and
streamed frames to test the text fallback without granting authority to model output.

Check that credentialed handlers refuse unauthorized destinations and redirects
and keep keys out of sandbox-visible files, replies and logs. Compare discovery
cost, task success, help calls, time and token usage with a fixed task corpus;
scripted boundary checks and optional paid-model evals retain separate evidence.
Use affected tests and targeted measurements, with aggregate summaries in Git and
raw attempts in CI artifacts under the existing measurement policy.

Re-run the documented installation only when packaging or first-use behavior
changes. A future backend must demonstrate its stated trust and resource boundary,
failure on unsupported hosts, cleanup and recovery, and unchanged default readiness.
