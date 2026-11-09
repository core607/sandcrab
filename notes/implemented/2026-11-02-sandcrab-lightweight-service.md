# Lightweight, Ready-to-Use Sandcrab

Date: 2026-11-02

## Problem

An independent API does not make a sandbox easy to install. Operators still
need tools, identities, resource delegation and profiles. Tying extraction to
a consumer's migration schedule or a four-week waiting period measures neither
installation cost nor usefulness to another project. Preserving application-specific
operations would make that coupling permanent.

## Decision

Low fixed cost and first-use readiness take priority over concurrent-agent
density. The reference is a two-CPU Linux host with 4 or 8 GB of memory, without
KVM. Readiness, native conformance and published SDK acceptance establish the
independent service boundary; elapsed time and a consumer's cutover schedule do not.

Sandcrab owns independently released source, API, CLI, SDK integration, evaluations
and benchmarks. Consumers own application identities, authorization, transactions
and credentials. A general primitive needs a use outside the original consumer;
consumers adapt to the generic service. Poketto's
[native consumer decision](https://github.com/core607/poketto/blob/main/notes/implemented/2026-11-05-native-repository-consumer.md)
owns its release pin, Git consistency, copy journals and admission. Cross-boundary
changes require a release before adoption, rather than a second provider workspace
or compiled consumer traits.

### Runtime and authority

A static daemon and checksum-verified bundled bubblewrap reduce host preparation.
Native seccomp avoids a Node/npm/SRT provisioning dependency; interpreters used by
workloads remain consumer or operator choices. Systemd installation and a delegated
container are supported operating choices, not extra resident services required
by the core runtime. The [installation guide](../../crates/sandcrab/install/README.md)
owns host preparation and release materials.

Direct cgroup v2 delegation avoids a service-manager transaction per sandbox.
[Direct placement](../../crates/sandcrab-spawn/src/lib.rs) uses a small syscall/exec
boundary instead of post-spawn migration and its measured quiescent delay.
[Process ownership](../../crates/sandcrab-core/src/process.rs) lasts through launcher
reaping and descendant containment; an empty leaf alone is insufficient.
[Recovery](../../crates/sandcrab/src/delegation.rs) validates delegation ownership
before cleanup. Unknown ownership refuses startup and preserves data; uncertain
cleanup retains admission. Missing kernel support refuses execution rather than
selecting an unrestricted subprocess.

The [bootstrap filter](../../crates/sandcrab-launch/src/seccomp.rs) protects
bubblewrap and its reaper before sandbox setup. Sealed workload filters take effect
before guest execution: applying mount and namespace denials before setup would
prevent construction, while postponing all filtering would expose the reaper.
Explicit ABI guards preserve the pinned reference policy; trusted overlay-export
exceptions belong to a fixed helper, not arbitrary workloads. Helper compatibility
cannot weaken or defer installation of a filter.

Operator profiles bound identities, mounts, networking and resources. Unix peers
and loopback tokens authenticate callers; guest fields and caller labels cannot
grant stronger authority. The [threat model](../../THREAT-MODEL.md) owns shared-kernel
hardening, helper trust and egress. Namespaces and seccomp retain a shared kernel;
they do not provide a microVM trust boundary. Opaque
[host calls](../../crates/sandcrab/host-calls.md) keep authorization, durable
deduplication and outside effects with the caller.

Ordinary directories keep non-XFS hosts usable. Periodic accounting can overshoot
between scans; optional XFS project quotas enforce a different storage contract
and require ownership of the whole filesystem. These modes cannot substitute for
each other's capacity evidence. [Storage accounting](../../crates/sandcrab/README.md#storage-accounting)
owns the operating limits.

Templates share immutable file identities with private writable overlays. Including
execution identity in their digest avoids world-writable bases and per-session
ownership rewriting. Named contexts share their parent's mount rather than mount
the same upper concurrently. Unsupported overlay capabilities fail at startup;
there is no implicit copy fallback for template operations.

### Reuse and measurement

[DSec](https://arxiv.org/html/2609.22978v1) motivates reducing repeated environment
preparation; its cluster results are not estimates for this service. Filesystem
capture, immutable publication and ordered recipes reuse template and diff
primitives. A checkpoint captures files, not process state, shell variables or cwd.
Layer order, execution identity and deletion semantics belong to immutable identity;
active and uncertain users retain pins. Expected identities and receipts reconcile
lost publication replies without replaying effects.

The [matched preparation comparison](../../evidence/sandcrab-preparation-reuse-2026-11-09/summary.json)
supports sharing immutable dependencies and avoiding repeated imports. It also
retains writable copy-up costs; reader savings are not a general improvement for
write-heavy commands. The [service-class comparison](../../evidence/sandcrab-service-classes-2026-11-09/summary.json)
supports optional operator CPU weights, with equal weights remaining the default.
Separate startup or execution limits and topology controls did not justify added
mechanisms. The [benchmark reference](../../benchmarks/density/README.md) owns these
workloads, commands and measurement boundaries.

The L2, L7 and L9 full-density checkpoints retain missed targets alongside successes.
Other changes use affected checks and targeted comparisons. Results bind revision,
workload, resource budget and successful work; refusals, an empty queue or zero OOM
alone do not establish capacity. Aggregate summaries belong in Git, while raw
samples and failed attempts remain CI artifacts. Missed targets become tracked
limitations without repeated tuning in the same change. The
[checkpoint protocol](../../benchmarks/density/README.md#native-measurement) owns
the comparison procedure; historical receipts retain their original revisions.

The [conditional investigation](../../evidence/sandcrab-conditional-performance-2026-11-09/summary.json)
keeps idle shell eviction deferred because historical checkpoint estimates do not
reach the 40% idle-memory trigger. Reconsider only with that measured cost,
background-process protection, disk-backed workspaces, cwd/export restoration and
explicit state-loss semantics. Freezing alone does not reclaim memory; the
zero-swap reference excludes swap-assisted pauses and VM-specific reclamation.

The same investigation defers EROFS and remote lazy loading. The reusable-dependency
fixture does not establish large-environment extraction, storage or distribution
as the dominant cost. Reconsider local EROFS first when that cost appears, including
tools, kernel support, I/O and startup tails; remote loading additionally needs
evidence of a distribution bottleneck.

Scripted integrity probes separate agent execution from reference answers, grading,
control channels and protected entrypoints. Grading reads output and state
independently, including interference and bounded resource failures. The
[evaluation reference](../../evals/README.md) distinguishes those checks from paid
model-directed tasks. Paid evidence retains estimates, bounds, actual usage,
unavailable prices and every attempt; scripted success does not establish model
usability. Application request replay and JVM configuration remain consumer work.

## Alternatives

- Wait for consumer migration and four stable weeks. This measures scheduling
  rather than independent readiness.
- Preserve application operations or compile consumer integrations into Rust
  traits. This couples authority and transactions to the distribution and makes
  integrators rebuild the daemon.
- Implement E2B's API. Its routing and Connect RPC add DNS, certificate and protocol
  work beyond the local service's bounded SDK compatibility requirement.
- Add bubblewrap to the full OpenSandbox stack. Its resident services and outer
  resource boundary impose costs avoided by the bounded SDK-compatible adapter.
- Require microVMs, gVisor, XFS, systemd or a container runtime everywhere. These
  change the target host or trust boundary; optional quotas and delegation keep
  installation choices explicit.
- Optimize idle shells or introduce storage infrastructure before measuring the
  cost. The conditional triggers avoid mechanisms without demonstrated benefit
  to the small-host workload.

## Consequences

Consumers own more adaptation and consistency work. The provider owns helper
builds, licensing, native conformance and independent releases. Overlay and
delegation remain kernel requirements; periodic accounting is weaker than quotas,
and same-host hardening retains shared-kernel risk. Release notices, corresponding
helper source and the threat model accompany the distribution. Provider metadata
follows the pre-1.0 rebuild rule.

## Verification

[Readiness acceptance](../../.github/workflows/sandcrab-readiness.yml) replays the
three-command installation on Ubuntu 22.04, Ubuntu 24.04 and Debian 12.
[Native and published SDK conformance](../../.github/workflows/evals.yml), Rust
filter/process tests and [evaluation integrity](../../evidence/sandcrab-evaluation-integrity-2026-11-09/summary.json)
exercise their distinct boundaries. The
[downstream workflow](../../.github/workflows/downstream-release.yml) tests a
consumer's exact reviewed commit against the released archive. The referenced
measurement summaries establish only their recorded workloads and revisions.
