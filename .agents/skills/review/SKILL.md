---
name: review
description: Use when reviewing a pull request or a specified repository change.
---

# Reviewing a Sandcrab Change

For a review-only request, report findings without fixing files. An explicit request for fixes authorizes correcting reviewed defects within that scope.

Verify the live base and exact head, inspect committed and uncommitted changes, and read the owning implementation and documentation on both sides of changed interfaces. Follow [AGENTS.md](../../../AGENTS.md), the [threat model](../../../THREAT-MODEL.md) and any decision the change implements or supersedes.

## Trace the affected contract

- Authority: operator profiles and authenticated peers bound access; guest fields and caller labels do not elevate privileges. Domain authorization, credentials and outside effects remain caller-owned.
- Isolation: trace the actual workload identity, mounts, namespaces, seccomp and cgroups, including helper paths. Missing capabilities fail closed without unrestricted subprocess fallback.
- Lifecycle: admission remains held through confirmed containment; follow cancellation, expiry, launcher reaping, background descendants and uncertain cleanup before resource reuse.
- Storage: immutable identities, writable layers, active pins, deletion markers and capture lifetimes agree with their owners. Recovery must not destroy state whose ownership is uncertain.
- Protocols: trace producers and consumers, retry and duplicate observation, operation identity, lost replies and restart. Acknowledgement of transport is distinct from a caller's committed effect.
- Bounds: include encoded bytes, pending work, retries, output, time and retained results; observe empty, oversized and multibyte cases.
- Evidence: exercise the real changed entry path and independently observe effects. Mocked or scripted success does not establish native isolation, model usability or deployed performance.
- Documentation: correct current contracts and related decisions in the same change; preserve proposed and historical status and follow [prose-standard](../prose-standard/SKILL.md).

Report a concrete defect with its location, trigger, impact and evidence. Prioritize correctness, authority and lifecycle over style; separate blockers from suggestions. Do not invent findings to fill a checklist. If none remain, say so and name the relevant checks or evidence still unavailable.
