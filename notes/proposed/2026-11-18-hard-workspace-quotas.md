# Hard Workspace Quotas

Date: 2026-11-18

## Problem

Ordinary-directory and overlay storage use periodic accounting. Writes can overshoot
between observations, and workloads on the same filesystem can pressure other
services ([storage accounting](../../crates/sandcrab/README.md#storage-accounting)).
[Issue 11](https://github.com/core607/sandcrab/issues/11) records a workspace with an
8 MiB limit that accepted a single command writing and flushing 32 MiB before the
next scan. XFS project quotas enforce byte and inode limits during writes only for
volumes on an XFS filesystem that Sandcrab owns entirely.

Hosts that serve many independent agent users need disk bounds that hold for short
bursts too. Requiring a dedicated XFS filesystem is a large step for the small
reference host.

## Proposal

This is an unimplemented design. The ordinary-directory path remains the default,
with its documented overshoot.

A profile may select a hard-quota backing for session workspaces, overlay upper
layers and [persistent workspaces](2026-11-18-persistent-workspaces.md). Candidate
mechanisms:

- a fixed-size filesystem image per workspace, mounted through a loop device;
- a size-limited tmpfs for ephemeral workspaces, charged to the sandbox's memory;
- XFS project quotas on a dedicated, Sandcrab-owned filesystem with enforced
  project accounting and non-colliding project IDs.

Acceptance criteria:

- Under hard backing, the issue 11 reproduction fails with a disk-full error at the
  limit.
- Exhaustion of the inode allowance also prevents new files. Validation measures
  bytes and inodes separately.
- The default path behaves as it does today.
- Fixed costs and setup latency of each backing are measured.

Remaining design questions: loop device availability in the standalone container;
recovering filesystem images after a crash; placing overlay upper layers on an
image; and memory accounting for tmpfs workspaces.

## Alternatives

- Shorten the scan interval. Overshoot shrinks but remains, because a burst within
  one interval still exceeds the limit.
- Rely on operator-managed filesystem quotas. Operators would rebuild per-workspace
  quota management outside Sandcrab.
- Require XFS for every installation. This conflicts with keeping ordinary hosts
  usable without reformatting.

## Consequences

Loop-backed images add privileged setup, cleanup states and per-workspace fixed
cost. Tmpfs workspaces compete with workload memory. Each backing has its own
capacity evidence and cannot stand in for another's.

## Verification

Native conformance runs the issue 11 reproduction under each backing, plus crash
recovery and cleanup. The density benchmark reports fixed costs under the existing
measurement policy.
