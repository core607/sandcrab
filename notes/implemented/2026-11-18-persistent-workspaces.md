# Persistent workspaces

Date: 2026-11-18

## Decision

A [workspace](../../crates/sandcrab/docs/workspaces.md) separates the lifetime of files from that of a shell. Keeping a process tree resident per idle user consumes memory on the reference host. Implementing session acquisition, renewal and crash recovery separately in each SDK would leave clients responsible for daemon-owned state.

Sandcrab persists an installation-wide key, its generation, profile and optional immutable template. The generation survives a healthy restart and service-token rotation. Deleting, forgetting and then recreating a key gives it a new generation. Applications authorize access to the key. An empty workspace owns a bounded volume. A template-backed one pins its base and keeps a writable layer. Applications can enforce a retention period by deleting the specific generation. The [storage decision](2026-11-18-hard-workspace-quotas.md) owns write-time enforcement.

The daemon orders commands in a bounded queue and releases the idle shell. It can also start a fresh child for each command while retaining the same files. Each submission carries an operation ID, server epoch, generation and submission window. Replaying a retained request returns its receipt. After an uncertain reply the caller reconciles its own effects before starting another operation. A containment failure holds the capacity and storage reservation.

Callers retain domain authority and decide when a change is acknowledged. Poketto takes a consistent checkpoint of the editable layer before acknowledging a repository command. It retains its Git and publication checks, its application journal and its imported-volume lease while delegating the normal template-backed command lifecycle to Sandcrab.

## Verification

[Native conformance](../../crates/sandcrab/sandcrab_conformance/workspace.py) exercises ordering, idle cgroup release, restart, generation fencing, receipt ownership and template checkpointing. The [independent client acceptance](https://github.com/core607/sandcrab/pull/49) covers reopening the same key from another language and appending once. The [Poketto integration](https://github.com/core607/poketto/pull/423) passed the [protected release check](https://github.com/core607/sandcrab/actions/runs/44420671364) using the published v0.4.0 archive.
