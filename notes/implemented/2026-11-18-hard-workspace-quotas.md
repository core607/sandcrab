# Hard workspace quotas

Date: 2026-11-18

[Periodic storage accounting](../../crates/sandcrab/docs/volumes.md#storage-accounting)
admits a bounded writer between observations. [Issue 11](https://github.com/core607/sandcrab/issues/11)
records 32 MiB flushed under an 8 MiB limit. Shorter scans still leave an interval
in which a single writer can consume free space.

Profiles that need a write-time bound use projects from a single verified XFS
filesystem. The same allocation and recovery code serves attached volumes,
keyed workspaces and private session storage. A single preallocated loop image
lets a host with one disk isolate the pool. An image per workspace would require
a mount and recovery record for every active workspace. Memory-backed storage
would charge retained files to RAM and lose them on shutdown.

Private session projects have no public volume identity. Startup contains old
processes before it reclaims these projects. Keyed projects survive that
recovery because their owner outlives a process. Missing enforcement prevents
startup for a profile that selected it. Ordinary profiles keep the existing
low-setup directory option and its documented accounting interval.

The [operator reference](../../crates/sandcrab/docs/volumes.md#write-time-workspace-limits)
owns setup and limits. The [native conformance suite](../../crates/sandcrab/sandcrab_conformance/hard_quota.py)
compares backing costs and checks kernel refusals and recovery.
