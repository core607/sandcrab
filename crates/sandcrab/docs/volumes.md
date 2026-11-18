# Volumes and storage

## Durable volumes

Enable optional `[storage]` in the example configuration. Ordinary directories
work without a dedicated filesystem or quota tools. The root and its ancestors
must be root-owned, non-writable by other accounts and searchable by execution
accounts. The daemon creates data at `root/data` and private metadata at `root/state`.
For a new store, prepare `root/data` as an empty protected directory.
It never formats a disk, remounts a filesystem or adopts a nonempty unowned store.
Profiles cannot expose this storage through their read mounts.

For enforced quotas, mount the root of a dedicated XFS filesystem at `root/data` with reflinks,
`prjquota` or `pquota`, `nosuid` and `nodev`, and a filesystem size no larger than
`pool_bytes`. Install `xfsprogs` under `/usr/sbin` and keep `root/state` on another
filesystem. Project IDs span the whole filesystem. A subdirectory bind supports
periodic accounting for a new store. Restore the dedicated pool to recover existing
project volumes. Set `require_quota = true` to require verified enforcement at startup.
The default is false. `/v1/info` reports the actual `storage.quotaEnforced` mode.
Existing plain volumes retain periodic accounting; enabling host quotas does not
silently assign projects to their data.

```sh
sandcrab volume create --socket /var/lib/sandcrab/runtime/control.sock --profile default --bytes 8388608 --inodes 256
sandcrab session open --socket /var/lib/sandcrab/runtime/control.sock --profile default --volume VOLUME_ID
# Execute commands, then close the session before cloning or deleting its volume.
sandcrab volume create --socket /var/lib/sandcrab/runtime/control.sock --profile default --clone-from VOLUME_ID
sandcrab volume list --socket /var/lib/sandcrab/runtime/control.sock
sandcrab volume get --socket /var/lib/sandcrab/runtime/control.sock VOLUME_ID
sandcrab volume delete --socket /var/lib/sandcrab/runtime/control.sock VOLUME_ID
sandcrab volume forget --socket /var/lib/sandcrab/runtime/control.sock VOLUME_ID
```

A volume is an ordinary directory mounted at `/workspace`. Session closure,
expiry and daemon restart retain its files; shell state and `/tmp` remain
ephemeral. Application writes follow normal filesystem synchronization semantics;
closing a session is not an atomic snapshot or a power-loss commit for those writes.
The selected profile must use the volume's execution UID/GID. One session owns a
volume exclusively until confirmed cleanup; a failed cleanup retains that ownership.
Cloning requires an unattached source and holds it for the operation. It uses
reflinks where supported and ordinary copying otherwise, preserving hard links
and opaque symlinks; subsequent writes are independent. Clone work uses the
selected profile's bounded cgroup and timeout.

Limits count allocated blocks and inodes, including managed metadata, rather than
sparse logical lengths. Requests may only lower configured maxima; byte limits
are multiples of 1024. Enforced quota failure can report `ENOSPC` or `EDQUOT`
inside a session. `max_volumes` bounds live volumes;
storage `max_records` separately bounds durable records. `STORAGE_CAPACITY`
allows one mutation at a time. A full quota data pool still permits recording deletion
on its separate control filesystem. Plain storage can exhaust data and metadata
together; uncertain publication fences mutations rather than inventing a successful record.

| Request | Result |
|---|---|
| `POST /v1/volumes` | Create with a UUID `id`, current `serverId`, `profile`, optional `cloneFrom`, `byteLimit` and `inodeLimit`; returns 202 |
| `GET /v1/volumes/ID` | Read state, quotas, plan digest and ownership |
| `GET /v1/volumes?after=UUID` | Up to 100 records in UUID order; continue with `nextAfter` |
| `POST /v1/volumes/ID/delete` with `{}` | Persist deletion intent, then remove an unattached volume |
| `POST /v1/volumes/ID/forget` with `{}` | Forget a failed or deleted record after its data is absent |

States are `creating`, `ready`, `deleting`, `deleted`, `failed` and `closing`.
Only `ready` can attach. Creation IDs bind a normalized plan digest across daemon
restarts; `serverId` is excluded. An existing ID with the same plan replays its
current state, including failure or deletion; different plans conflict. An unknown
ID needs the current server epoch. The CLI prints its recovery ID before submission;
`--id UUID` permits an explicit replay. Never substitute a new ID after a lost response.
Forgetting ends replay protection; never reuse that client ID.

Startup contains owned cgroups before recovering unfinished creation or deletion.
Published volumes remain intact. Uncertain metadata or volume cleanup fences
mutations (`STORAGE_UNCERTAIN`, `storage.available=false`) until restart and
reconciliation; it never exposes uncommitted data as ready. Unexpected data,
mounts or a changed cleanup namespace require operator reconciliation and are
preserved. Keep the store and its matching runtime configuration together.

## Write-time workspace limits

Set `hard_workspace_quota = true` on each profile that requires the kernel to enforce
`temporary_bytes` and `temporary_inodes` during writes. A raw session gets a private
project until closure. A keyed workspace keeps its project across idle periods and
daemon restarts. Template-based sessions and workspaces charge their writable
overlay to the project. Read-only base layers are shared. An explicitly attached
volume must fit both profile limits. Plan one volume slot per active private
session and one per retained workspace. Sandcrab refuses startup when a selected
profile lacks a verified pool. `sandcrab info` reports the setting as
`profiles.<name>.hardWorkspaceQuota`.

A single-disk Linux host can use one preallocated file for the pool. The following
root shell commands create a **new** 1 GiB store. They require `xfsprogs`, loop
mount support and 1 GiB of free space for the image. Use a new path; a successful
exclusive directory creation below protects existing data.

```sh
set -eu
pool=/var/lib/sandcrab-xfs-pool
mkdir -m 0755 "$pool"
install -d -m 0755 "$pool/storage" "$pool/storage/data"
(umask 077; fallocate -l 1G "$pool/data.xfs")
mkfs.xfs -m reflink=1 "$pool/data.xfs"
mount -o loop,prjquota,nosuid,nodev "$pool/data.xfs" "$pool/storage/data"
```

Use `root = "/var/lib/sandcrab-xfs-pool/storage"` and `pool_bytes = 1073741824` in
`[storage]`. Keep the existing store and its data together when upgrading. For
this new store, persist the mount before enabling the profile, for example with
this entry in `/etc/fstab`:

```fstab
/var/lib/sandcrab-xfs-pool/data.xfs /var/lib/sandcrab-xfs-pool/storage/data xfs loop,prjquota,nosuid,nodev 0 0
```

Order the service after the mount with `RequiresMountsFor=/var/lib/sandcrab-xfs-pool/storage/data`
in its systemd unit's `[Unit]` section. Run `sandcrab check --config /etc/sandcrab/config.toml`
with the actual configuration path. In a container, the operator can mount the
dedicated filesystem on the host and expose its root at the configured data path.
The [hard-quotas conformance suite](verification.md) records the initial allocated
bytes and opening time for each backing, and write-time byte and inode refusals.
The [512 MiB test-pool results](../../../evidence/sandcrab-hard-workspace-quotas-2026-11-18/summary.json)
include each layout's opening cost and the usable file space under an 8 MiB project limit.

## Storage accounting

Without enforced quotas, `Volume.usage`, `Session.storageUsage` and
`storage.poolUsage` in `/v1/info` report periodic allocated-byte/inode observations.
An attached session also exposes `storagePoolUsage`; it is null for an ephemeral
directory. The pool sums owned volume observations and its directory overhead,
not unrelated files on the host filesystem. Its timestamp is the oldest constituent
observation, so it is not an atomic snapshot. These fields are null where accounting
does not apply or the session has no live workspace.

One background worker refreshes active directories and new volumes at most once per second
per directory, then enforces the measured limits. `exceeded` refuses new commands,
child shells, uploads and other growth with `STORAGE_LIMIT`, cancels active growth
helpers and freezes existing workspace processes. `pending` or `unavailable` also
refuses growth, with `STORAGE_USAGE_UNAVAILABLE`. Reads and deletion remain available;
after a complete below-limit observation, processes and admission resume. Command
timeouts and session expiry keep running while frozen.

Each scan limits depth to 64, directory entries to 1,000,001, retained hard-link
identities to 16,384 and time between syscalls to five seconds. Incomplete scans
never report zero or successful usage. Kernel I/O can exceed that deadline;
many active directories lengthen the refresh cycle. Concurrent writes, reflinks,
in-flight copying and open unlinked files prevent a hard physical disk bound.
Keep filesystem headroom or enable enforced quotas when a hard bound is required.
End background writers before deleting their files: unlinking an open file does
not reclaim its blocks. Closing an ephemeral session removes its data; a volume
retains data and can be reattached for recovery.
