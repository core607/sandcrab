# Custom installation

Build with the [release target](../../../README.md#build-and-test). In `build/bin`,
`sandcrab` and `bwrap` are static executables; install both with mode 0755 in
the same root-owned directory with protected ancestors. Keep `bwrap-notices.txt`
and `bwrap-source.tar.xz` alongside them with mode 0644. The
[helper build](../../sandcrab-launch/bwrap/README.md) owns its version, source and
reproduction instructions.

Startup and every launch verify the helper beside the resolved executable,
including its protected path and pinned SHA-256. A missing, modified or mismatched
helper refuses execution. The host needs writable delegated cgroup v2,
unprivileged user namespaces, Linux 5.11+ and `mount`/`umount`.
Startup tests overlay mounting and copy-up on `runtime_root` storage before
serving clients; use a supported local filesystem such as ext4 or XFS. Unsupported
mount syscalls, helpers or backing storage refuse startup. There is no copy fallback.
[Tool preparation](../../../scripts/prepare-tools.sh) supplies optional workload utilities; the helper
comes from the release. The seccomp filter is compiled into Sandcrab, which needs
no Node.js, npm or SRT runtime.

For a custom service, copy [config.example.toml](../config.example.toml) to a root-owned file with mode 0600
in a protected directory. Set the client's numeric UID/GID and a separate execution
account. Profiles choose readable paths, tools, finite resource limits and
[network policy](network.md#network-egress); calls can lower timeout and output limits but cannot select
accounts, mounts or isolation policy. Sessions need `/bin/bash` and its libraries
in the profile's read mounts. Read mounts cannot expose runtime storage.
Before starting, create the root-owned parent of `runtime_root` with mode 0755
(`/var/lib/sandcrab-demo` for the example).

Workloads have private mount, user, PID, IPC, UTS, cgroup and network namespaces.
Their hostname is `sandcrab`, the sandbox sees its own cgroup root, and sibling
sessions cannot look up each other's SysV shared memory. The bundled bwrap disables
nested user namespaces. A profile with a proxy retains the disconnected network
created for that workload. Fixed file helpers use host UID mappings to publish files
with the owner's identity.

The x86-64 and aarch64 workload filters deny new Unix and VSOCK sockets, io_uring, BPF,
keyrings, perf events, userfaultfd, kernel and module loading, mount operations,
setns, namespace flags in clone/unshare, ptrace and nondefault personality changes.
Unix socketpairs, ordinary processes and threads, and personality queries remain
available. `clone3` returns `ENOSYS` so runtimes can use `clone`.

Workload processes use the profile's execution UID and primary GID with empty
supplementary groups and capability sets. The launcher sets `no_new_privs` before
dropping identity. The guest cannot open its cgroup controls for writing or raise
a process hard resource limit.

Each session has a child cgroup under the configured delegation. Its
aggregate memory, CPU and task limits apply to every process in the session.
Memory caps round down to whole kernel pages; swap is disabled. File freezing
covers that child cgroup. Closing and restart recovery confirm process containment
before releasing the workspace or attached volume.

Set `service.cgroup_root` to a root-owned cgroup whose effective ancestors bound
memory, CPU and tasks and disable swap. Delegate `cpu`, `memory` and `pids`.
The daemon creates separate `daemon` and `workloads` subtrees; its own limits are
`daemon_memory_bytes` and `daemon_tasks_max`. It moves itself before enabling
controllers, so the delegation must contain no unrelated processes.
For systemd, use `Delegate=yes`, `TasksMax=infinity` and `OOMPolicy=continue` on
the service, with aggregate limits on its enclosing slice. Set `cgroup_root` to
the service's full cgroup path; a per-service memory cap also caps its sandboxes.
An already delegated container or root host can run `sandcrab serve --config FILE`
directly. No per-sandbox service manager invocation is required.
The daemon creates launchers directly in their configured leaves with
`clone3(CLONE_INTO_CGROUP)`. It also requires `close_range` and `cgroup.kill`;
unsupported or filtered operations fail without an uncontained fallback.
Child setup or executable failure exits 127 without running the workload.
Startup locks the runtime and contains old owned leaves before publishing a new
epoch. The protected ownership marker binds the runtime to its delegation;
pre-delegation runtime/storage directories require a fresh location.
`sandcrab check --config FILE` checks configuration, accounts and tools; it does
not prove that delegation or a sandbox works.

Finite runs use a fresh bounded tmpfs at `/workspace`; sessions use ordinary
directories beneath `runtime_root`, or an attached volume. Choose a disk-backed
runtime location to keep session data off tmpfs. Every run uses the profile's
account, a private bounded `/tmp`, isolated network and PID namespaces, and seccomp.
It shares the host kernel; this is not a microVM boundary. Workspace data is
disposable unless supplied by a durable volume. Read mounts are the operator's responsibility.
