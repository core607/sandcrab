# Sandcrab threat model

Sandcrab runs trusted or semi-trusted programs on a shared Linux host. It limits
which files, processes, network destinations and resources a program can reach.
The host operator, kernel, root daemon, bundled bubblewrap and installed profiles
are trusted. A program, its input, its dependencies and the contents of a template
are guest code or data. A compromised kernel or host administrator can observe or
change any sandbox. Hostile multi-tenant isolation, hardware side channels and
protection from kernel vulnerabilities are outside this boundary.

## Who controls a sandbox

On the Unix socket the daemon checks the kernel-reported peer UID against the
configured client UID. Filesystem permissions also control access to the socket.
The optional TCP listener accepts literal loopback connections and checks a
private bearer token before admitting native requests. The operator must keep
that endpoint exclusive. Plain HTTP supplies no server identity or remote TLS.
The installed OpenSandbox adapter uses the service key for lifecycle operations
and issues a separate scoped credential for each sandbox's execution endpoint.
A party with the service credential can control sandboxes across that installation.
Applications sharing it must enforce their own user, tenant and object permissions.
See [client authentication](crates/sandcrab/README.md#loopback-tcp) and the [SDK contract](crates/sandcrab/opensandbox.md).

## What a program can reach

The operator chooses the execution account, read mounts, workspace, tools, network
mode and optional host calls. A read-only mount still discloses everything the
execution account can read there. Templates share an immutable base and place
changes in an upper layer. A content digest identifies bytes. Trust in the author
or executables inside those bytes is a separate decision.

Workloads run without capabilities or supplementary groups, with `no_new_privs`,
private namespaces and a syscall filter. The namespace boundary separates
same-UID guests' process views, SysV IPC, hostnames and cgroup paths. The filter
reduces the kernel entry points available to guests. Approved calls still reach
the shared kernel. Trusted file helpers need host UID mappings, and the fixed
overlay exporter can clone its own mount through an authenticated daemon channel.
The service treats those helpers and its protected binary directory as privileged
host components. See the [workload and installation boundaries](crates/sandcrab/README.md#custom-installation).

The default network has no path to external hosts. An enabled profile allows
exact destination names through a daemon-owned CONNECT or SOCKS proxy. The
daemon resolves each request and connects to a checked address. The allowlist
controls where a tunnel starts. An allowed service can receive guest data or
relay it elsewhere. TLS identity and payload validation belong to the client
and remote service. See [network egress](crates/sandcrab/README.md#network-egress).

With host calls enabled, the guest can send opaque bytes to its caller. The
caller owns authorization, credential handling, durable deduplication and effects
outside the sandbox. A disconnected stream or missing record leaves an external
effect uncertain. See the [host-call contract](crates/sandcrab/host-calls.md).

## Exhaustion and recovery

Delegated cgroups bound workload CPU, memory and tasks, with swap disabled.
Session commands and their descendants share their session's limit. The daemon
also bounds admission, pending commands, output and transfer resources. A queue
timeout records that the command never executed. A running workload may hit its
limit, consume its allowance continuously or lose progress on cancellation.
Closing and restart recovery must confirm containment before releasing ownership.
Uncertain cleanup can leave capacity reserved. See [command admission](crates/sandcrab/README.md#command-queue).

XFS project quotas can enforce volume byte and inode limits during writes.
Ordinary-directory and overlay storage use periodic accounting. Writes can
overshoot between observations, and workloads on the same filesystem can put
pressure on other services. Operators own filesystem capacity and backups.
Memory ceilings and passing load tests do not guarantee latency, disk availability
or service availability under saturation. See [storage accounting](crates/sandcrab/README.md#storage-accounting).
