# Developer hosts

The Sandcrab service runs on Linux. Installer acceptance covers Ubuntu 22.04,
Ubuntu 24.04 and Debian 12 on `x86_64`, and Ubuntu 24.04 on `aarch64`.
The [quickstart](../../../README.md#quickstart) installs the release on those
hosts. The macOS and Windows setups below describe untested development options.

## Host requirements

The environment must provide:

- Linux 5.11 or later with unprivileged user namespaces and `mount`/`umount`;
- writable delegated cgroup v2;
- systemd, for the release installer's service and slice;
- a local filesystem such as ext4 or XFS under `runtime_root`, because startup
  refuses storage that fails its overlay mount and copy-up test
  ([installation](installation.md)).

After installation, `sudo sandcrab doctor` checks kernel namespaces, the verified
helper, the delegated cgroup, storage and service discovery, and prints a fix for
each failed check ([installation guide](../install/README.md)).

## Linux virtual machine

Run Ubuntu 22.04, Ubuntu 24.04 or Debian 12 in a virtual machine and follow the
quickstart inside it. On macOS, tools such as Lima, Multipass or UTM provide such
a machine; on Windows, Hyper-V or WSL2 do. A WSL2 distribution must run systemd
and expose cgroup v2 before the installer can succeed; `sandcrab doctor` reports
which requirement is missing.

Applications on the developer machine reach the service through the virtual
machine. The loopback listener accepts only literal loopback connections
([loopback TCP](http.md#loopback-tcp)), so run the application inside the virtual
machine or forward a local port to it over a channel you trust.

## Standalone container

The [standalone container](../install/README.md#standalone-container) needs a Linux
Docker engine with cgroup v2 and runs privileged. Docker Desktop provides its Linux
engine inside a virtual machine. The container keeps its loopback listener inside
its own network namespace, so an application must join that namespace or reach
the service's Unix socket through a shared volume.

Use the container only on a trusted machine: Docker grants the service container
administrative capabilities to manage mounts and cgroups.
