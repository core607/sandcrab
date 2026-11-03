# Installing Sandcrab

Follow [Get started](../README.md#get-started) with a release directory owned by
root and not writable by other users. Keep that directory installed: the service
unit uses its executable. The installer does not change shell search paths.

`sandcrab install --dry-run` prints directory modes, the account, configuration,
units and activation commands without changing the machine or generating a
credential. Run `sudo sandcrab install` to apply them. Installation preserves an
existing protected configuration and token and refuses to replace conflicting
units or accounts.

The service listens on a root-only Unix client interface and on `127.0.0.1:9011`
with a private token in `/etc/sandcrab/token`. The `default` profile runs as
`sandcrab-exec`, mounts the host's `/usr` and runtime libraries read-only and has
no network. The [default configuration](default.toml) and [slice](sandcrab.slice)
own the limits. Edit `/etc/sandcrab/config.toml` and restart `sandcrab.service`
to change profiles. Give authorized external clients a private copy of the token.

`sudo sandcrab doctor [--config FILE]` checks kernel namespaces, the verified
helper, the delegated cgroup, storage and service discovery. It runs bash and
Python as the default execution user; each failed check prints a fix and the
command exits nonzero. On native hosts that restrict user namespaces through
AppArmor, the installer loads a [profile](sandcrab.apparmor) for the Sandcrab
service. It leaves the host's global restriction in place.

## Standalone container

Use a Linux Docker engine with cgroup v2. Set `SANDCRAB_IMAGE` to the per-commit
image reported by the [installer workflow](../../../../.github/workflows/sandcrab-readiness.yml) after a main dispatch with `publish_image=true` (`ghcr.io/core607/poketto-sandcrab:sha-COMMIT`),
or build the same image from the local bundle:

```sh
docker build -t sandcrab:local -f executor-service/rust/sandcrab/install/Dockerfile build/executor-service/bin
SANDCRAB_IMAGE=sandcrab:local
```

On a host with `kernel.apparmor_restrict_unprivileged_userns=1`, load the
[service profile](sandcrab.apparmor) with
`sudo apparmor_parser -r executor-service/rust/sandcrab/install/sandcrab.apparmor`
and add `--security-opt apparmor=sandcrab-service` to the following invocation.

```sh
docker run -d --name sandcrab --privileged --cgroupns=private --network=none \
  --memory=512m --memory-swap=512m --cpus=2 --pids-limit=512 \
  --mount type=volume,source=sandcrab-data,target=/var/lib/sandcrab \
  --mount type=volume,source=sandcrab-config,target=/etc/sandcrab "$SANDCRAB_IMAGE"
docker exec sandcrab sandcrab doctor
docker exec sandcrab sandcrab run --socket /var/lib/sandcrab/runtime/control.sock --profile default -- id -u
```

The container starts `sandcrab serve --container` as PID 1 and creates a token at
first boot. Docker grants the **daemon container** administrative capabilities
to manage mounts and cgroups; run it only on a trusted host. The workloads use
the non-root profile. No host cgroup bind mount, Docker socket or systemd is
required. The isolated network keeps loopback HTTP inside the container.
The data volume supplies an overlay-capable backing filesystem; the image's
writable overlay layer is unsuitable for writable template layers. Startup tests
the selected filesystem and refuses unsupported storage. The two dedicated
volumes retain data and credentials across container replacement.
