# Agent-ready installation defaults

Date: 2026-11-18

## Decision

The [installer](../../crates/sandcrab/src/install_defaults.rs) chooses the initial capacity from the effective memory and free space on the storage filesystem. A fixed count exhausted small machines or left larger ones idle. The [installation reference](../../crates/sandcrab/install/README.md) owns the formulas and ceilings. Operators can edit the generated configuration, and reinstall preserves their choices.

The installed offline profile remains the default. A separate [package profile](../../crates/sandcrab/docs/network.md) grants egress to named registries. Selecting it lets a guest send data to those services. The CA bundle is mounted read-only for that profile. Exact destinations keep routine dependency installation independent of broader network access.

The CLI shares the installer's socket and profile defaults. Explicit connection and profile choices stay authoritative. A containerized application can mount a separate, read-only socket volume. Authentication checks the daemon's and client's kernel-reported UIDs across independent PID namespaces. The daemon can join a bridge for the package profile while its workloads keep private networks. This avoids sharing credentials, the data volume or the host network with the application.

## Verification

[Installer acceptance](../../.github/workflows/sandcrab-readiness.yml) installs into clean distributions and tests the packaged service beside an unprivileged application. It checks discovery, configuration preservation, capacity under a memory limit, peer identity, package installation and a denied destination.
