# Agent-Ready Defaults and Client Ergonomics

Date: 2026-11-18

## Problem

The [installed default configuration](../../crates/sandcrab/install/default.toml)
allows eight sandboxes and eight volumes of at most 64 MiB each. Its only profile
has no network and a 60-second session lifetime. Agents commonly install packages
and serve more than eight users, so an operator must write an allowlist and new
limits by hand before the first realistic agent task
([network egress](../../crates/sandcrab/README.md#network-egress)).

Every [CLI](../../crates/sandcrab/README.md#cli) client command needs `--socket`,
`--endpoint` or an environment variable, even though the installer knows the socket
path. The [standalone container](../../crates/sandcrab/install/README.md#standalone-container)
runs with `--network=none`. Its loopback listener is reachable only inside the
container, and allowlisted egress has no route out. The documentation does not
describe how an application in another container shares the socket and matches
the configured client UID.

## Proposal

This is an unimplemented design. The default profile keeps `network = "none"`.

- **Package profile.** The default configuration adds an opt-in profile that
  allows exact package-index destinations, such as `pypi.org`,
  `files.pythonhosted.org` and `registry.npmjs.org`. Applications select it
  explicitly per sandbox or workspace.
- **Capacity defaults.** The installer derives sandbox, volume and storage-pool
  limits from effective memory (including cgroup limits) and available space on
  the chosen storage filesystem, within documented ceilings, instead of
  fixed counts of eight.
- **Socket discovery.** When no flag or environment variable selects a transport,
  the CLI uses the installed socket path if it exists and passes the existing
  root-owned socket and peer checks. Otherwise it keeps today's error. Commands
  selecting a profile use the explicit flag, then `SANDCRAB_PROFILE`, then the
  literal installed profile name `default`. A custom installation missing that
  name reports the unknown profile and allows the caller to select another.
- **Container layouts.** The installation guide documents and tests two layouts:
  an application container sharing the socket through a volume with a matching
  client UID, and an egress-enabled variant whose network lets the daemon's proxy
  reach allowlisted names while workloads keep no direct route.
- **Session lifetime.** Raw sessions keep their current default. Long-lived agent
  directories rely on the idle window of
  [persistent workspaces](2026-11-18-persistent-workspaces.md).

Acceptance criteria:

- On a fresh install, `sandcrab run -- python3 -c 'print(6 * 7)'` succeeds as
  root without connection or profile flags or environment variables.
- `pip install` succeeds under the package profile, and destinations outside the
  allowlist are refused.
- Both container layouts pass in CI.

Remaining design questions: the exact preset destination list and who maintains
it; capacity formulas and their ceilings; and whether a client configuration file
is worth its extra state.

## Alternatives

- Enable egress in the default profile. Every guest could then send data to the
  preset destinations without an explicit decision, which changes the default
  posture in the [threat model](../../THREAT-MODEL.md).
- Run the container on the host network. This exposes the loopback listener to
  every host process and removes the container's network isolation.
- Leave defaults minimal and document tuning only. This keeps the first realistic
  agent task blocked on configuration that most agent operators need.

## Consequences

The preset list needs maintenance as package hosts change. Selecting the package
profile lets guests send data to those destinations, which an allowlisted service
can relay elsewhere. Derived capacity defaults make two hosts' installed
configurations differ. Socket discovery adds one implicit transport choice, but
under the same authentication checks as an explicit flag.

## Verification

Installer acceptance and the readiness workflow cover socket discovery, derived
limits and the package profile on each supported distribution. Network egress
conformance checks allowed and refused destinations. Container layouts run in CI
on a disposable host.
