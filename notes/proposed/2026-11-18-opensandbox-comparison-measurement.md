# OpenSandbox Comparison Measurement

Date: 2026-11-18

## Problem

The [README](../../README.md) positions Sandcrab against subprocesses, Docker,
microVMs and, through its adapter, OpenSandbox. Claims about low fixed cost, fast
starts and small idle footprint come from the design and from Sandcrab-only
[density measurements](../../benchmarks/density/README.md). No same-host comparison
with OpenSandbox exists. The [OpenSandbox adapter](../../crates/sandcrab/opensandbox.md)
is verified with the published Python and Kotlin SDKs, not with OpenSandbox's
`osb` CLI.

## Proposal

This is an unimplemented design.

A comparison stage in the density benchmark measures Sandcrab and OpenSandbox's
local Docker runtime on the no-KVM reference host:

- install-to-first-command time;
- resident memory of the service at idle;
- idle memory per sandbox;
- create and first-command latency;
- command round trip;
- density at a fixed memory budget, using the existing seeded workload.

Running the same workload through the OpenSandbox Python SDK against both services
isolates runtime cost from client differences. A separate check records which `osb`
commands work against the adapter.

Acceptance criteria:

- Aggregate results are committed and raw attempts retained under the existing
  measurement policy.
- README claims either cite the measurement or are removed.
- The supported `osb` subset is documented.

Remaining design questions: the pinned OpenSandbox version; a fair configuration
for images, egress and OpenSandbox's isolation sessions; and how to state that
OpenSandbox's KVM-based Fast Sandbox runtime is outside the reference host.

## Alternatives

- Keep qualitative positioning. Readers cannot verify the claims that distinguish
  Sandcrab.
- Compare only with plain Docker. That omits the project whose API Sandcrab
  implements and whose users the adapter targets.

## Consequences

The benchmark maintains a second runtime fixture. Results may contradict current
positioning, in which case the README changes rather than the measurement.

## Verification

The density benchmark's component tests cover the new collectors. Native runs
follow the existing checkpoint and evidence rules, keeping aggregate summaries in
Git and raw and failed attempts in CI artifacts.
