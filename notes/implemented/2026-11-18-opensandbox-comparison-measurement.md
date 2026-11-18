# Comparing the OpenSandbox Docker backend

Date: 2026-11-18

A density claim depends on the workload, admission limits and which processes
the measurement includes. The [comparison](../../benchmarks/density/opensandbox/README.md)
drives both services through the same released OpenSandbox Python client and
seeded content workload. The upstream Docker engine and its shims share the
upstream service's cgroup. Both services run sequentially on the same kernel;
alternating the order across trials reduces ordering bias.

Using an installed, idle Docker engine outside the upstream budget would hide
part of its resident cost. Plain Docker alone would omit the server, adapter and
execution daemon that clients actually use. Staging dependencies locally keeps
registry bandwidth outside both installation timers. KVM-based Fast Sandbox
requires a separate measurement. The [adapter reference](../../crates/sandcrab/opensandbox.md)
owns the tested upstream CLI surface.

The [L9 evidence](../../evidence/sandcrab-l9-opensandbox-2026-11-18/summary.json) retains the last passing stage and
the first failure for each backend. Per-attempt data lives in the linked CI
artifact. Memory, latency and supported concurrency remain independent claims.
