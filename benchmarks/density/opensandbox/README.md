# Same-host OpenSandbox comparison

The [comparison workflow](../../../.github/workflows/opensandbox-comparison.yml) runs the published OpenSandbox Python SDK 1.2.1 against Sandcrab and the upstream OpenSandbox 1.2.1 Docker service on the same Docker engine. Each backend gets a fresh Debian 12 guest with two CPUs, 4 GB of memory, no swap and no external network. OpenSandbox runs its own Docker daemon inside this guest. The separate SDK process shares only its network namespace. The summary records whether the kernel device for KVM was accessible. Both providers use their non-KVM backends.

**Install to first command** starts with a prepared OS, the native archive, server wheels and workload images staged locally. It ends when a newly created sandbox prints 42. The upstream interval includes creating its environment, installing the wheels, starting Docker and loading its images. The dependencies' network downloads, building images and the SDK client's startup are outside both timers.

**Idle memory** records the whole guest's proportional set size (PSS), including the upstream server, Docker engine, container shims and workload processes. Subtracting the same guest's pre-install PSS gives the service increment. A nonempty stage reports additional PSS per sandbox. Raw cgroup counters include page cache and kernel charges. Neither PSS nor process RSS substitutes for the enforced cgroup limit.

**Density** uses the [seeded corpus and command mix](../workload.py) with 256 documents and a Git repository per sandbox. Each retained sandbox runs 12 commands after all members of its stage finish seeding. Both services receive the same guest CPU and memory requests. The harness stops at the first failed stage, unexpected output, OOM, memory reserve or command p95 above one second. It reports the largest passing stage across three repetitions, alternating provider order. A result at the last tested stage is a lower bound. The capacity settings used for density are separate from the initial installation measurement.

A pull request runs the two-sandbox smoke check. Full measurements require an L2, L7 or L9 dispatch. CI retains all attempts, including failures. Commit only the aggregate summary when reporting a full measurement.

## L9 measurement

[The three trial summaries](../../../evidence/sandcrab-l9-opensandbox-2026-11-18/summary.json) use the same x86-64 Linux
runner with a 2-CPU, 4 GB, zero-swap limit per service. Both use subprocess or
Docker isolation. KVM was available on the runner and neither arm used it.
Install time starts with locally staged artifacts. Values below span the three
repetitions.

| Metric | Sandcrab | OpenSandbox Docker 1.2.1 |
|---|---:|---:|
| Install to first successful command | 0.480–0.489 s | 13.24–13.54 s |
| Incremental idle service PSS | 3.79–3.85 MiB | 276–282 MiB |
| Command p95 at 16 populated sandboxes | 54–61 ms | 226–234 ms |
| Largest stage passing the seeded command mix in every repetition | 16 | 50 |

All 25 Sandcrab sandboxes became ready at the next stage. Nine workers received
rate-limit errors in each trial. OpenSandbox initialized 100 at its next stage
and hit the 128 MiB reserve before starting the command mix. The harness stops
after the first failed stage. [Run and raw attempts](https://github.com/core607/sandcrab/actions/runs/44367252012)
and [the Sandcrab admission issue](https://github.com/core607/sandcrab/issues/41)
record those boundaries.
