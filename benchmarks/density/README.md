# Sandcrab density experiment

The [lightweight-service proposal](../../notes/proposed/2026-11-02-sandcrab-lightweight-service.md)
owns the footprint, readiness, density and breakdown requirements. This directory
contains the seeded workload, scorer, native HTTP client and isolated density
driver. Component tests do not establish sandbox capacity.

The [W0 measurement report](../../executor-native/evidence/sandcrab-w0-2026-11-02/README.md)
links retained raw results, failed attempts and their measurement boundaries.

The [manual installation baseline](READINESS.md) measures first-use steps, edits
and elapsed time on fresh distribution containers. It is separate from density
host preparation and does not establish turnkey readiness.

## Workload and scoring

[protocol.json](protocol.json) fixes the measurement parameters before native runs.
Memory budgets use decimal GB; receipts must include the effective page-rounded
kernel byte limits. A stage passes only when every repetition meets the thresholds.
The fixture allows 512 live sandboxes so every requested stage through 400 can
reach admission; this configuration limit is not a measured capacity.
The first failed repetition ends the search for that budget; retain it and identify
unattempted stages. If all scheduled stages pass, capacity is a lower bound.

[workload.py](workload.py) defines the command probabilities and synthetic files.
The corpus has 20,000 Markdown documents and a separate 32-file Git repository.
The seed fixes their bytes and Git commit. Each agent has an independent seeded
sequence of uniform think intervals and commands. Report the observed command mix
as well as the configured probabilities. Corpus creation refuses an occupied root
and ignores ambient Git paths and configuration so the fixture cannot redirect
writes to another repository.

[scoring.py](scoring.py) judges requests by submission time, including slow
completions after the measurement window. Refusals and transport failures remain
in the success-rate denominator and latency population. A missing OOM observation
does not mean zero OOM kills. Use unrounded nanoseconds for the inclusive one-second
threshold. Record admission failures separately from CPU or memory saturation;
a configured sandbox ceiling is not a measurement of physical host capacity.

[client.py](client.py) uses bounded JSON over the public Unix HTTP interface and
checks the service's peer UID before sending request bytes. It sends each request
once. A lost command acknowledgement remains uncertain; observing its original ID
does not authorize another command submission. New connections avoid commands
racing the server's idle-connection deadline; connection and polling costs belong
in the reported client latency.

## Component checks

From the repository root, with Python 3.10 or newer, Git, bash and ripgrep available:

```sh
python3 -m unittest discover -s experiments/sandcrab-density -p 'test_*.py' -v
```

Linux runs the real command mix and Unix-peer/transport checks. On Windows those
checks skip; a Windows pass is not Linux evidence.

## Native measurement

Use an isolated root-capable systemd host with cgroup v2, XFS utilities, Git,
Python 3.10+, bash, ripgrep and the [prepared toolchain](../../executor-service/prepare-tools.sh).
Build the binary with `./gradlew buildExecutorRust`. The driver refuses competing
load controllers or native fixtures, insufficient free disk, and insufficient
host memory outside its bounded slice. It creates a disposable XFS image and uses
the public API to create the corpus, clone volumes and run commands. It never
adopts existing storage. Keep the repository layout for the shared native cleanup.

```sh
sudo python3 experiments/sandcrab-density/density.py --smoke \
  --binary build/executor-service/bin/sandcrab --tools /prepared/tools \
  --report /operator/evidence/smoke-unique.json
sudo python3 experiments/sandcrab-density/density.py --budget 5 \
  --binary build/executor-service/bin/sandcrab --tools /prepared/tools \
  --report /operator/evidence/density-5gb-unique.json
```

Smoke uses two agents and a small corpus to check the actual entry path and cleanup;
it is not a capacity measurement. Run all protocol budgets for W0 and final
comparisons. Each budget needs a new receipt path. The
[measurement workflow](../../.github/workflows/sandcrab-density.yml) runs smoke on
relevant pull requests; manual dispatch with `canonical=true` runs all three budgets
on separate hosts after smoke. Its binary build uses a separate runner.

The JSON receipt includes source and binary identities, effective resource limits,
all stage attempts, kernel counters, refusal codes and cleanup results. The sibling
`.attempts.jsonl` records a command's identity before submission, including setup
commands, kernel samples and attempts interrupted before an outcome. Full receipts
are checkpointed during setup and between stages; the timed loop appends compact
ledger events without rewriting or fsyncing the whole receipt. Unknown outcomes retain their identity for reconciliation;
there is no command replay. API cleanup checks resource inventories; host cleanup
stops only fixture units and verifies empty cgroups and unmounted fixture paths.
Unconfirmed cleanup fails and preserves resources for inspection.

`measurementStatus=COMPLETED` means the capacity search completed, including its
first failed stage. Read each stage's score; process exit zero does not mean every
stage passed. Missing observations, invalid setup and unconfirmed cleanup produce
`ERROR`. Smoke fails its process if its stage fails. Keep failed receipts and the
adjacent diagnostic files. Collected timestamps are monotonic; only the receipt's
start and finish timestamps are wall time.

Daemon RSS and hierarchical memory/CPU counters are observations of this fixture.
`file` already includes `shmem`; do not add them as disjoint memory categories.
Sandbox CPU is pool CPU minus daemon CPU; system-manager CPU outside the slice is
reported separately. Polling can miss brief executing states. Fresh-distribution
readiness remains a separate W0 requirement.

The [native density smoke receipt](../../executor-native/evidence/2026-11-02-sandcrab-density-smoke.json)
records one two-agent run on Ubuntu 24.04 with its source/binary hashes and verified
cleanup. It checks the measurement entry path, not the canonical capacity or
fresh-install readiness targets. The full attempt ledger is retained in the
[workflow artifact](https://github.com/core607/poketto/actions/runs/41352546796).

## Fixed costs

[footprint.py](footprint.py) accepts the same binary, tools, budget and report
arguments. It measures daemon idle RSS, then 1, 10 and 50 idle bash sessions and
finite `/bin/sleep` runs. `--smoke` checks only one of each. The workflow runs its
smoke entry on pull requests and all counts during canonical measurement.

Each cohort has five one-second samples after two seconds of settling. A finite
run holds for 30 seconds; the whole cohort must become live within 15 seconds and
remain alive during sampling. Refusal, OOM, a lost cohort or unconfirmed cleanup
fails the measurement. Minimal bash/sleep workload memory is included. These are
observed fixed costs of those workloads, not an estimate of an absent process.

Per-item deltas compare cohort medians with an empty baseline. Idle-session counts
grow within one daemon, with its initial idle samples as the baseline. Each finite
cohort gets its own baseline after the previous cohort is cleaned. Raw counters,
negative cache-release deltas and both shared-memory fields remain in the receipt.
No global page-cache reset is performed. The volume capability is enabled but
these cohorts contain no volume data.

The binary record checks ELF interpreter and dynamic-library entries as well as
bytes and SHA-256. The dependency inventory counts distinct executable surfaces
used by core execution, sessions and optional durable volumes, separately from
installation tools and workload programs. It is not a distribution package count
or the transitive shared-library closure; the receipt names that boundary.

The [native footprint smoke receipt](../../executor-native/evidence/2026-11-02-sandcrab-footprint-smoke.json)
covers one idle session and one finite run with verified API and host cleanup.
It does not establish the 10/50-session fixed costs or any capacity limit.

## Page-cache comparison

[page_cache.py](page_cache.py) uses the same command arguments to compare ten
sessions over distinct reflink volumes with ten sessions reading one shared tree.
The corpus and Git commit must match. Public API commands read and checksum every
Markdown file; the shared tree is mounted through the profile's read-only paths,
with that mount property checked inside the sandbox. This measures the existing
read-mount mechanism, not a template API.

The controller flushes and advises eviction only for the synthetic document files,
then uses root `mincore` observations to require a cold dataset before each case.
It never drops global caches. Root observation avoids the restricted residency
view a different unprivileged file owner can receive. Distinct device/inode pairs
establish that the reflink case does not silently read the same tree ten times.
Receipts retain cold/warm resident page counts, hierarchical `memory.stat` before
and after reads, checksums, OOM counters and cleanup outcomes. No cache saving is
assumed in advance, and an unavailable cold-state observation fails the run.

The shared fixture tree is created before daemon startup; its data pages must be
evicted before sandbox readers fault them into the measured slice. Inode metadata
and tool caches are not reset. The controller inspects only its disposable volume
paths according to the current storage layout. These observations are not an API
for accessing another daemon's content. Smoke uses 400 documents with all ten readers;
the canonical comparison uses the full corpus.

The [native page-cache smoke receipt](../../executor-native/evidence/2026-11-02-sandcrab-page-cache-smoke.json)
records that small comparison, including cold-state proof and verified cleanup.
It does not replace the full-corpus comparison.

## Startup timeline

[cold_start.py](cold_start.py) uses the same arguments and additionally requires
bpftrace, kernel BTF, the raw cgroup-create tracepoint and scheduler exec/exit
tracepoints on an isolated Linux 5.7+ host.
It observes three new persistent sessions; smoke uses the smaller fixture budget.
Only the fixture's daemon cgroup and new descendants of its pool emit events.
The trace records D-Bus client exec, session-slice creation, systemd-run exec,
the sandbox bwrap exec and bash exec. It distinguishes bwrap's version check from
the actual sandbox launch by matching the launcher's PID and cgroup across its
`exec` replacement, as implemented by
[`sandcrab-launch`](../../executor-service/rust/sandcrab-launch/src/lib.rs).
A process exit invalidates that identity. No user argv pointers are read.
Unparseable events, reported probe errors and missing required events fail the
measurement.

The observer runs temporarily in a bounded service inside the fixture slice, with
its own memory, CPU, task and lifetime limits. Receipt timelines use CLOCK_BOOTTIME
and include tracing overhead; use the density driver's untraced `coldStartNs` for
latency comparisons. The trace clock handshake, event ordering, source hash,
observer diagnostics and cleanup are retained. bpftrace is a measurement tool,
not a Sandcrab runtime dependency. Fresh-install readiness is not established by
preparing this instrumented host.
