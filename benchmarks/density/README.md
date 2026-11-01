# Sandcrab density experiment

The [lightweight-service proposal](../../notes/proposed/2026-11-02-sandcrab-lightweight-service.md)
owns the footprint, readiness, density and breakdown requirements. This directory
contains the seeded workload, scorer, native HTTP client and isolated density
driver. Component tests do not establish sandbox capacity.

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
reported separately. Polling can miss brief executing states. Binary/dependency
footprint, idle 1/10/50 and finite-run costs, fresh-distribution readiness, and the
cold-start/page-cache breakdown remain separate W0 requirements.

The [native smoke receipt](../../executor-native/evidence/2026-11-02-sandcrab-density-smoke.json)
records one two-agent run on Ubuntu 24.04 with its source/binary hashes and verified
cleanup. It checks the measurement entry path, not the canonical capacity or
fresh-install readiness targets. The full attempt ledger is retained in the
[workflow artifact](https://github.com/core607/poketto/actions/runs/41352546796).
