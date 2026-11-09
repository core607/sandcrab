---
name: pre-push-checks
description: Use when preparing a push or pull request, or assessing delivery readiness.
---

# Pre-Push Checks

Confirm the repository, branch and worktree state, fetch the live base when needed, and inspect the complete outgoing diff, including untracked files. Reinspect after integrating another change.

## Select evidence

[Repository checks](../../../.github/workflows/repository-checks.yml) own document, skill and generation verification. Run its commands for changes to those surfaces; regenerate stubs before checking skill metadata changes.

[Rust and benchmark checks](../../../.github/workflows/ci.yml) own the pinned Docker Rust check and collector tests. Run the affected commands without replacing Linux verification with host-only compilation.

- Isolation, lifecycle and native API changes require the real Linux [conformance runner](../../../crates/sandcrab/README.md#verification); unit tests alone do not establish containment.
- Published SDK or adapter changes use [evaluation preflight](../../../.github/workflows/evals.yml) and the [SDK contract](../../../evals/sdk/README.md).
- Installer, packaging or first-use changes use [readiness acceptance](../../../.github/workflows/sandcrab-readiness.yml); release materials and documented commands must be tested together.
- Benchmark and eval changes verify collector/grader integrity and successful work, keeping scripted and paid-model evidence distinct; [benchmark documentation](../../../benchmarks/density/README.md) owns measurement operation.
- Select downstream acceptance when a change affects a consumer contract, using the [released-archive workflow](../../../.github/workflows/downstream-release.yml).

Use the owning workflow's actual commands and path coverage; report skipped or unavailable checks honestly. Local JVM checks use the Gradle Wrapper without `--no-daemon`. Full density runs follow the limited checkpoints in [AGENTS.md](../../../AGENTS.md), not every PR.

## Deliver

Fix relevant failures before an ordinary push. An environment failure needs the command, observed error and missing capability; do not substitute a manual imitation for a required check or bypass hooks without authorization.

Commit on a short-lived branch, push normally, verify the remote head and open the PR. Describe the problem, resulting behavior and selected validation. Read back required author attribution on the commit and PR body.

Review the exact head and address blocking findings. Wait for every applicable CI check, including any newly required by a changed head. A skipped job provides no evidence. Merge only after those checks and review complete; read back the final commit and its attribution, and verify applicable post-merge checks. A merge alone does not prove deployment or a published release.

Within the assigned task, drive delivery without repeated approval requests. Stop for an actual blocker or a decision outside the authorized scope, while continuing independent work.
