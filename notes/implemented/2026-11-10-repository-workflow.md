# Independent Repository Workflow

Date: 2026-11-10

## Problem

Maintainers working only in the provider repository need its rules and design
ownership without access to a consumer's checkout or a past conversation.
Duplicating executable instructions across agent tools can make the selected
tool change the rules a contributor follows.

## Decision

[AGENTS.md](../../AGENTS.md) owns repository rules, lifecycle and skill inventory.
[CLAUDE.md](../../CLAUDE.md) points there, and generated Claude skill stubs point
to the authoritative `.agents/skills/` files. Both tools receive the same name,
description and workflow. [The generator](../../scripts/sync-claude-skills.py)
validates metadata before writing; check mode refuses drift and extra stubs.

Current behavior belongs in the root or owning component README and the threat
model. Notes retain alternatives, consequences and boundaries that those contracts
do not explain. Their directories encode proposed, implemented, rejected or frozen
historical status; proposals never establish shipped behavior. Agreed work left
unimplemented needs a committed proposal so an independent maintainer can find it.

[Repository checks](../../.github/workflows/repository-checks.yml) run independently
of Rust, SDK and installation acceptance. The offline checker covers repository-local
Markdown links, Markdown heading fragments, skill metadata and inventory, the
Claude pointer and generated stubs. Remote availability is verified when a link
is introduced or moved; network availability does not gate every prose edit.
Frozen archived text is excluded from current-link validation.

## Alternatives

Copying the consumer's Gradle governance, path lanes, bilingual rules, word budgets
and paid AI review would add dependencies and maintenance unrelated to this repository.
Python's standard library and a small dedicated workflow cover the present checks;
Gradle remains scoped to the JVM SDK fixture.

Maintaining complete skills for each agent tool would allow policy drift. Generated
pointers preserve discovery while keeping one instruction source. Having no local
rules would leave ownership and verification dependent on external context.

## Consequences

Maintainers review the meaning of decisions; automation validates local structure
and references rather than deciding whether rationale is true. The lightweight
checker is not a full Markdown renderer and does not fetch remote links. The
repository has no word-count gate or paid review requirement. Additional policy
needs a demonstrated failure rather than parity with the consumer's tooling.

## Verification

`python3 scripts/repo_check.py`, generator `--check` and
`python3 -m unittest discover -s scripts -p test_repo_check.py -v` cover the
published document and skill surface, including broken targets, stale generation
and invalid metadata. The workflow runs for every PR and main push so deleting
a linked non-document file cannot evade the link check.
