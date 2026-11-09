---
name: maintain-notes
description: Use when writing, implementing, auditing, consolidating, deleting or archiving decision records under notes/.
---

# Maintaining Decision Records

[AGENTS.md](../../../AGENTS.md) owns the lifecycle. Judge a note by the future decision it guides, not its age or word count.

## Find the owner

Search active notes for the mechanism, alternative and replaced design before writing. Update the existing owner when it holds the same decision. Resolve the related-note audit in the change that adds a note.

Keep lasting alternatives, ownership, security, durability and reintroduction conditions. Move descriptions of current behavior into the owning README and link them. Machine-specific procedures stay outside the repository.

A note states `Date: YYYY-MM-DD` and contains Problem, Decision or Proposal, Alternatives, Consequences and Verification. The problem explains the need before choosing a solution. Implemented decisions describe shipped reality; proposals name acceptance criteria and remaining design questions. Record real alternatives and named limitations without restating test cases.

## Classify and apply

- Keep an implemented decision that still guides changes, regardless of length.
- Consolidate a superseded decision into its current owner, preserving every unique rationale, consequence and limitation; repair inbound links before deleting it.
- Keep partially superseded decisions cross-linked and correct the clauses still authoritative.
- Archive settled history only after correcting its content and redirecting inbound links; archived text stays frozen and does not govern current behavior.
- Reject a proposal no longer worth pursuing, with the actual reason; never archive a proposal.
- Delete obsolete rejection or feature-description records only after repairing their references.

When implementing a proposal, move and rewrite its lasting rationale into `implemented/`, or delete it after moving useful behavior into current docs. A consolidation must carry its rationale forward rather than rely on Git history.

## Verify

Run `python3 scripts/repo_check.py`. Inspect cross-repository targets separately: the offline checker validates local links, not remote availability. Report each moved, consolidated, archived or deleted note and explain borderline classifications. Preserve frozen historical references when transferring current ownership between repositories.
