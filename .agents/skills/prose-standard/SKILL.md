---
name: prose-standard
description: Use for substantive writing, rewriting or audits of repository prose, including READMEs, decision records, skills and contracts in comments.
---

# Prose Standard

Write enough to preserve the reader's contract, then remove repetition and narration. [AGENTS.md](../../../AGENTS.md) owns where each fact belongs.

Before rewriting, identify the actor, action, condition, ordering, obligation, ownership, side effect, failure, exception and consequence. Shortening must preserve all clauses that affect a caller or maintainer.

- Current docs describe behavior, configuration, limits, failures and operation; link to decisions for alternatives and rationale.
- API documentation states non-obvious parameters, return distinctions, cancellation, ownership and durability.
- Internal comments explain non-local invariants, races or surprising failure behavior; remove narration of adjacent code.
- Decision records explain the choice, real alternatives, consequences and verification; implemented notes describe shipped reality.
- Skills name a concrete failure their guidance prevents; remove rules without one.

Prefer direct terms and one main idea per sentence. Keep related conditions together. Separate measured facts from hypotheses and design proposals. Use emphasis sparingly, and do not repeat a fact already owned by another surface.

Every repository reference must resolve. Cross-repository links name a committed target; chats, review rounds and private machine paths are not project authority. Keep change narration in commits and PRs rather than current-state docs.

Read the owning implementation before changing a contract. Update authoritative text before generated derivatives, then reread the result independently to confirm that every required condition and consequence survived. Review-only requests produce findings without edits.
