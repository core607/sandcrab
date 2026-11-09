# AGENTS.md

Sandcrab is an independently released Linux sandbox service. This repository owns the daemon, CLI, SDK integration, generic evaluations and benchmarks; applications consume releases and own their domain state and effects.

The [provider decision](notes/implemented/2026-11-02-sandcrab-lightweight-service.md) owns installation, runtime and measurement trade-offs; read it when changing those boundaries.

## Working boundaries

- Implement only an assigned, settled task; `notes/proposed/` records designs awaiting implementation and is not evidence of shipped behavior.
- Before 1.0, releases identify commits without promising compatibility; change interfaces and rebuild provider metadata instead of adding compatibility shims.
- Read the owning code and current documentation before relying on a decision record; [repository ownership](notes/implemented/2026-11-10-repository-workflow.md) keeps rules, rationale and behavior separate.
- Keep application identities, authorization, transactions and credentials in callers; [host calls](crates/sandcrab/host-calls.md) carry opaque bytes rather than application handlers.
- Preserve the containment and authority boundaries in [THREAT-MODEL.md](THREAT-MODEL.md); missing required isolation never permits unrestricted execution.

## Content ownership

| Home | Authority |
|---|---|
| [README.md](README.md) | First use and navigation |
| Crate, SDK, evaluation and benchmark READMEs | Current API, configuration, operating limits and commands |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Trust, authority and isolation boundaries |
| `notes/` | Lasting rationale, alternatives and consequences |
| This file | Repository rules and skill inventory |
| `.agents/skills/` | Reusable workflows and judgment |

## Decision records

- Use `notes/{proposed,implemented,rejected,archived}/yyyy-mm-dd-topic.md`; directories encode status and a decision needing no implementation belongs in `implemented/`.
- Write a note only for lasting rationale that code, tests and current docs do not explain; search and resolve related notes in the same change using [maintain-notes](.agents/skills/maintain-notes/SKILL.md).
- Record agreed work left unimplemented as a proposal; implementing a proposal moves and rewrites its lasting rationale into `implemented/`, or deletes it after moving behavior into current docs and repairing links.
- Each note must stand alone using committed references; never cite a chat, private machine path or uncommitted plan as authority.
- Correct current decisions made false by a change; record reversals explicitly and preserve unique rationale when consolidating notes.
- Archive only settled history after redirecting inbound links; add `Archived: YYYY-MM-DD` beneath its date, then leave it frozen and non-authoritative.

## Verification and delivery

The [pre-push workflow](.agents/skills/pre-push-checks/SKILL.md) selects evidence for the affected surface. Repository checks need Git and Python 3.10+; the [workflow decision](notes/implemented/2026-11-10-repository-workflow.md) explains their scope.

| Command | Evidence |
|---|---|
| `python3 scripts/repo_check.py` | Local document links, skill metadata and inventory, generated stubs |
| `python3 scripts/sync-claude-skills.py` | Regenerate Claude skill stubs; `--check` verifies without writing |
| `python3 -m unittest discover -s scripts -p test_repo_check.py -v` | Repository checker and generation failure cases |
| `docker build --target check .` | Pinned Linux Rust formatting, Clippy and locked tests |
| `python3 -m unittest discover -s benchmarks/density -p 'test_*.py' -v` | Benchmark protocol and collector tests |

- Run affected checks; real isolation changes need [native conformance](crates/sandcrab/README.md#verification), and SDK or installation changes need their owning acceptance workflows.
- Never replace a required check with an invented equivalent; report unavailable evidence and stop only the delivery that depends on it.
- Run complete density measurements only at the [L2, L7 and L9 checkpoints](benchmarks/density/README.md#native-measurement); use affected checks otherwise, commit aggregate summaries, retain raw and failed attempts in CI artifacts, and track missed targets without repeated tuning in one PR.
- Work on short-lived branches with conventional commits, push through PRs, address blocking review findings and verify checks on the exact head before merging; never push directly to `main`.
- Preserve author identities, copyright and existing attribution; when contributing with Hiyori, include `Co-authored-by: Hiyori <noreply@openai.com>` in ordinary commits, the PR body and the final merge commit, and read each back.
- Keep credentials and environment-specific runbooks outside this repository; `.env` remains the first line of `.gitignore`.
- Write repository prose in English and follow [prose-standard](.agents/skills/prose-standard/SKILL.md); preserve contractual conditions and consequences when shortening text.

## Skills

`.agents/skills/` is authoritative. Claude discovers generated pointers under `.claude/skills/`; regenerate them through the command above after skill metadata changes.

| Skill | Purpose |
|---|---|
| [maintain-notes](.agents/skills/maintain-notes/SKILL.md) | Classify and maintain decisions |
| [prose-standard](.agents/skills/prose-standard/SKILL.md) | Write and audit repository prose |
| [review](.agents/skills/review/SKILL.md) | Review correctness, lifecycle, authority and evidence |
| [pre-push-checks](.agents/skills/pre-push-checks/SKILL.md) | Select verification and deliver a reviewed change |

Explicit task instructions take precedence over skill guidance. Skills do not authorize unrelated work; retain a rule only while its prevented failure is concrete.
