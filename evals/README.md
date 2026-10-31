# Evaluations

[Inspect](https://inspect.aisi.org.uk/) owns execution, repetitions, logs and the
transcript viewer. The application has no dependency on it. Install the pinned
[requirements](requirements.txt) in a dedicated Python 3.12+ virtual environment.

## Current entrance

The **Evaluation preflight** workflow runs ten native API cases and the same six programming
tasks through both native and published OpenSandbox Python clients, three times each
(66 attempts). It is available from GitHub Actions' Run workflow button and is also
required by the code-change CI matrix. It builds the requested checkout, starts a
disposable native service and runs Inspect as an ordinary client. No production
endpoint, product account, model key or model API is used. The root controller
owns only its fixture's units, slice and temporary directory; cleanup verifies
containment before deleting them.
Native HTTP framing, authenticated loopback TCP, connection reuse, live command events and resume, opaque host calls, caller-lowered resource caps, session lifecycle, file transfers, volume durability and quotas, startup cancellation, cleanup-failure and CLI recovery probes must pass before Inspect runs. The file, volume and TCP probes and the programming fixture each own a separate 512 MiB XFS image. These deterministic probes do not measure model usability.

Scripted runs also require the [published Python and Kotlin SDK consumers](sdk/README.md)
to pass against a separate native fixture. The artifact retains their SDK receipt;
these checks make no model calls.

The workflow summary lists every case and all attempts. Its artifact contains
the machine-readable summary, complete Inspect log, static transcript viewer and
fixture cleanup receipt. Programming attempts also retain their exported tar files,
including failed submissions. To browse the downloaded transcript, run
`python -m http.server --directory viewer` from the artifact directory and open
the local URL. Summary links are relative to the downloaded artifact; GitHub's
job summary does not host the viewer.

These scripted results establish that the harness can drive and score the API.
The **Agent evaluations** workflow runs a selected suite with a plain tool-calling
DeepSeek Flash agent. Start it on `main`, choose `workspace` (the default), `native`
or `all`, the programming client (`sdk` by default), repeat count and batch budget,
then read the workflow summary. The native-only suite selects the `native` client automatically.
Incorrect task results are measurements; missing
usage, infrastructure errors and incomplete cleanup fail the run. Every trial
remains in the artifact. Paid work never runs automatically on a pull request.
The [programming evidence receipt](evidence/2026-10-29-workspace-model.json) records
one paid batch and a controlled regrade of the same artifacts after correcting an
unstated exit-status requirement. It preserves the original scores separately.
The [first SDK model receipt](evidence/2026-10-30-workspace-sdk-model.json) retains
15 successes in 18 attempts: two uploads stopped on a service error classification,
and one sample reached its token limit without exporting. Fixing that classification
does not change these recorded outcomes.
The [second SDK model receipt](evidence/2026-10-31-workspace-sdk-model.json) retains
15 successes in 18 attempts with no infrastructure errors and complete cleanup.
Three multi-file attempts reached the token limit without exporting; their tool
refusals were omitted from model-facing replies. The receipt records that defect
and the unchanged outcomes, independently of its offline serialization regression.

Configure `DEEPSEEK_EVAL_API_KEY` as a repository secret. The workflow can reuse
`AI_REVIEW_API_KEY` when review uses the standard DeepSeek endpoint. Only the
unprivileged evaluator receives the key; the daemon and sandbox commands do not.
Rerunning an existing paid workflow fails validation before the evaluator starts:
inspect its ledger and start a new run explicitly. Non-main refs, other providers,
automatic baseline comparison, scheduled runs, Poketto MCP tasks and creator QA remain under the
[evaluation proposal](../notes/proposed/2026-10-28-agent-evaluation-entrance.md).

## Native API cases

Each file in [cases/sandcrab](cases/sandcrab/) is YAML with four fields:

| Field | Meaning |
|---|---|
| `id` | Unique stable case name |
| `task` | Natural-language instructions shown to the agent |
| `fixture` | Command argv, optional narrower timeout/output limits, and exercise |
| `expected` | Independent daemon-state and output checks; hidden from the agent |

Exercises are `run`, `cancel`, `replay`, `profile-recovery` and `forget`. The
scripted baseline follows the exercise; an agent receives the task and fixture.
Expected checks are terminal `state`, exact `stdout`/`stderr`, `exitCode`,
`truncated`, daemon error codes in `errors`, idempotent `replay`, and `forgotten`.
`refusalBeforeRun` requires its error before successful admission, so a refusal
after a successful command cannot satisfy a recovery task.
Unknown checks are rejected. No model judge or final-answer assertion can pass a
case. A forgotten result needs an observed terminal read and a final 404; a 404
alone does not prove execution.

The Inspect task provides one bounded HTTP tool scoped to a sample's run ID.
Commands execute only through Sandcrab. The tool checks the root-owned socket and
peer, and optional waiting polls the real service. Reports separate native HTTP
calls from model tool calls; expected refusal cases still count as refused calls.
Missing usage prices are unknown, not zero. Scripted runs have zero model calls.
The corpus hash, source revision, model, evidence kind, attempts, usage, duration,
failures and limit exits remain in the result. A cleanup failure fails preflight.

## Programming tasks

[cases/workspace](cases/workspace/) covers CSV aggregation, interval and log-parser
repairs, binary file indexing, a multi-file program and a persistent inventory CLI.
The agent receives the task, initial files and required artifact paths. It writes
and tests Python using an ordinary consumer client with five tools: shell, text
upload, session restart, receipt inspection and tar export. The native client owns
a volume and sessions; the SDK client owns a sandbox and named shells. Neither requires a Poketto account, repository or
content semantics. These results measure this client and corpus, not an agent's
ability to discover the raw HTTP API or general programming ability.

Each case has `id`, `task`, `fixture.files`, `reference` and `expected`. File maps
hold UTF-8 strings or a single `base64` field for binary bytes. `reference.files`
and `reference.check` drive the scripted client through the same tools; reference
code and hidden checks never enter model messages. Expected checks are:

| Field | Meaning |
|---|---|
| `artifacts` | Required regular source files; must match the reference file paths |
| `preserve` | Supplied inputs or public tests that must remain byte-identical |
| `textContains` | Required literal snippets in a submitted text file |
| `steps` | One to eight ordered checks, each invoking submitted Python or a supplied check driver with `argv`, `stdin` and exact `stdoutJson` |
| Step `exitCode` | Expected process status, default `0`; `null` permits normal nonzero exits when only the output and state are specified |
| Step `files`, `links`, `reset` | New inputs, opaque symlink targets and paths to remove inside the grading sandbox; cannot replace submitted source |
| Step `filesJson`, `absentFiles`, `unchangedFiles` | Independent stored-JSON, absence or byte-preservation checks |

The last successful export is the submission. The client verifies response length
and SHA-256 before sealing it. The host reads bounded regular files from the tar
without extracting or executing them. After closing the producing session, the
grader copies only the required sources into a fresh sandbox, provides hidden
inputs and compares stdout and file readback on the host. A final-answer claim,
changed public test or matching stdout with incorrect stored data cannot pass.
Every hidden check uses real Sandcrab execution; there is no model judge.
Timeout, cancellation, resource exhaustion and output truncation always fail;
accepting a normal nonzero exit still requires every output and stored-file check.

A task has an 8 MiB workspace, at most 20 shell commands, 16 text uploads, three
session restarts and four exports. Commands have ten-second and 4096-byte output
limits; text files are at most 64 KiB and exports at most 2 MiB. A restart retains
files and resets shell state. Archive members require unique relative paths;
unrelated drafts and directories are allowed within the export byte bound.
The native client queries an uncertain upload by its original ID without replay.
Cleanup joins outstanding client work before releasing resources;
an unresolved identity fails cleanup and stops later programming samples.

Reports separate agent tool traffic from setup, grading and cleanup API calls.
Transport failures and output-size refusals have separate counts. Evaluator and
sandbox Python versions, pinned client packages and source/corpus revisions are
recorded. Legacy native-case harness traffic is labelled uncounted.

### OpenSandbox programming client

`workspace_sdk.py` uses the unmodified synchronous API of the published Python SDK
pinned in [sdk/requirements.txt](sdk/requirements.txt). The controller enables its
authenticated TCP endpoint on loopback only after native lifecycle preflight.
The SDK credential belongs to the evaluator; neither it nor the model key enters
the sandbox. Setup, shell commands, files, export and sandbox deletion use the SDK;
the existing native grader runs submitted sources in a separate fresh sandbox.

The task text, fixtures and hidden checks are identical for both clients. Tool
contracts describe their differences: SDK uploads overwrite existing files, and
their receipt hash describes sent bytes. SDK export closes the producing shell,
builds a bounded tar inside a separate sandbox command, then downloads and verifies
its length and SHA-256 before sealing it. Export closes background processes too;
further commands need an explicit restart. SDK status reports the sandbox, bound
shell ID and recent receipts; binding does not prove shell readiness.

The caller-owned HTTP transport rejects endpoints outside the fixture origin,
bounds complete responses and counts actual requests without retaining credentials
or discovery response bodies. It buffers command events because tools return
complete results; these evaluations do not measure streaming latency. Mutations
are not automatically retried; SDK creation health polls remain recorded, including
initial not-ready responses. An ambiguous SDK mutation stops agent operations;
cleanup deletes the known sandbox or fails if its creation was not acknowledged.
The client checks observed HTTP status even when the pinned SDK masks a session
error. Recoverable refusals include the HTTP status and a bounded protocol error
code; raw server diagnostics are not copied into observations. This is evaluation
instrumentation, not an SDK patch or a server response change.
The model provider includes Inspect tool-error types and messages alongside any
partial tool output, within the same request byte limit as successful replies.

## Paid-run limits

[pricing.yaml](pricing.yaml) owns the verified provider context ceiling and peak
rates. Before each dispatch, [budget.py](budget.py) reserves the full context plus
maximum output cost and fsyncs a request ID and digest to a new ledger. Input is
charged at the cache-miss rate even when cached, so recorded costs are upper
estimates under that catalog, not invoices. A valid response releases unused
reservation. Missing or invalid usage, transport failure, cancellation or a lost
response retains the maximum reservation and stops the entire batch. Neither the
transport nor Inspect retries it; an existing ledger cannot be reused for paid work.
Model tasks reject an unbudgeted provider before generation.

The default batch limit is USD 1 and the maximum is USD 5. A batch must cover one
maximum request reservation calculated from the catalog. A 64 KiB
request limit, bounded output, twelve turns for the native suite or twenty for
workspace/all, 32,000 tokens and 180 seconds per sample, and a thirty-minute
controller deadline also bound the work. Model calls use text and client-side
Sandcrab tools only; no provider search, fetch or other separately billed tools are
enabled. Unknown costs stay labelled unknown and keep their reserved upper bound.

Reverify prices and context limits before changing the catalog; paid runs reject
catalogs older than thirty days. The cap depends on those rates and the provider
honouring its token limits. Reports record the catalog, configuration, source and
corpus revisions, usage and provider fingerprint when returned. `deepseek-flash`
is a mutable provider alias; its advertised release is recorded without claiming
an immutable model version. Automatic comparisons remain disabled.

## Local checks

```sh
python -m venv .gradle/eval-python
.gradle/eval-python/bin/python -m pip install -r evals/requirements.txt
.gradle/eval-python/bin/python -m unittest discover -s evals -p 'test_*.py' -v
```

Windows uses `.gradle/eval-python/Scripts/python.exe`. Offline checks exercise
the real Inspect engine's failure retention and the scorer's rejection paths.
They do not prove Linux containment. On a disposable Linux host meeting the
[native requirements](../executor-service/rust/sandcrab/README.md), build with
`./gradlew buildExecutorRust`, prepare the tools, then run:

```sh
sudo python3 evals/native.py --binary build/executor-service/bin/sandcrab \
  --tools /var/lib/sandcrab-evals/tools --python /absolute/path/to/venv/bin/python \
  --output /var/lib/sandcrab-evals/results --workspace-client both
```

The output directory must be new. Its ancestors and the virtual environment must
be readable by the `daemon` client account; source files are copied into the
root-owned fixture. Keep every attempt in a separate directory. The harness never
falls back to an unrestricted host subprocess for a sandbox command.
Export directories belong to `daemon` and are private. After a local run, use a
privileged copy to collect them. The workflow transfers report ownership to its
runner after the controller exits, including on failure.

Use `--suite native`, `workspace` or `all` (default) to select cases. For a paid
local run, supply `DEEPSEEK_API_KEY` through the environment, preserve only that
variable through sudo, and add `--mode model --suite workspace --epochs 3 --budget-usd 1.00`.
Keep the key out of arguments, cases and artifacts. Inspect the complete ledger
after any interrupted run before authorizing another batch.
