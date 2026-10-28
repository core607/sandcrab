# Evaluations

[Inspect](https://inspect.aisi.org.uk/) owns execution, repetitions, logs and the
transcript viewer. The application has no dependency on it. Install the pinned
[requirements](requirements.txt) in a dedicated Python 3.12+ virtual environment.

## Current entrance

The **Evaluation preflight** workflow runs ten independent Sandcrab cases three
times each. It is available from GitHub Actions' Run workflow button and is also
required by the code-change CI matrix. It builds the requested checkout, starts a
disposable native service and runs Inspect as an ordinary client. No production
endpoint, product account, model key or model API is used. The root controller
owns only its fixture's units, slice and temporary directory; cleanup verifies
containment before deleting them.
Startup cancellation and CLI result-recovery fault probes must pass before Inspect runs.

The workflow summary lists every case and all attempts. Its artifact contains
the machine-readable summary, complete Inspect log, static transcript viewer and
fixture cleanup receipt. To browse the downloaded transcript, run
`python -m http.server --directory viewer` from the artifact directory and open
the local URL. Summary links are relative to the downloaded artifact; GitHub's
job summary does not host the viewer.

These scripted results establish that the harness can drive and score the API.
The **Agent evaluations** workflow runs the same cases with a plain tool-calling
DeepSeek Flash agent. Start it on `main`, choose the repeat count and batch budget,
then read the workflow summary. Incorrect task results are measurements; missing
usage, infrastructure errors and incomplete cleanup fail the run. Every trial
remains in the artifact. Paid work never runs automatically on a pull request.

Configure `DEEPSEEK_EVAL_API_KEY` as a repository secret. The workflow can reuse
`AI_REVIEW_API_KEY` when review uses the standard DeepSeek endpoint. Only the
unprivileged evaluator receives the key; the daemon and sandbox commands do not.
Rerunning an existing paid workflow is disabled: inspect its ledger and start a
new run explicitly. Non-main refs, other providers, automatic baseline comparison,
scheduled runs, Poketto MCP tasks and creator QA remain under the
[evaluation proposal](../notes/proposed/2026-10-28-agent-evaluation-entrance.md).

## Cases and scoring

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
request limit, bounded output, twelve turns per sample and a thirty-minute
controller deadline also bound the work. Model calls use text and client-side
native tools only; no provider search, fetch or other separately billed tools are
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
  --output /var/lib/sandcrab-evals/results
```

The output directory must be new. Its ancestors and the virtual environment must
be readable by the `daemon` client account; source files are copied into the
root-owned fixture. Keep every attempt in a separate directory. The harness never
falls back to an unrestricted host subprocess for a sandbox command.

For a paid local run, supply `DEEPSEEK_API_KEY` through the environment, preserve
only that variable through sudo, and add `--mode model --epochs 3 --budget-usd 1.00`.
Keep the key out of arguments, cases and artifacts. Inspect the complete ledger
after any interrupted run before authorizing another batch.
