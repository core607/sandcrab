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

The workflow summary lists every case and all attempts. Its artifact contains
the machine-readable summary, complete Inspect log, static transcript viewer and
fixture cleanup receipt. To browse the downloaded transcript, run
`python -m http.server --directory viewer` from the artifact directory and open
the local URL. Summary links are relative to the downloaded artifact; GitHub's
job summary does not host the viewer.

These are scripted baseline results, not agent success rates. They establish that
the harness can drive the native API and independently score its state. Model
runs, spend enforcement, model baseline comparison, scheduled runs, Poketto MCP
tasks and creator QA remain under the
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

The model solver is available in the task implementation, but the supported
runner enables only the scripted baseline. Inspect's per-sample cost threshold
requires explicit model pricing and can overshoot by an in-flight call; it is not
a hard batch spend cap. A paid entrance must enforce the proposal's budget before
it is enabled. No workflow receives provider secrets.

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
