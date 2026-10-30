# Published SDK conformance

These independent consumers call OpenSandbox 1.1.0 through Sandcrab's
[optional adapter](../../executor-service/rust/sandcrab/opensandbox.md).
[python_client.py](python_client.py) uses the published Python SDK;
[SdkConformance.java](jvm/src/main/java/example/sandcrab/SdkConformance.java)
calls the published Kotlin SDK from Java. Neither depends on Poketto application
code or calls a model API. They verify the implemented adapter subset, not the
entire upstream SDK surface.

The [Evaluation preflight](../../.github/workflows/evals.yml) runs both consumers
on code changes and scripted manual runs, before Inspect. It uses a separate
Python environment and retains the JSON SDK receipt with the evaluation artifact.
Paid model runs skip SDK conformance and keep their model evidence separate.

Install [requirements.txt](requirements.txt) in a dedicated Python environment.
Build the JVM client from the repository root:

```sh
./gradlew -p evals/sdk/jvm spotlessCheck installDist checkstyleMain
```

The JVM project locks its dependencies. The controller verifies these published
artifacts before running the JVM client:

| Artifact | SHA-256 |
|---|---|
| `sandbox-1.1.0.jar` | `cb96348a273124a899586e23abe9b5aeafcc98b1d6055532a62ecc8a2a22a392` |
| `sandbox-api-1.1.0.jar` | `4cc5236a3c69d4328a8e80754fe0ccf47bddea10a0eaecd5dd01ba299bb87e45` |

On a prepared Linux host, run
[opensandbox_probe.py](../../executor-service/rust/sandcrab/opensandbox_probe.py)
as root with `--binary`, `--tools`, `--python`, `--java`, `--jvm-libs` and a fresh
`--report` path. Pass absolute paths; `--jvm-libs` selects the generated
`evals/sdk/jvm/build/install/sandcrab-sdk-conformance/lib` directory. Keep the
Python environment readable and executable by the fixture's ordinary client
account. The controller creates its own bounded units and temporary credentials,
runs both clients without root, checks effective kernel limits and native record
cleanup, and verifies containment before removing its fixture.

The receipt pins the [specification revision](https://github.com/opensandbox-group/OpenSandbox/tree/b1a29cf93a823a95913f7943010febb3f29de05c/specs)
and records binary, probe and Python-client hashes, JVM artifact hashes, client
checks and cleanup. Failed attempts keep their receipts and separate
operator diagnostics. Use a different report path for every attempt. Supplying
only `--python` runs the Python client alone and cannot establish JVM support.
The harness also exercises credential scope, reused native identities,
disconnects, timeout, cancellation, directory management, literal replacement,
glob search, byte and line selections,
and file refusal paths against the same
service. No result establishes production adoption or model usability.
