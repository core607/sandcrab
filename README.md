# Sandcrab

Sandcrab is a Linux service for running code on the same machine as its caller.
Submit a single command, or open a bash session when a build, test or agent needs
a persistent workspace. Sandcrab ships a static x86-64 daemon and CLI with a
checksum-verified bubblewrap helper. The host needs cgroup v2 and user namespaces.

## Quickstart

On Ubuntu 22.04, Ubuntu 24.04 or Debian 12, download the ZIP from the
[v0.1.1 release](https://github.com/core607/sandcrab/releases/tag/v0.1.1) using an
account with repository access. An authenticated GitHub CLI can download it directly:

```sh
gh release download v0.1.1 --repo core607/sandcrab --pattern sandcrab-linux-x86_64.zip
```

From a root shell on the systemd host, run the last two commands below in the
directory containing the ZIP. For unattended installation, supply a short-lived
authorized asset URL in `SANDCRAB_BUNDLE_URL` and run all three commands.

<!-- sandcrab-quickstart -->
```sh
curl --fail --silent --show-error --location --output sandcrab-linux-x86_64.zip "$SANDCRAB_BUNDLE_URL"
python3 -I sandcrab-linux-x86_64.zip
/var/lib/sandcrab-release/sandcrab run --socket /var/lib/sandcrab/runtime/control.sock --profile default -- python3 -c 'print(6 * 7)'
```

The last command returns a JSON record with `state` equal to `succeeded` and
`42` in `result.stdout`. The installer creates the execution account, local service
and private token. The [installation guide](crates/sandcrab/install/README.md)
covers diagnosis and the [container quickstart](crates/sandcrab/install/README.md#standalone-container).

## Choose a client

Use the CLI or native HTTP API for commands, files, sessions and immutable templates.
The installed service also supports published Python and Kotlin OpenSandbox clients.
Applications can handle domain-specific actions with optional opaque host calls.
See the [native reference](crates/sandcrab/README.md), [OpenAPI](crates/sandcrab/openapi.json),
[SDK contract](crates/sandcrab/opensandbox.md) and [host-call guide](crates/sandcrab/host-calls.md).

```sh
curl --fail --unix-socket /var/lib/sandcrab/runtime/control.sock http://localhost/v1/info
bash examples/sandcrab-build-test.sh
python3 examples/sandcrab-batch.py first.py second.py
```

The [Python](examples/sandcrab-sdk.py) and [Kotlin](examples/sandcrab-sdk.main.kts)
examples create a sandbox, run code and release it. The [threat model](THREAT-MODEL.md)
describes profile selection, credential scope and egress.

## Build and test

From the repository root, use the pinned Linux build environment.

```sh
docker build --target release --output type=local,dest=build/bin .
docker build --target check .
python3 crates/sandcrab/conformance.py --list
```

The release contains the executables, installer ZIP, SHA-256 manifest, threat model
and the helper's notices and source. The [conformance runner](crates/sandcrab/README.md#verification)
exercises real Linux sandboxes. [Inspect evals](evals/README.md) test agent use of the API.
The [density benchmark](benchmarks/density/README.md) measures a reproducible workload.

Maintainers can test a released ZIP against a reviewed commit on a public consumer's own
branch. Add the repository to the JSON array in the `SANDCRAB_DOWNSTREAM_REPOSITORIES`
Actions variable. The consumer provides `.github/ci/sandcrab-release-check.sh`, receives
the ZIP in `SANDCRAB_BUNDLE`, and writes test output under `SANDCRAB_EVIDENCE`. The receipt
records the tested commit, archive digest and result. [Downstream release check](.github/workflows/downstream-release.yml)

Sandcrab is licensed under [Apache 2.0](LICENSE). The separate bundled helper and
its dependencies retain their [upstream licenses and corresponding source](crates/sandcrab-launch/bwrap/README.md).
