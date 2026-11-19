# Unified release versions

Date: 2026-11-18

## Decision

One stable tag identifies the Linux service, container image and both SDK distributions. Independent SDK releases previously gave callers different version numbers for the same service. A compatibility table would need continuing maintenance during a phase that promises no backwards compatibility. An SDK-only fix therefore advances every artifact. Each SDK warns on discovering a different advertised service version and keeps diagnostic and recovery operations available.

GitHub Releases, PyPI and npm accept uploads independently. The registered [tag workflow](../../.github/workflows/publish-sdks.yml) verifies the packaged SDK examples against the candidate archive, publishes the service and reconciles each registry against its accepted files. Identical bytes make a retry safe. A mismatch stops publication. The top-level workflow retains its trusted publisher identity with [npm](https://docs.npmjs.com/trusted-publishers/) and [PyPI](https://docs.pypi.org/trusted-publishers/troubleshooting/).

A failure in a tagged publication command can outlive the workflow revision that caused it. The [recovery check](../../scripts/release_recovery.py) lets trusted main resume a completed tag run by matching the original SDK artifacts to the same commit and published release. It selects only the files each registry still needs. The [release reference](../../README.md) owns the operator steps.

## Verification

The [v0.4.0 tag run](https://github.com/core607/sandcrab/actions/runs/44417547094) published the service and PyPI distributions. The [recovery run](https://github.com/core607/sandcrab/actions/runs/44422636353) completed npm publication, read back the accepted distributions and installed both SDKs from their public registries. The historical npm staging version carries a [deprecation notice](https://registry.npmjs.org/sandcrab/0.0.0-stage) directing users to the stable release.
