# Unified Release Versions

Date: 2026-11-18

## Problem

The service shipped as GitHub release archives. The Python and TypeScript SDKs
initially used separate manual runs of the package publisher. For the
v0.3.0 service release, PyPI carries `sandcrab` 0.3.0 while npm carries 0.3.0 and
0.3.1. The 0.3.1 npm package activated trusted publishing and corrected its README.
npm also lists a leftover `0.0.0-stage` version.

Before 1.0, releases identify commits without promising compatibility
([AGENTS.md](../../AGENTS.md)). A caller therefore needs to know exactly which SDK
matches which service. Independent releases allowed those numbers to diverge.

## Proposal

The tag workflow, package readback and SDK version warnings are implemented.
The first unified tag and retirement of the historical npm staging version are
still pending.

- Starting with the first common version above 0.3.1, the service archives and
  both SDK packages build from the same tag and carry that version. Existing
  registry versions remain historical.
- Run both SDK quickstarts against that tag's candidate service archive and SDK
  distributions before publishing. Publishing jobs run directly in the registered
  [tag entry point](../../.github/workflows/publish-sdks.yml). Both
  [npm](https://docs.npmjs.com/trusted-publishers/) and
  [PyPI](https://docs.pypi.org/trusted-publishers/troubleshooting/) bind publishing
  authority to the top-level workflow. On retry it verifies any published asset and package
  against the accepted artifact digest, resumes only missing targets and fails
  on a mismatch. Completion requires readback from all three destinations.
- `/v1/info` reports the release version beside its existing API version. Each SDK
  compares it with its own version and reports a mismatch before the first request.
- A correction to an SDK's published text ships as a patch release of every
  artifact, so version numbers never diverge.
- The `0.0.0-stage` npm version is deprecated with a message pointing to the
  current release.

Acceptance criteria:

- A tag produces service archives and both SDK packages with identical versions.
- An SDK connected to a service with a different version reports the mismatch.
- Each version published under this policy has a matching service release.
  When one registry succeeds and the other fails, a retry completes the same
  release without uploading the successful package again.

SDKs warn once per differing advertised service version during discovery.
This preserves access to diagnostic and recovery operations on mixed versions.

## Alternatives

- Version SDKs independently with a compatibility table. This is more flexible,
  but the table becomes another artifact to keep correct while compatibility is
  explicitly not promised.
- Keep manual publication. Registry versions can drift again and depend on
  someone starting the workflow for each registry.

## Consequences

An SDK-only fix requires a patch release of every artifact, and a release takes
longer because it waits for SDK acceptance. Callers can identify a matching pair
from one number.

## Verification

A release dry run builds every artifact from one tag and checks their versions.
SDK tests cover mismatch reporting against a native fixture. The downstream
release check consumes the published packages at the release version.
