# Unified Release Versions

Date: 2026-11-18

## Problem

The service ships as GitHub release archives through the release workflow. The
Python and TypeScript SDKs are published separately by a manually started
[workflow](../../.github/workflows/publish-sdks.yml), one registry per run. For the
v0.3.0 service release, PyPI carries `sandcrab` 0.3.0 while npm carries 0.3.0 and
0.3.1. The 0.3.1 npm package activated trusted publishing and corrected its README.
npm also lists a leftover `0.0.0-stage` version.

Before 1.0, releases identify commits without promising compatibility
([AGENTS.md](../../AGENTS.md)). A caller therefore needs to know exactly which SDK
matches which service, yet neither SDK README states it, and the version numbers
have already diverged.

## Proposal

This is an unimplemented design.

- Starting with the first common version above 0.3.1, the service archives and
  both SDK packages build from the same tag and carry that version. Existing
  registry versions remain historical.
- Run both SDK quickstarts against that tag's candidate service archive and SDK
  distributions before publishing. The release workflow calls the trusted SDK
  publishing workflow. On retry it verifies any published asset and package
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

Remaining design question: whether a mismatch warns or refuses before 1.0.

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
