# Public CI policy

The required `Public CI / Foundation` check is intentionally small, portable,
and predictable. It runs for pull requests to `main` and for intentional manual
dispatches. It does not run again on every push to `main`, on a schedule, or as
a release publisher.

The workflow:

- receives read-only repository contents permission;
- uses only GitHub-owned actions pinned to full commit identifiers;
- disables retained checkout credentials;
- never reads repository or environment secrets;
- never uses `pull_request_target` or a self-hosted runner;
- cancels superseded runs for the same pull request or ref;
- installs locked JavaScript dependencies without lifecycle scripts;
- runs the portable Go, Node.js, Python, formatting, and documentation gates;
  and
- has a bounded 25-minute timeout and no artifact upload or publishing step.

Fork pull requests therefore validate untrusted source without gaining write
authority, private credentials, package tokens, or access to RouteSphere
infrastructure. Repository settings must keep workflow tokens read-only and
must not send secrets to fork workflows.

Container, sanitizer, fuzz, protocol, package, SBOM, provenance, signing, and
release checks remain explicit local or protected-release gates. They are not
silently weakened to fit this cost-bounded workflow. Release automation may be
added only with the verified-release checkpoint, a protected environment, and
separate least-privilege review.

## Release candidate intake and identity boundary

`.github/workflows/release.yml` establishes the protected handoff from hosted
technical candidates into the later verified-release gates. It is manual,
strictly tag-bound and guarded by the `release` environment. A read-only intake
job discovers exactly one successful run-attempt-one Debian workflow and one
OCI workflow for the same tag and commit, downloads six fixed evidence
artifacts, and replays the existing fail-closed candidate intake. No caller can
provide run IDs, artifact names or payload paths.

Only the downstream identity-probe job receives `id-token: write`. It creates
and verifies a signature over a fixed generated identity probe. The workflow
cannot sign a caller-selected or product artifact, generate product
provenance, create a GitHub Release, upload a package or container, or authorize
publication.

The contract and `scripts/verify-oss-release-workflow.mjs` pin the complete
workflow boundary, candidate workflow identities, artifact names, action
revisions, Cosign version, evidence paths, timeout, retention and false
authority fields. Run `make oss-release-workflow-test` for the focused
adversarial checks.

The verified release contract requires product signatures whose subject is
exactly this workflow at `refs/tags/<tag>`. Existing immutable candidates,
including `v1.0.0-rc.6`, cannot acquire that identity retroactively and their
tags must not be moved.

## Protected supply-chain evidence producers

`.github/workflows/oss-supply-chain-producers.yml` is the next manual,
strictly tag-bound protected checkpoint. It discovers exactly one earlier
successful `release.yml` candidate intake for the same tag and commit. Callers
cannot choose a run ID, candidate artifact, payload path, scanner database or
output name. Runtime verification requires GitHub to report the selected tag
as protected and rejects skipped steps, error suppression, command folding or
any other uncontracted workflow field.

The SBOM job generates CycloneDX 1.6 and SPDX 2.3 documents for both retained
candidate artifacts. It validates each document with its separately pinned
validator, runs invalid-control checks, decodes both formats with the pinned
Syft image and proves normalized package parity. Every document root binds the
exact candidate bytes, artifact kind, platform, source commit and source tag.

The vulnerability job hydrates one official Grype database, retains that exact
database once, then performs four offline scans: both formats for both
artifacts. Before scanning, it rejects extra or linked evidence, verifies every
SBOM and decoded-inventory checksum, rechecks both candidate-root bindings and
requires exact decoded package parity. Checksum-bound private copies keep the
candidate, SBOM and database pathnames stable across tool execution. It emits
complete scanner reports and deterministic review inputs.
It deliberately cannot create the accountable human `review.json`; the
release-security reviewer must assess every finding separately before the
existing neutral evidence handoff can accept the set.

All three jobs run in the protected `release` environment with read-only
repository and Actions permissions. The workflow has no identity token,
secrets, signing, provenance, release, package, container or publication
authority. Producer artifacts expire after three days. Run
`make oss-supply-chain-producer-test` for the focused source-discovery,
producer and workflow-drift suites.

The hosted Debian and OCI workflows establish reproducible technical-candidate
bytes only. The first fully signable candidate must be cut from a later commit
that already contains this separately reviewed workflow and any subsequently
reviewed product-artifact gates. Passing candidate intake and the identity
probe is a distinct checkpoint and does not by itself authorize a product signature,
provenance statement, GitHub Release, package upload, container upload or
publication.

## Inactive Debian reproducibility candidate

`packaging/release/debian/oss-deb-reproducibility.workflow.yml` is a reviewed
workflow template, not an active GitHub workflow. It deliberately lives outside
`.github/workflows/`, so GitHub cannot dispatch it or consume Actions minutes.

The template defines two independent Ubuntu 24.04 builders, an exact-byte
comparison job, read-only permissions, a protected `release` environment,
three-day evidence retention and a maximum 200 billable job-minute envelope.
It has no publication, package-upload, signature or provenance authority. The
contract verifier rejects activation until the public repository exists, the
protected environment settings are evidenced, and a public Linux AMD64 builder
image is pinned and externally verified by digest. Only then may the exact
reviewed template be promoted to
`.github/workflows/oss-deb-reproducibility.yml` in a separate checkpoint.
