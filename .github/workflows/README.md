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

## Manual builder image publication

`.github/workflows/oss-builder-publication.yml` is the narrow exception that
can upload the two source-free builder containers. It runs only by manual
dispatch from protected `main`, requires the main-only protected
`builder-publication` environment,
and accepts exactly one full source commit. The protected workflow definition
and requested builder source are checked out separately without retained Git
credentials.

The job builds only `oss-deb-builder` and `oss-oci-builder` for Linux AMD64,
checks the minimum fixed zlib version, exact powerless identity and empty
product-source locations before registry login, and gives every upload a
source, run and attempt-specific tag. The job-level package-write permission is
present throughout the protected job, while the registry token is passed to
Docker only for the bounded GHCR login. It cannot sign product artifacts,
create provenance, create a GitHub Release, or upload the BonVoyage product
package or runtime container. Registry digests must still be independently
observed and pinned in the reviewed builder contracts before any hosted
candidate workflow can use them.

The workflow contract and
`scripts/verify-oss-builder-publication-workflow.mjs` pin its trigger, source
input, action revision, environment, permissions, targets, zlib floor, command
surface and false product authority. Run
`make oss-builder-publication-workflow-test` for the focused adversarial checks.

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

This workflow's probe signature is not an accepted product signature. Existing
immutable candidates cannot acquire a later product-signing identity
retroactively and their tags must not be moved.

## Protected product signing and independent verification

`.github/workflows/oss-product-signing.yml` is the only workflow authorized to
create BonVoyage product signatures. It runs manually from a strict protected
tag after discovering exactly one earlier successful candidate intake for the
same commit. Callers cannot choose a run ID, payload path, bundle path or
artifact name. The signing job revalidates the entire intake and signs only the
checksum-bound Debian package and OCI archive with pinned Cosign `v3.1.4`.

The signing job verifies both bundles online and offline. A separate job with
no OIDC permission downloads the same candidate and same-run bundles, repeats
both verification modes and emits an independent receipt. Both jobs bind the
exact workflow subject, GitHub Actions issuer, repository, commit, protected
tag and manual trigger. The workflow uploads short-lived evidence only; it
cannot create provenance, admit or publish a release, create a GitHub Release,
or upload a package or container.

The contract and `scripts/verify-oss-product-signing-workflow.mjs` freeze this
boundary. Run `make oss-product-signing-test` for the portable adversarial
suites. The verified-release contract accepts only subjects under
`oss-product-signing.yml@refs/tags/<tag>`.

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
bytes and producer provenance. A fully signable candidate must be cut from a
commit that already contains these reviewed producer gates and the later
product-signing gate. Passing candidate intake and the identity probe remains a
distinct checkpoint and does not by itself authorize a product signature,
GitHub Release, package upload, container upload or publication.

## Protected hosted reproducibility candidates

The active Debian and OCI reproducibility workflows must remain byte-identical
to their reviewed templates under `packaging/release/`. Each workflow contains
a preflight, two independent Ubuntu 24.04 builders, an exact-byte comparison
and one downstream provenance job. All jobs use the protected `release`
environment. The build and comparison jobs inherit read-only repository
permissions; only the provenance job receives `id-token: write` and
`attestations: write` in addition to read-only contents.

The provenance job downloads only builder A's already-compared candidate,
revalidates its powerless build receipt and exact bytes, and invokes the pinned
GitHub attestation action for that subject. It retains a separate canonical
receipt and Sigstore bundle for three days. It cannot alter the candidate,
create a product signature, upload a package or container, create a GitHub
Release or admit publication. Each workflow has a maximum 210 billable
job-minute envelope.

Run `make oss-hosted-provenance-test`,
`make oss-deb-hosted-contract-test` and
`make oss-oci-hosted-contract-test` for the recorder and fail-closed workflow
contracts. Existing immutable candidates do not inherit this mechanism; a
fresh protected tag must execute both producer workflows before a later release
checkpoint can independently verify their attestations.
