# OSS release bundle contract

The initial BonVoyage OSS release surface is deliberately limited to Linux
AMD64:

- one native Debian package; and
- one OCI image archive whose selected manifest is Linux AMD64.

`oss-1.0-contract.json` defines the minimum release gates for both artifacts.
`scripts/verify-oss-release-bundle.mjs` verifies a complete offline bundle and
rejects missing, changed, linked, unbound, or unexpected files. It also binds
every gate receipt to the selected source commit and, for artifact gates, the
exact artifact digest.

## Trust boundary

The bundle verifier composes already-produced gate receipts. It does not build
the gateway, validate SBOM schemas, scan dependencies, verify Sigstore
cryptography, or generate provenance by itself. The protected hosted release
workflow must run those tools and create their receipts. The verifier then
proves that the exact receipts and evidence were packaged together without
substitution.

Passing technical gates does not automatically authorize publication. The
technical `release-manifest.json` is finalized first and contains no mutable
publication decision. Publication requires a separate
`publication-authorization.json` directory, its externally retained SHA-256,
and `--require-publishable`.

The authorization envelope binds the exact technical-manifest and release-
contract digests. It contains one cryptographically signed statement from an
authorized RouteSphere `release-owner`. The statement is signed with an
Ed25519 key pinned by the canonical contract, identifies the approver, observes
the bounded review-age policy, and references checksum-bound technical
evidence. The verifier accepts only canonical printable ASCII identities and
canonical SPKI public-key PEM.

The release-owner statement must bind a separate rights record in which all 12
ADR 0099 approval gates are `APPROVED` and each gate binds at least one retained
evidence file present in the private authorization inventory. Those records are
not published merely to prove the release. Re-checksumming the envelope cannot
forge the owner signature, reuse an approval against another manifest, or turn
an unresolved rights gate into publication authority.

Every role statement signs the envelope creation and expiry times. The current
contract limits authorization lifetime to 24 hours; strict publication checks
that lifetime against the verifier's clock. Security-sensitive JSON must use
deterministic bytes and timestamps must use canonical millisecond UTC form. The
verifier hashes and parses the same retained snapshots, then repeats both file
trees and the contract before returning so an in-run replacement fails closed.
Large artifacts are stream-hashed and only bounded control documents are kept
in memory.

The production CLI pins the canonical contract digest and does not accept a
caller-selected contract. The contract has one active RouteSphere
`release-owner` public key. Activation proves only which key may sign; it does
not approve any rights row, admit an artifact or authorize publication. The 12
completed rights decisions, protected release controls and exact technical
evidence remain mandatory. Architecture, security and documentation reviews
remain required technical evidence, but they are not represented as additional
corporate publication signers. Targeted counsel is obtained when an unresolved
ownership or licensing question requires it; a generic legal signature is not
manufactured as a mechanical release gate. The exported test helper can
exercise generated fixture keys, but always labels its result `TEST_ONLY_PASS`
and forces `publishable: false`.

The private founder release process includes a tested owner-identity tool for
the initial ceremony. It creates an encrypted Ed25519 key outside Git, emits a
public-only activation record, applies that public identity consistently to all
three owner trust contracts and updates this verifier's pinned contract digest.
Initial activation is rejected unless every policy is still pending with an
empty key list. The tool does not approve rights or authorize publication.

Technical admission therefore uses:

```bash
node scripts/verify-oss-release-bundle.mjs \
  --bundle RELEASE_BUNDLE \
  --manifest-sha256 TECHNICAL_MANIFEST_SHA256
```

After trust activation, strict publication additionally supplies the separate
authorization package:

```bash
node scripts/verify-oss-release-bundle.mjs \
  --bundle RELEASE_BUNDLE \
  --manifest-sha256 TECHNICAL_MANIFEST_SHA256 \
  --authorization PUBLICATION_AUTHORIZATION_DIR \
  --authorization-sha256 PUBLICATION_AUTHORIZATION_SHA256 \
  --require-publishable
```

## Hosted technical-candidate intake

`oss-candidate-intake-contract.json` and
`scripts/intake-oss-release-candidate.mjs` provide the narrow handoff from the
two hosted reproducibility workflows into later release gates. The intake
requires one clean tagged public commit, distinct Debian and OCI workflow runs,
two isolated builders per format, byte-identical outputs, exact hosted receipt
bindings and successful compiled tests. It rejects links, extra files, mixed
runs, changed receipts, changed payloads and every release or publication
claim.

Run the intake only with separately downloaded GitHub Actions artifacts:

```bash
node scripts/intake-oss-release-candidate.mjs \
  --deb-root DOWNLOADED_DEBIAN_ARTIFACTS \
  --oci-root DOWNLOADED_OCI_ARTIFACTS \
  --output NEW_PRIVATE_INTAKE_DIRECTORY \
  --source-commit FULL_COMMIT \
  --source-tag v1.0.0-rc.N \
  --deb-run-id DEBIAN_RUN_ID \
  --oci-run-id OCI_RUN_ID \
  --created-at 2026-10-30T05:00:00.000Z
```

The output retains one verified copy of each candidate, all non-payload
evidence and a canonical checksum-bound intake receipt. The tool has no network,
signing, upload, GitHub Release, package-publication or container-publication
authority. A passing intake is therefore reproducibility evidence, not a
release.

Historical candidate `v1.0.0-rc.6` passed this intake, but it predates the
protected `.github/workflows/release.yml` identity required by the keyless
signature contract. Its immutable tag will not be moved or retroactively
relabeled. The first candidate eligible for signing and complete admission must
be created from a later commit that already contains the reviewed release
workflow.

## Dual-SBOM and vulnerability evidence handoff

`oss-supply-chain-evidence-contract.json` and
`scripts/intake-oss-supply-chain-evidence.mjs` define the offline handoff from
an exact candidate intake to a retained, non-admitting evidence set. The review
root contains one physical vulnerability database shared by all four scans.
For each Debian and OCI candidate, the evidence directory contains exactly:

- CycloneDX 1.6 and SPDX 2.3 documents whose roots contain the exact candidate
  SHA-256, artifact kind, platform, source commit and source tag;
- decoded inventories from both formats plus command records bound to the
  candidate, documents, validator outcomes and decoded outputs;
- complete Grype reports for both formats, produced with the one retained
  database and no filtering, user ignores, VEX or suppressed matches; and
- a canonical, accountable review that covers every exact nonblocking finding
  and records zero unreviewed or unresolved High/Critical findings.

```bash
node scripts/intake-oss-supply-chain-evidence.mjs \
  --candidate-root VERIFIED_CANDIDATE_INTAKE \
  --review-root DOWNLOADED_SUPPLY_CHAIN_EVIDENCE \
  --output NEW_PRIVATE_SUPPLY_CHAIN_DIRECTORY \
  --source-commit FULL_COMMIT \
  --source-tag v1.0.0-rc.N
```

The adapter validates all input before creating output, streams large candidate
and database identities without buffering them into memory, and retains the
exact snapshots it inspected. It emits one checksum-bound
`supply-chain-evidence-handoff.json` with status `EVIDENCE_RETAINED`. It does
not emit release-gate PASS receipts. The adapter has no network or
product-signing authority and cannot create provenance, admit a release, upload
packages or containers, create or move a tag, create a GitHub Release, or
publish. Operator-authored JSON remains evidence for a later protected producer
to verify; it is not proof by itself that a tool executed. Run
`make oss-supply-chain-evidence-test` for the portable artifact-root,
database, reviewer, command, substitution, parity, freshness, severity and
authority regressions.

## Protected SBOM and vulnerability producers

`oss-supply-chain-producer-workflow-contract.json`,
`.github/workflows/oss-supply-chain-producers.yml` and
`scripts/verify-oss-supply-chain-producer-workflow.mjs` pin the protected
producer boundary. A manual run must start from a protected strict `v*` tag and
the exact public commit, with the protected-ref state verified at runtime. It
discovers, rather than accepts from the caller,
exactly one earlier successful `release.yml` candidate-intake run for that
same tag and commit.

`scripts/produce-oss-supply-chain-evidence.mjs` has three bounded operations:

1. `prepare-validator` retrieves the commit-pinned official SPDX 2.3 schema
   and prepares the hash-locked Python 3.12 validator environment;
2. `sbom` generates, validates, invalid-control tests and decodes CycloneDX
   1.6 and SPDX 2.3 for both exact candidate artifacts; and
3. `vulnerability` hydrates one official Grype database and then uses only
   that retained database for all four offline SBOM scans, after independently
   verifying the complete SBOM handoff inventory, checksums, roots, normalized
   package identities and parity.

The producer outputs deterministic reviewer inputs, not `review.json`. It
cannot replace the named release-security reviewer, suppress findings, apply
VEX, sign product artifacts, generate product provenance, admit a release,
create a GitHub Release, upload a package or container, or publish. The human
review and `scripts/intake-oss-supply-chain-evidence.mjs` remain subsequent
separate steps. Run `make oss-supply-chain-producer-test` for the complete
portable producer foundation.

## Protected candidate intake and keyless identity foundation

`oss-release-identity-workflow-contract.json`,
`.github/workflows/release.yml` and
`scripts/verify-oss-release-workflow.mjs` define the protected release workflow
boundary. The manual workflow accepts no caller inputs and must run from a
strict protected `v*` tag in the `release` environment. Repository contents
remain read-only.

Before requesting an identity token, the workflow uses
`scripts/discover-oss-release-candidate-runs.mjs` to find exactly one successful
run-attempt-one Debian workflow and one OCI workflow for the exact same tag and
commit. Those runs must predate the current release workflow. Six fixed
evidence artifacts are downloaded with job-scoped `actions: read`, then
`scripts/intake-oss-release-candidate.mjs` replays the existing byte, receipt,
source, test and authority checks. Duplicate, retried, mixed-source, future or
caller-selected runs fail closed.

Only the downstream identity-probe job receives `id-token: write`.

The workflow generates one fixed JSON identity probe bound to the public
repository, exact tag, commit and GitHub run. Pinned Cosign `v3.1.4` signs that
probe keylessly and immediately verifies the bundle against the exact
`release.yml@refs/tags/<tag>` subject, GitHub Actions issuer, repository,
commit, ref and manual trigger claims. The bounded evidence artifact expires
after three days.

This remains a candidate-intake and identity test, not product signing. The
workflow cannot accept a payload path, sign the Debian package or OCI archive,
generate product provenance, create a GitHub Release, upload packages or
containers, or assert release admission or publication. Run
`make oss-release-workflow-test` for the focused discovery, authority and
workflow-drift tests. Later reviewed checkpoints must add the remaining product
gates before any candidate is admitted or published.

## Protected product-signature evidence

`oss-product-signing-workflow-contract.json`,
`.github/workflows/oss-product-signing.yml` and
`scripts/verify-oss-product-signing-workflow.mjs` define the only authorized
product-signature identity. The manual workflow accepts no caller inputs and
must run from a strict protected tag after exactly one successful candidate
intake for the same tag and commit. The intake is downloaded by its discovered
run ID and revalidated before any signature is requested.

Only the signing job receives `id-token: write`. It signs the exact retained
Debian and OCI candidate bytes with pinned Cosign `v3.1.4`, verifies both
bundles online and offline, and emits a checksum-bound signing receipt. A
separate job with no OIDC permission downloads the same candidate and same-run
signature evidence, repeats both verification modes and emits the independent
verification receipt.

This checkpoint creates signature evidence only. It cannot generate product
provenance, admit or publish a release, create a GitHub Release, or upload a
package or container. Run `make oss-product-signing-test` for the discovery,
preparation, receipt, verifier and workflow-drift suites. The accepted product
signature subject is
`oss-product-signing.yml@refs/tags/<tag>`; an older immutable candidate cannot
acquire this identity retroactively.

## Required artifact gates

Each artifact must independently pass:

1. two-build reproducibility;
2. official CycloneDX 1.6 and SPDX 2.3 validation;
3. same-database vulnerability review with zero unreviewed or unresolved
   release-blocking findings;
4. hosted SLSA Build Level 2 or stronger provenance verification;
5. keyless Sigstore signature verification against the RouteSphere release
   workflow identity;
6. bounded functional acceptance; and
7. install, upgrade, rollback, shutdown, and removal lifecycle acceptance.

Global receipts bind clean pushed source, company rights authorization and the
immutable build/toolchain inputs. Raw evidence, gate receipts, artifacts and
the embedded release contract must account for every file in the bundle.

## Public Debian technical-candidate path

The public native path is deliberately separate from the historical private
rehearsal builder:

- `packaging/release/debian/oss-deb-input.schema.json` defines the source and
  artifact input contract;
- `packaging/release/debian/oss-deb-toolchain.schema.json` defines the complete
  Ubuntu builder lock;
- `scripts/capture-oss-deb-toolchain.py` records the running builder environment;
- `scripts/create-oss-deb-input.py` binds reviewed files to a clean tagged public
  source checkout;
- `scripts/build-oss-deb.py` assembles and verifies one technical candidate; and
- `scripts/verify-oss-deb-reproducibility.py` compares two candidate directories.

Run `make oss-deb-builder-test` on any development host for the portable contract
tests. Actual assembly must run in a digest-pinned Ubuntu 24.04 AMD64 builder.
The capture command records a caller-supplied image identity; the protected
workflow must independently prove that it launched that exact digest.

The builder requires a new output directory outside the source checkout. It
accepts only a clean `routesphere-global/bonvoyage` checkout whose `v<version>` tag and
commit timestamp match the input manifest. The resulting receipt always keeps
reproducibility, SBOM, scan, signature, provenance, lifecycle, release and
publication authority false. Compare two outputs before submitting their exact
artifact digest to the later hosted gates.

Every Debian candidate must carry the BonVoyage Apache-2.0 license plus the
release-facing third-party notice, source-availability record and complete
third-party license bundle under `/usr/share/doc/bonvoyage-gateway/`. The OCI
candidate carries the same disclosure set under `/usr/share/bonvoyage/`.
Artifact verification rejects either format when those files are absent or
changed.

## Native fresh-install evidence foundation

`debian/oss-native-fresh-install-contract.json` and
`scripts/verify-oss-native-install.py` define the independent admission boundary
for one disposable Ubuntu 24.04 AMD64 fresh installation. The evidence must bind
the exact package and clean public-origin build receipt, prove installation did
not start or enable the service, explicitly commission a reviewed snapshot,
route fixed and controlled-upstream traffic with exact metrics, retain one
process with zero automatic restarts, stop cleanly, remove package-owned files,
and retain operator state.

The reviewed snapshot is not caller-selected: the contract pins
`tests/fixtures/oss-native-fresh-install.yaml` and its deterministic `.pb`
artifact by path, size, digest, identifier and generation. The snapshot compiler
test reproduces the bytes from source.

The verifier checks six ordered phases and every raw evidence file by size and
SHA-256. It deliberately leaves upgrade, rollback, Kubernetes, benchmark,
release admission and publication false. Run
`make oss-native-install-verifier-test` for portable adversarial fixtures.

`scripts/collect-oss-native-install.py` is the fail-closed privileged runner for
that contract. It accepts exact caller-supplied digests, requires a pristine
disposable host and explicit state-retention acknowledgement, uses only fixed
argument-vector commands with timeouts, stages exact verified bytes in a
root-private temporary directory before invoking privileged package tools,
caps command output, filters listener evidence by process ownership, compares
the complete retained state inventory, drives the six phases, retains failed
attempts, and calls the independent verifier before reporting success. Its
controlled two-route source is
`tests/fixtures/oss-native-fresh-install.yaml`. Run
`make oss-native-install-collector-test` for portable safety coverage. The
collector candidate has not yet run on Ubuntu; fixture success is not native
installation evidence.

## Exact Gateway artifact lifecycle foundation

`oss-artifact-lifecycle-contract.json` and
`scripts/verify-oss-artifact-lifecycle.mjs` define the fail-closed evidence
boundary for the remaining Gateway package and OCI lifecycle requirement. The
contract pins `v1.0.0-rc.6` as the immutable rollback baseline, including its
source commit, protected Debian and OCI hosted-build run IDs, artifact byte
counts and SHA-256 identities.

The future hosted execution has two non-substitutable lanes. A fresh lane must
install or start the exact candidate on a pristine Ubuntu 24.04 AMD64 runner. A
transition lane must begin with the exact pinned baseline, move to a strictly
newer and byte-distinct candidate, prove candidate traffic and state, roll back
to the baseline and prove baseline traffic and state, reactivate the candidate,
then stop and remove it cleanly. Debian and OCI retain separate ordered phase
and check sets. Reinstalling the same artifact cannot satisfy upgrade or
rollback.

Every observation must bind the candidate and baseline intake receipts, exact
GitHub Actions runner identity, run attempt one, and every raw evidence file by
path, size and SHA-256. The verifier rejects linked or extra files, changed
baseline bytes, mixed identities, phase drift, false checks, repeated attempts,
unbound evidence and any assertion of release admission, signing, provenance or
publication.

`oss-artifact-lifecycle-workflow-contract.json`, the byte-identical reviewed
template and active workflow, `discover-oss-artifact-lifecycle-runs.mjs`, the
three bounded collectors and `assemble-oss-artifact-lifecycle.mjs` add the
protected hosted runner foundation. The manual workflow accepts only a
protected strict tag newer than the rollback baseline, discovers exact
unexpired run-attempt-one Debian and OCI reproducibility artifacts, reconstructs
checksum-bound baseline and candidate intakes, and keeps the Debian fresh,
Debian transition and OCI transition lanes separate until final independent
verification. All jobs use Ubuntu 24.04, read-only repository and Actions
permissions, full action commits, short-lived evidence and a 155-minute total
job ceiling. The workflow cannot sign, attest, tag, publish or admit a release.

Run `make oss-artifact-lifecycle-test` for 46 portable verifier, discovery,
assembler, collector and workflow cases. These tests establish the runner's
safety contract; they do not execute package installation, OCI
start/replacement, upgrade, rollback, reactivation or removal on hosted Ubuntu.
No lifecycle gate, release gate or publication authority is granted until a
newer protected candidate has successful Debian and OCI reproducibility runs
and this hosted workflow passes against their exact artifacts.

## Protected hosted Debian contract

`debian/oss-deb-hosted-build-contract.json`,
`debian/oss-deb-reproducibility.workflow.yml` and the byte-identical active
workflow define the protected hosted boundary. The workflow is manual,
tag-only, environment-gated and limited to the public repository. The contract
and `scripts/verify-oss-deb-hosted-build.mjs` require all three external facts:

1. the public `routesphere-global/bonvoyage` repository exists;
2. its protected `release` environment and `v*` tag rules are verified; and
3. the public Linux AMD64 builder image is anonymously pullable, digest-pinned,
   and matches a separately reviewed registry/pull/inspection receipt.

The accepted `v1.0.0-rc.4` replay is GitHub Actions run `40928269331`; both
independent builders produced the exact Debian package SHA-256
`0f8c135e78d317b7c8fa10539f52388a73993ec896c21366ab9e5698ddc88554`.
This is hosted reproducibility evidence for that immutable candidate, not a
published product release.

The workflow permits a preflight, two independent build jobs, exact-byte
comparison and one downstream provenance job. Each build runs without container
network access, with a read-only root, dropped capabilities and no new
privileges. The provenance job revalidates the reviewed contract, downloads
only builder A's already-compared candidate, rechecks its receipt and bytes,
then creates GitHub-hosted SLSA provenance for that exact subject. Its separate
receipt and Sigstore bundle retain no product-signing or release authority.
Evidence expires after three days, and the total workflow budget is capped at
210 billable job minutes. Even a byte-identical, attested hosted result remains
a technical candidate: release admission, publication, product signing and
package/container upload all stay false.

Run `make oss-deb-hosted-contract-test` to replay its adversarial contract tests.
Changing the template, active workflow, builder identity or source boundary
requires a new reviewed candidate and cannot inherit this evidence.

## Offline public Debian builder-image foundation

`debian/oss-deb-builder-image-contract.json`, the `oss-deb-builder` Dockerfile
target and `scripts/oss-deb-builder-entrypoint.py` define the source-free Linux
AMD64 execution environment expected by both hosted build jobs. The image
contains pinned build dependencies and Debian packaging tools from Ubuntu
snapshot `20261006T000000Z`; it contains no BonVoyage source or prebuilt
dataplane. At runtime it compiles the exact clean tagged public checkout, runs
the compiled CTest suite and emits only the package and powerless receipts.

Run `make oss-deb-builder-image-test` for the focused contract tests. Hosted
execution must additionally use no network, a read-only root, dropped
capabilities, `no-new-privileges`, an exact read-only source mount, separate
empty work/output mounts and a no-execute temporary filesystem. Git trust is
limited to the exact source mount; wildcard safe-directory configuration is
rejected.

The public source-free builder is pinned to
`ghcr.io/routesphere-global/bonvoyage-debian-builder@sha256:34c900a9678853d5985cd457568a9daa6d5e8290d894279184fbdc920d913111`.
Its registry manifest, anonymous pull and local image identity were verified on
2026-10-31. That verification proves the exact execution image is independently
retrievable; it does not grant license approval, release admission, signing,
provenance or product publication authority.

## Deterministic OCI technical-candidate path

The OCI path is separate from the ordinary development runtime image:

- `oci/oss-oci-image-contract.json` defines the exact Linux AMD64 manifest,
  runtime configuration and root-filesystem boundary;
- `oci/oss-oci-builder-image-contract.json` defines the source-free offline
  execution image and hardened launch controls;
- `scripts/build-oss-oci.py` assembles and verifies canonical OCI layout bytes;
- `scripts/oss-oci-builder-entrypoint.py` compiles and tests the exact mounted
  clean tagged public checkout before assembly; and
- `scripts/verify-oss-oci-reproducibility.py` compares two output directories
  and requires byte-identical archives and identities.

Run `make oss-oci-builder-test` for the focused portable contracts. A mechanical
builder execution must additionally use no network, a read-only root, dropped
capabilities, `no-new-privileges`, a read-only source mount, separate empty
work/output mounts and a no-execute temporary filesystem.

The public source-free OCI builder is pinned to
`ghcr.io/routesphere-global/bonvoyage-oci-builder@sha256:8be7cc0ab8db9b4f1f491ba0aa9df84b06f6b33ffc7640b314ded72be288e861`.
Its registry manifest, anonymous pull and local image identity were verified on
2026-10-31. That verification establishes the independently retrievable
execution image only; it does not make a BonVoyage runtime image publishable.

The assembler emits one deterministic gzip layer and one Linux AMD64 manifest.
It rejects unsafe paths and modes, links, special files, non-AMD64 ELF objects,
unexpected OCI members, changed descriptor sizes/digests, embedded configuration
or secrets and non-canonical metadata. The image runs as `65532:65532` and its
index reference is `ghcr.io/routesphere-global/bonvoyage:<version>`.

Two local executions may establish deterministic mechanics, but they do not
establish independent hosted reproducibility. Exact committed-source export
acceptance also does not establish a clean tagged public-origin artifact.
Builder publication, approved license rights, SBOMs, vulnerability review,
signing, provenance, lifecycle testing, release admission and publication are
separate gates and remain false in every builder receipt.

## Protected hosted OCI contract

`oci/oss-oci-hosted-build-contract.json` and
`oci/oss-oci-reproducibility.workflow.yml` define a manual, protected-tag-only
hosted replay. The active workflow must be byte-identical to that reviewed
template. It runs two isolated Linux AMD64 builds from the exact clean public
tag and compares the OCI archive, manifest, configuration and layer identities.

Both build jobs use the exact anonymously verified source-free builder digest,
no network, a read-only root, dropped capabilities, `no-new-privileges`, a
read-only source mount, separate work/output mounts and a no-execute temporary
filesystem. The comparison receipt is bound to the GitHub repository, tag,
commit, run and distinct uploaded evidence digests. Run
`make oss-oci-hosted-contract-test` for its adversarial contract tests.

After exact-byte comparison, one downstream job revalidates the contract and
builder A archive, then creates GitHub-hosted SLSA provenance for those exact
OCI archive bytes. The evidence is retained separately as a bounded receipt and
Sigstore bundle; it is not an OCI registry upload or a product signature.
Activation therefore does not make an OCI image publishable. SBOM admission,
vulnerability disposition, independent provenance verification, product
signing, lifecycle acceptance, release admission and upload remain separate
false gates.

## Current status

This contract is a release-admission foundation, not a release. The public
Apache-2.0 repository, protected candidate tags and release environment are
established. Protected GitHub Actions run `41042184197`, attempt 2, published
both source-free builder images from reviewed source commit
`f50fa24df37b22aea5459104c73e37ac9bd7ceb4`. Independent anonymous checks then
read each exact manifest and all referenced blobs: 30 Debian objects and 62 OCI
objects, with no failures. Earlier failed attempts remain diagnostic evidence
and do not satisfy this gate.

No result in this directory grants final artifact admission or publication.
The hosted Debian and OCI contracts can now create producer provenance for a
fresh candidate, but existing immutable candidates cannot acquire it
retroactively. A later release checkpoint must independently verify those
attestations against the exact retained candidate bytes. Final SBOM and
vulnerability disposition, product signatures, installation/lifecycle
acceptance and explicit release-owner approval remain separate requirements.
Existing local, private or differently bound evidence cannot be relabeled to
satisfy them.
