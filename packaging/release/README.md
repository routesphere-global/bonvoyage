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

## Protected hosted Debian contract

`debian/oss-deb-hosted-build-contract.json` and
`debian/oss-deb-reproducibility.workflow.yml` define the next hosted boundary.
The YAML is intentionally stored outside `.github/workflows/`; it cannot run or
consume Actions minutes in its current location. The contract starts blocked
and `scripts/verify-oss-deb-hosted-build.mjs` rejects activation until all three
external facts are evidenced:

1. the public `routesphere-global/bonvoyage` repository exists;
2. its protected `release` environment and `v*` tag rules are verified; and
3. the public Linux AMD64 builder image is anonymously pullable, digest-pinned,
   and matches a separately reviewed registry/pull/inspection receipt.

The candidate permits two independent build jobs and a comparison job only.
Each build runs without container network access, with a read-only root,
dropped capabilities and no new privileges. Evidence expires after three days,
and the total workflow budget is capped at 200 billable job minutes. Even a
byte-identical hosted result remains a technical candidate: release admission,
publication, signing, provenance and package/container upload all stay false.

Run `make oss-deb-hosted-contract-test` to replay its adversarial contract tests.
Do not copy the template into `.github/workflows/` merely to test it; activation
is a distinct, evidence-bound checkpoint.

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

The current image is a local, unpublished foundation. Its local image ID and a
synthetic test-only package rehearsal do not prove a public GHCR digest,
approved license rights, clean committed BonVoyage source, hosted independence
or release admission. Do not activate the hosted template until those external
facts are separately evidenced.

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

## Current status

This contract is a release-admission foundation, not a release. The public
native package assembler has passed exact clean-source local acceptance, and a
source-free offline builder-image foundation has passed a bounded local
mechanical rehearsal. A deterministic OCI assembler and source-free OCI-builder
candidate have also passed a bounded local two-execution replay. Their
implementation is accepted in the exact clean private commit `25d8df02` and its
matching 854-file no-Git exports; one untouched export now occupies OSS staging
and passes complete-inventory verification. Hosted independent-build acceptance
remains pending. The builder image is not publicly published or externally
verified, and the synthetic rehearsals do not qualify release artifacts. The
repository also does not yet have its final public license, public origin and
release tag, clean tagged public-origin OCI artifact, active hosted release
workflow, signing identity, hosted provenance, final vulnerability disposition
or publication approval. Existing private package and scanner evidence cannot
be relabeled to satisfy these gates.
