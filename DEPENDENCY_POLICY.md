# Dependency policy

BonVoyage treats every dependency as part of its correctness, security,
performance, licensing, and operational surface. Convenience alone is not a
reason to add runtime code.

## Admission requirements

A dependency proposal must identify:

- its purpose and accountable maintainer;
- the exact source, version, immutable commit or image digest, and integrity
  mechanism;
- license and redistribution compatibility;
- project maintenance, vulnerability-response, and release history;
- request-path allocations, copies, syscalls, blocking behavior, threading,
  lifetime, and failure semantics where applicable;
- deployment, upgrade, rollback, and offline-build effects; and
- the tests and evidence that prove the dependency is necessary and correctly
  bounded.

Request-path dependencies receive performance and ownership review. Parsers,
cryptography, identity, networking, compression, policy, and serialization
dependencies also receive focused security review. Generated code does not
remove the need to review its generator and runtime.

## Version and patch control

- Go modules and npm packages remain locked by committed checksums or lockfiles.
- Container bases, downloaded tools, and Git source inputs use immutable
  digests or commits, not floating tags or branches.
- Local patches record their upstream source, purpose, checksum, affected
  version, test coverage, and intended removal or upstream path.
- Dependency updates are grouped and opened monthly to bound review and CI cost.
  Security updates may be opened sooner, but are never auto-merged.
- An update must pass the same correctness and relevant performance gates as the
  code path it changes.

## Release evidence

Each release regenerates and validates CycloneDX and SPDX SBOMs from the exact
artifact, then scans the artifact and both manifests using the recorded scanner
and database identities. A clean scan is time-bound evidence, not a guarantee
that no vulnerability exists.

A scanner error, stale or missing database, malformed SBOM, artifact mismatch,
or unexplained format disagreement fails the gate. Vulnerabilities are upgraded,
removed, mitigated, or documented with evidence. A VEX `not affected` decision
requires version, configuration, call-path, or reachability evidence; an
architectural assumption is not enough.

## Removal

Unused, unmaintained, legally incompatible, or unjustifiably expensive
dependencies are removed. Emergency replacement must preserve rollback and
must not bypass protocol, security, or lifecycle tests.
