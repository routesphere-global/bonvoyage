# API Definitions

BonVoyage-owned Protobuf, gRPC, OpenAPI, and generation configuration live
here. The canonical Protobuf module is `api/proto`; no RouteSphere Core or
Envoy API is imported into the product contract.

The v1 contract separates:

- Immutable traffic configuration in `proto/bonvoyage/v1/config.proto`.
- Snapshot transport, capability negotiation, two-phase rollout, heartbeat,
  and ACK/NACK in `proto/bonvoyage/v1/discovery.proto`.
- Human-facing configuration under the repository-level `config/` directory.

The additive Phase 3 cluster contract includes bounded passive health, active
HTTP health, and DNS refresh. Active-health and DNS field numbers are part of
the v1 compatibility surface; generated Go bindings and the C++ build-time
bindings must be regenerated and checked together.

## Required contract workflow

Run from the repository root:

```bash
make api-lint
make api-breaking
make api-generate-check
make contracts-go-test
```

`api/buf.gen.yaml` pins the Go generation plugins. Generated Go bindings are
committed under `api/gen/go`; C++ bindings are generated into the CMake build
tree and compile-tested there. `api/baseline/bonvoyage-v1.binpb` is the checked
v1 wire-compatibility baseline. Change the baseline only as part of an
explicitly reviewed contract-version decision.

The 2026-10-27 company-namespace migration changed the generated Go package
option from `github.com/routesphere/bonvoyage` to
`github.com/routesphere-global/bonvoyage`. The baseline was rebuilt from its
existing descriptor with only those two file-option values changed. Its
SHA-256 moved from
`e45fa55d848a6e07ed3246e36f0ec85418e9d60c68a3c6978652abfdf2fe60c8` to
`c78dae91294dbca7590853efb0528b79ff8452ba4e36961e58c8ccfe21f72a9a`.
Protobuf package names, messages, fields, services and wire numbers did not
change; pinned Buf 1.47.2 lint, breaking and generated-source checks pass.

Phase 4 preserves the original delivery and acknowledgement fields for v1
wire compatibility. Nodes advertising the two-phase capability use explicit
prepare and activate commands. Rollback distributes retained exact bytes under
a newer sequence; it never mutates or re-labels an old rollout.

Checkpoint 8 adds `NodeIdentityService` without changing the snapshot stream.
`EnrollNode` accepts a node ID, one-use bootstrap token, local PKCS#10 request,
and bounded observation time. `RenewNode` accepts the currently authenticated
node ID and a replacement local CSR. Both return a public
`NodeCredentialBundle`; private key material is never part of the API.

Enrollment authorization is a deployment property of the separate
server-authenticated listener. Renewal authorization is the existing mTLS node
identity on the discovery listener. Callers cannot select an arbitrary SPIFFE
URI, issuer, validity period, or trust policy through these messages. Unknown
fields, over-limit inputs, identity disagreement, and unsafe time state fail
closed.

Checkpoint 9 adds the standalone machine-management contract at
`openapi/bonvoyage-admin-v1.yaml`. Checkpoints 10 and 11 extend it to ten
OpenAPI 3.1 operations covering:

- strict desired-state validation;
- deterministic semantic preview;
- preview-bound idempotent apply;
- selected and historical rollout status;
- bounded typed diagnostics;
- rollback preview; and
- exact retained-artifact rollback under a new sequence;
- explicit pre-activation cancellation; and
- paged integrity-bound rollout audit.

This HTTP API uses a separate TLS 1.3 mutual-TLS HTTP/1.1 listener and a fresh
fingerprint-pinned SPIFFE authorization document. It is not a browser, cookie,
bearer-token, file-upload, Git-clone, or shell-execution API. Apply and rollback
require an `Idempotency-Key`, expected selected sequence, expected active
artifact digest, and the exact preview fingerprint. The selected sequence is
persisted explicitly and shared with the discovery runtime; callers cannot
select role, actor, source channel, or an alternate coordinator.

The OpenAPI document is checked by
`cd website && npm run validate:project`. Live contracts are exercised by
`make phase4-admin-api`, `make phase4-safe-rollout`, and
`make phase4-operational-recovery`. The authenticated Prometheus endpoint is a
text exposition surface on the same Admin listener and is governed separately
by `observability/control-plane-telemetry-contract.yaml`.
