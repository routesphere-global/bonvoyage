# Control Plane

The Phase 1 command validates the local desired-state YAML and compiles it into
the deterministic `bonvoyage.v1.Snapshot` protobuf consumed by the data plane.
It accepts one strict YAML document, rejects unknown fields and unsupported
Phase 1 features, and atomically replaces the output artifact.

From this directory:

```sh
go run ./cmd/bonvoyage-control-plane \
  -input ../config/examples/local.yaml \
  -output snapshot.pb
```

Validate without writing an artifact:

```sh
go run ./cmd/bonvoyage-control-plane \
  -input ../config/examples/local.yaml \
  -validate-only
```

The pre-release offline authoring adapter exposes the same compiler through a
strict machine-result contract:

```sh
go run ./cmd/bonvoyage-config validate \
  --input ../config/examples/local.yaml
```

Use `--stdin --source-id NAME` for explicit standard input. Validation is
read-only and offline: it does not contact a gateway or establish runtime ACK
or activation. The same command also implements fail-closed `format`, static
release-matched `explain`, redacted compiled-semantic `diff`, explicit
version-to-version `migrate`, and immutable-artifact `preview` operations.
Use `bonvoyage-config diff --baseline BASELINE.yaml --proposed PROPOSED.yaml`
to compare two accepted immutable snapshots without returning scalar values.
Run the `migrate` operation with `--input INPUT.yaml`,
`--from-schema-version 1`, and `--to-schema-version 1` to use the only
currently shipped no-change migration pair. Migration acceptance is not
semantic validation; validate its returned document separately. Use
`bonvoyage-config preview --input PROPOSED.yaml [--baseline BASELINE.yaml]` to
report the post-default artifact identity, resource counts, and optional
redacted semantic changes without contacting a gateway.

The Phase 4 contract-level rollout state machine lives in
`internal/rollout`. It proves prepare barriers, activation ordering, replay,
reconnect, cancellation, drift, and explicit rollback requirements without
claiming that gRPC distribution or dataplane activation already exist.

`internal/storage` is the Phase 4 standalone durable-lineage foundation. It
retains strictly valid desired-state bytes, deterministic content-addressed
snapshot artifacts, many-to-one compilation lineage, and monotonic rollout
intent in a private process-exclusive filesystem repository.

`internal/rolloutservice` binds the pure state machine to the durable event
journal. It persists accepted START, REPORT, RECONNECT, and CANCEL transitions
before releasing commands, rejects stale writers, verifies deterministic
replay at startup, fail-stops after persistence ambiguity, and requires fresh
node runtime reconciliation after restart.

`internal/discovery` binds that service to strict bidirectional gRPC. The
`serve-discovery` command now exposes the shipped TLS 1.3 mTLS listener, and the
native C++/Seastar discovery client consumes its PREPARE, ACTIVATE, and CANCEL
commands. Certificate-bound node identity, exact v1 capability negotiation,
one stream owner, receipt-side heartbeat deadlines, and bounded nonblocking
command queues remain mandatory.

Checkpoint 8 adds `internal/identity`, `internal/identityservice`, and
`internal/nodecredentials`. A separate server-authenticated enrollment
listener redeems one-use node/audience-bound tokens; renewal remains mTLS on
the discovery listener. Nodes generate private keys locally and publish
complete immutable credential generations before the dataplane performs one
controlled reconnect. Dynamic TLS trust and revocation reloads retain their
last valid generation and fail new authentication closed when revocation state
expires.

The standalone identity repository is process exclusive and single writer.
Issue enrollment tokens before starting `serve-discovery`; a live authorized
operator surface belongs to the Checkpoint 9 Admin API. HSM/KMS custody, HA
issuance, automated renewal scheduling, and fleet approval are not claimed.

The original command without a subcommand remains the one-shot local compiler.
