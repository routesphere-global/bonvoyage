# Phase 3 Scale Fixture

This test-only Go program has two commands:

- `snapshot` generates deterministic BonVoyage v1 Protobuf snapshots containing
  up to 100,000 exact fixed-response routes.
- `hold` opens an exact number of HTTP/1.1 keep-alive connections, validates one
  response on every socket, exposes bounded readiness/summary/release controls,
  and releases all sockets on request or termination.

The fixture exists outside the production runtime and control plane. Its
snapshot command exercises the immutable runtime contract without changing the
security limits on human-authored YAML. Its holder uses ordinary TCP sockets so
the dataplane remains the only component under connection-density test.

Unit tests assert deterministic snapshot bytes and addressable route identities.
The live lifecycle, telemetry, RSS, active-progress, drain, recovery, image, and
evidence checks are owned by
`scripts/phase3-route-scale-connection-density.sh`.
