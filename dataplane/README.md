# Dataplane

The BonVoyage dataplane is an independent C++20 service built on Seastar. It
must not link RouteSphere Core, RouteSphere OTT, Envoy runtime, xDS, or Envoy
filter libraries.

## Build

The supported Phase 0 build is the pinned Linux container build from the
repository root:

```bash
make dataplane-build
make dataplane-smoke
make dataplane-active-health-dns-smoke
```

The smoke test starts one Seastar shard with bounded memory, sends `SIGTERM`,
and requires a clean zero-status shutdown. Native builds are supported on a
Linux host with the pinned dependencies documented in Docusaurus.

## Source documentation

Public C++ interfaces and non-obvious lifecycle, ownership, concurrency, and
failure contracts use Doxygen comments. Implementation comments explain why a
constraint exists; they do not narrate straightforward code.

The Doxygen build treats malformed and missing public API documentation as an
error.

## Phase 4 snapshot lifecycle

The dataplane has a separate shard-local PREPARE slot for control-plane
artifacts. It verifies the exact digest and deterministic Protobuf bytes,
rejects unknown fields, checks compatibility and expected active identity, and
compiles the existing bounded `RuntimeSnapshot` on every shard. A node-level
success is possible only after all shards retain the same private artifact;
any shard failure clears matching private state without replacing the active
snapshot or changing traffic.

The lifecycle owner also provides node-local ACTIVATE and CANCEL barriers. It
fences new leases on every shard before allocation-free publication, lets
existing leases drain against one immutable old generation, and blocks another
activation until that generation can retire. Lease acquisition uses only a
plain shard-local counter; there is no request-path atomic or cross-shard
coordination.

The shipped Gateway and discovery client are not wired to this owner yet. See
[ADR 0049](../docs/architecture/decisions/0049-all-shard-snapshot-preparation.md),
[ADR 0050](../docs/architecture/decisions/0050-atomic-snapshot-activation.md),
and the [activation checkpoint evidence](../docs/implementation/phase-4-atomic-snapshot-activation.md).

## Bounded access logging

Request access logging is optional and disabled by default. Enable one
asynchronous JSONL sink per shard by providing an existing writable directory:

```bash
bonvoyage-dataplane \
  --snapshot /etc/bonvoyage/snapshot.pb \
  --access-log-directory /var/log/bonvoyage \
  --access-log-queue-capacity 8192 \
  --access-log-max-file-bytes 1073741824 \
  --access-log-flush-interval-ms 1000 \
  --access-log-sample-every 1
```

The runtime image uses UID/GID `65532`; mounted storage must be writable by that
identity. A full, unavailable, or slow destination causes observable record
drops and never blocks gateway traffic. The `bonvoyage.access.v1` schema omits
paths, queries, authorities, client identity, credentials, headers, cookies,
and bodies. See ADR 0033 and the Phase 3 bounded access-log checkpoint for the
complete privacy, lifecycle, and qualification boundaries.
