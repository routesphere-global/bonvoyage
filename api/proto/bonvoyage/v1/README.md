# BonVoyage v1 Protobuf API

This directory is the canonical home of the BonVoyage v1 Protobuf contracts.

- `config.proto` defines immutable traffic snapshots.
- `discovery.proto` defines legacy snapshot delivery plus additive capability,
  heartbeat, two-phase rollout, and structured ACK/NACK behavior.

Human-authored YAML and JSON are control-plane inputs. The dataplane consumes
the serialized `Snapshot` artifact and never parses those human formats on the
request path.

Generated Go and C++ sources belong in build output and must not become a
second source of truth.

The dynamic v1 contract separates `PREPARE` from `ACTIVATE`. Preparation must
complete on every local shard and every required target before activation is
authorized. Snapshot SHA-256 binds exact bytes; rollback is a new monotonic
rollout of retained bytes. See ADR 0045 for replay, reconnect, cancellation,
drift, and node-local atomicity semantics.

`RouteMatch` carries exactly one path matcher plus bounded method, header, and
query-parameter predicates. The runtime revalidates and prepares those fields
even when a snapshot did not come from the current Go compiler. Semantics and
limits are governed by
`docs/architecture/decisions/0011-bounded-route-predicate-engine.md`.

`Cluster` carries one weighted load-balancing policy and an optional bounded
`PassiveHealthPolicy`. The dataplane owns mutable in-flight and ejection state
per shard; these values are configuration, not distributed health state. Both
the endpoint count and total endpoint weight are bounded to 4,096 per cluster.
Failure classification, bounds, and fail-closed behavior are governed by
`docs/architecture/decisions/0012-shard-local-load-balancing-passive-health.md`.
