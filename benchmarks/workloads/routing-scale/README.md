# Routing Scale

This workload qualifies immutable dataplane preparation and exact-path lookup at
1K, 10K, and 100K routes. It is a runtime-scale test, not an authoring-format
test and not a competitive benchmark.

The test-only fixture generates deterministic BonVoyage v1 Protobuf snapshots.
It does not relax the 1 MiB and 100K-node bounds on human-authored YAML. Every
snapshot must remain within the runtime's 16 MiB snapshot ceiling.

For each route count, the gate:

1. Generates and hashes one deterministic snapshot.
2. Starts one shard and waits for readiness.
3. Requires the configured-route gauge to equal the requested count.
4. Verifies the first, middle, last, and missing route positions.
5. Runs three 100,000-request fixed-response lookup samples at concurrency 64.
6. Records cold-container-to-ready time, RSS, RPS, p99, p99.9, metrics, logs,
   image identity, source hashes, and a graceful zero exit.

Run the combined route-scale and connection-density gate with:

```bash
BONVOYAGE_BUILD_PLATFORM=linux/arm64 \
  make dataplane-route-scale-density
```

Use `linux/amd64` on native x86-64. Local throughput is directional because the
gateway and load generator share Docker Desktop. Publication requires a
dedicated Linux campaign with isolated roles and a separate approval decision.
