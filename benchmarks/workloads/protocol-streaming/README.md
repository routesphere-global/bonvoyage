# PERF-05 protocol and streaming catalog

`phase5-protocol-streaming.json` is the reviewed scope contract for PERF-05.
It separates TLS, downstream HTTP/2, end-to-end HTTP/2, unary gRPC, and
incremental SSE so that one protocol result cannot be used to imply another.

The catalog is intentionally not a benchmark result. It freezes the traffic
shapes, required measurements, correctness invariants, and excluded claims
before the live fixture and native runner are implemented. The deterministic
validator rejects accidental scope drift.

Run the contract tests with:

```sh
make benchmark-phase5-protocol-contract-tests
```

