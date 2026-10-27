# HTTP/1.1 Keep-Alive

Baseline reverse-proxy workloads with 256-byte responses, persistent
connections, no TLS, and access logs disabled.

- `baseline.yaml` defines the open-loop operating curve used for comparative
  contract and schema fixture.
- `phase1-scaling.yaml` defines the closed-loop, per-core concurrency profile
  used to qualify BonVoyage's one-shard to two-shard scale-up in Phase 1. It
  uses 64 connections per gateway core, which preserves saturation throughput
  without adding enough client-side queue depth to exceed the p99.9 ceiling.
- `phase2-baseline.yaml` fixes the executable competitive profile at 64
  connections for both CPU allocations, five valid repetitions, and
  50/70/80/90/95 percent of each product's confirmed sustainable capacity.
  Holding concurrency constant isolates the effect of adding the second CPU;
  Phase 1 separately exercises the 64/128 per-core concurrency profile.

Connection churn uses the same request and response contract with keep-alive
disabled. Intentional overload is reported separately and is never used as a
sustainable-capacity point.
