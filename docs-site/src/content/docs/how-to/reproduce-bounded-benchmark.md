---
title: Reproduce the bounded local benchmark
description: Run the checksum-bound BonVoyage installation benchmark without making a capacity or competitor claim.
---

Use this workflow after the Docker quickstart passes. It sends a short,
fixed HTTP/1.1 workload through BonVoyage to the controlled upstream and
produces independently verified evidence.

This is an installation and tooling reproduction check. Because all three
roles share one Docker host and kernel, its result is **not** a production
capacity, dedicated-hardware, cost-saving, or competitor comparison claim.

## Before you begin

You need:

- a clean committed BonVoyage checkout;
- Node.js 22 or newer;
- Docker with Compose v2; and
- the local Compose stack running and passing `make verify-local-deployment`.

Start the stack in one terminal:

```sh
docker compose -f deploy/compose/local.yml up --detach --build
make verify-local-deployment
```

The benchmark refuses a dirty source tree, ambiguous Compose roles, restarted
containers, a wrong response body, non-200 traffic, missing metrics, weak
resource sampling, or an existing runner-container name.

## Run the reproduction

Create a new evidence path **outside** the checkout. Supply a path that does
not already exist:

```sh
evidence_parent="$(mktemp -d)"
export BONVOYAGE_BOUNDED_BENCHMARK_EVIDENCE="$evidence_parent/evidence"
make run-bounded-benchmark
```

The run performs three repetitions. Each repetition has a five-second warmup
and a ten-second measurement with 32 closed-loop HTTP/1.1 connections. The
client waits for requests already in flight when the measurement deadline is
reached.

An accepted run prints its source commit, median successful RPS, p95 and p99.
It retains:

- the raw HTTP response used to verify the exact 256-byte payload;
- raw warmup and measurement output from the digest-pinned `oha` image;
- gateway metrics before and after each measurement;
- CPU and memory observations for gateway, load generator and upstream;
- immutable container identities and restart counts;
- a command journal, environment record and derived summary; and
- a SHA-256 manifest covering the complete contracted inventory.

## Replay the verifier

You can independently replay evidence admission:

```sh
node scripts/verify-oss-bounded-benchmark.mjs \
  --evidence "$BONVOYAGE_BOUNDED_BENCHMARK_EVIDENCE"
```

The verifier derives successful RPS and p50, p95, p99, p99.9 and maximum
latency from the raw client output. Only HTTP 200 responses count as success.
Gateway request, response and upstream-selection counters must match the
client result exactly, selected error counters must stay at zero, and neither
runtime role may restart.

## Stop the stack

The benchmark removes only the load-generator containers it creates. It does
not stop or replace the local gateway or upstream. When you are finished:

```sh
docker compose -f deploy/compose/local.yml down --volumes
```

Retain the evidence directory if you need to compare an installation later.
Do not present this single-host result as a public capacity or competitive
performance result.
