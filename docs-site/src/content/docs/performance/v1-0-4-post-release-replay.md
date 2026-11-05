---
title: v1.0.4 post-release replay
description: What the release-matched installation, functional, comparative, policy, protocol, recovery, and observability campaign proved and did not prove.
---

The BonVoyage `v1.0.4` post-release replay followed the public installation and
configuration paths, exercised the claimed behaviors through traffic, and
measured matched BonVoyage and NGINX workloads where the semantics were
comparable. Failed setup and functional attempts were retained rather than
silently replaced with preferred runs.

This page is a bounded engineering summary. It does not convert shared-EC2
results into a universal performance ranking or a customer sizing guarantee.

## Release identity

| Subject | Identity |
| --- | --- |
| Public source | `v1.0.4` at `9c252fcc583641341b44ba5ca8b7434a6ff0a165` |
| Gateway Debian SHA-256 | `dd6f3f96af391c312e80576c53351f9be0e72950e07cc80b425989865464b6cd` |
| Gateway OCI SHA-256 | `94e1ddddcf37ef4677e6021b56b4de27730d2366e50e4fd5cbda25256ca24d39` |
| Console Debian SHA-256 | `a979c4f37349d0a456dcba31c674e5c5131e7525108912e690968b1d8421ef3b` |

The public [GitHub release](https://github.com/routesphere-global/bonvoyage/releases/tag/v1.0.4)
contains checksums, signatures, provenance, CycloneDX and SPDX SBOMs, and
bounded release evidence for the published artifacts.

## What was exercised

| Stage | Outcome | Bounded meaning |
| --- | --- | --- |
| A: public artifacts | 16/16 assets verified; native Debian, OCI, and Console paths executed on Ubuntu 24.04 AMD64 | Anonymous retrieval, identity verification, installation, startup, traffic, and cleanup were replayed. |
| B: functional replay | 17/17 cases passed | Release-matched routing, policy, protocol, recovery, and immutable-rollout behavior passed the bounded cases. |
| C: matched curves | HTTPS/1.1, HTTP/2, and bounded header-transform profiles retained | Correctness, tail latency, CPU, RSS, descriptors, and rejected points were evaluated at fixed offered rates. |
| D: policy cost | API-key, JWT, and composed-policy control/policy repetitions completed | Measures bounded policy cost; it is not a policy-capacity limit. |
| E: protocol lifecycle | HTTP/2, unary gRPC, WebSocket, and SSE cases completed | Confirms bounded negotiation and lifecycle behavior, not production-scale concurrency. |
| F: recovery | Upstream failure, overload admission, same-process recovery, and NACK/rollback/corrected activation completed | Confirms the tested failure and immutable-configuration transitions, not continuous-availability certification. |
| G: observability supplement | Prometheus and OTLP failure-isolation cases passed | Confirms bounded telemetry isolation and recovery; it creates no SLO, billing, or capacity claim. |

## Kubernetes lifecycle supplement

After the A-G release-matched campaign, the public `main` source at
`1ccf3cea29f43d467e0035610e302e67eb9c9994` completed a separate disposable
Kubernetes lifecycle replay on November 5, 2026. All 54 focused verifier and
runner tests passed, followed by six live phases: preflight, a two-replica
baseline, zero-unavailable configuration upgrade, malformed-candidate
rejection, exact rollback, and teardown.

The important operational result was containment: the malformed configuration
did not replace the accepted snapshot, both healthy replicas remained
available, and service traffic continued before exact rollback to the baseline.

This supplement is source-built evidence for the named public commit on
disposable `kind` with Ubuntu 24.04 AMD64. It is not an additional replay stage,
a tagged public-artifact installation result, a throughput or capacity result,
multi-node availability evidence, or release admission. See
[Verify a Kubernetes deployment](../../how-to/verify-kubernetes-deployment/)
for the public contract, commands, versions, and boundaries.

## Test conditions and acceptance

The campaign used shared AWS `c7a.8xlarge` instances in `ap-southeast-1` with
separate load-generator, gateway/comparator, upstream, and observability roles.
Only one gateway or comparator was active on the target host at a time.

The comparable Stage C profile used:

- 24 BonVoyage reactor shards or 24 NGINX workers on the same 24-CPU allowance;
- eight open-loop client lanes and two deterministic round-robin upstreams;
- TLS 1.3, a 256-byte response, matched keepalive intent, and no access log,
  compression, caching, or request/response buffering;
- exact status, body, protocol, and workload-specific header semantics; and
- three repetitions per directional point with rotated run order.

An accepted point required zero unexpected errors, timeouts, or semantic
failures; p95 and p99 at or below 500 ms; reconciled request counts; bounded
resource collection; and no relevant process restart or failed recovery.

Application CPU is accumulated application CPU-seconds divided by wall time.
It measures average core-equivalents consumed across the 24-CPU allowance; it
does **not** mean that only that many workers, shards, or CPUs participated.

A lower value means that the application consumed less CPU time during that
measurement. It is not, by itself, proof of greater efficiency or better
scaling. The latency and correctness gates must be read with it. At 480K both
systems passed, so NGINX's lower application CPU is a valid resource advantage
for that exact operating point. At 600K, NGINX's lower application CPU
coexisted with two p99 gate failures, so it cannot establish greater efficiency
at that point. The campaign did not instrument NGINX scheduler wait, locks,
internal queues, or per-worker saturation and therefore does not assign a root
cause to the tail widening.

## Header-transform workload at 480K

At 480,000 offered HTTPS/1.1 requests per second, both systems delivered all
172.8 million requests across the six measurements with zero errors, timeouts,
or semantic failures.

| Three-run median | BonVoyage | NGINX | Bounded reading |
| --- | ---: | ---: | --- |
| Successful RPS | 479,929.5 | 479,930.2 | Equivalent to the fixed offered rate; not capacity. |
| p95 | 1.367 ms | 1.335 ms | NGINX was 2.3% lower; both were far below the gate. |
| p99 | 31.709 ms | 29.711 ms | NGINX was 6.3% lower; every repetition passed. |
| Average application CPU | 22.12 core-eq | 13.97 core-eq | NGINX consumed less measured application CPU while both systems passed; a point-specific resource advantage, not a universal efficiency claim. |
| RSS | 601.2 MiB | 956.4 MiB | BonVoyage used 37.1% less RSS. |
| Descriptors | 3,943 | 5,225 | BonVoyage used 24.5% fewer descriptors. |

The outcome is intentionally not simplified into “one gateway won.” NGINX
retained slightly lower primary latency and consumed less measured application
CPU at this point; BonVoyage retained materially lower memory and descriptor
use.

## Supplemental 600K diagnostic

The 600,000 offered-RPS point was a supplemental shared-EC2 diagnostic outside
the frozen 20/40/60/80% curve. Across six runs, all 216 million requests
returned HTTP 200 with zero client errors, zero timeouts, and all exact header
semantics accepted. BonVoyage passed the p95/p99 gate in 3/3 repetitions;
NGINX passed in 1/3 because two repetitions exceeded 500 ms at p99.

| Three-run median | BonVoyage | NGINX | Bounded reading |
| --- | ---: | ---: | --- |
| Successful RPS | 599,899.2 | 599,787.9 | Fixed offered rate; not maximum capacity. |
| Tail-gate outcomes | 3/3 accepted | 1/3 accepted | NGINX repetitions 1 and 3 exceeded the p99 gate. |
| p95 | 2.180 ms | 256.919 ms | BonVoyage was 99.2% lower and stable across its three runs. |
| p99 | 189.934 ms | 745.333 ms | BonVoyage was 74.5% lower and stayed below 500 ms. |
| Average application CPU | 22.66 core-eq | 16.92 core-eq | NGINX consumed less measured application CPU, but failed p99 in 2/3 runs; lower CPU is not an efficiency result at this point. |
| RSS | 643.2 MiB | 959.0 MiB | BonVoyage used 32.9% less RSS. |
| Descriptors | 3,930 | 5,242 | BonVoyage used 25.0% fewer descriptors. |

BonVoyage p99 ranged from 183.125 to 199.782 ms. NGINX p99 ranged from
274.294 to 907.626 ms. The useful finding is the repeatable tail distribution
for this exact high-load workload, not a universal throughput claim.

The 600K result shows that NGINX's lower average application CPU coexisted with
non-compliant tails despite the same 24-CPU allowance. It does not prove why.
Claims about scheduler stalls, lock contention, kernel behavior, or an internal
scaling bottleneck would require separate profiling evidence.

## Policy, protocol, and recovery outcomes

- API-key, JWT, and composed-policy cases were compared against their own
  controls at fixed offered rates. They establish functional and directional
  policy cost, not the maximum policy capacity of either product.
- HTTP/2, unary gRPC, WebSocket, and SSE checks establish the recorded
  negotiation and lifecycle behavior. They do not establish streaming-gRPC or
  large-fan-out production limits.
- Rejected configuration, no-partial-activation, rollback, corrected
  activation, upstream failure, and overload recovery were observed without
  turning the private management surface into a public API claim.

## Observability failure isolation

The post-plan Stage G supplement exercised the exact `v1.0.4` image:

- Prometheus rules, shard readiness, rate decisions, and privacy checks passed.
- During Prometheus loss and 24 slow readers, traffic remained healthy and the
  selected-tenant canary failure stayed isolated; recovery required no gateway
  restart.
- During OTLP rejection and queue overflow, request traffic completed, drops
  and retry exhaustion were accounted, the queue returned to zero, and the
  gateway process did not change.

These observations support the design claim that telemetry consumers are
bounded and outside the request path. They do not establish zero trace loss,
universal collector compatibility, a contractual SLO, or billing accuracy.

## What you can conclude

The campaign supports these bounded conclusions:

1. The exact public `v1.0.4` artifacts can be independently identified and installed through the documented paths.
2. The tested routing, policy, protocol, immutable-configuration, failure, and telemetry lifecycles behaved as recorded.
3. At the matched 480K header-transform point, both systems passed; NGINX had slightly lower latency and consumed less measured application CPU, while BonVoyage used materially less memory and fewer descriptors.
4. At the supplemental 600K point, BonVoyage retained a substantially lower and more repeatable tail distribution while preserving the same successful request semantics. NGINX's lower measured application CPU did not translate into p99 gate compliance in two repetitions.
5. BonVoyage's reactor model consumed more measured application CPU at these points. That is not a cost-per-request or energy-efficiency win, but neither can a lower CPU value be called efficient when the associated latency objective is missed.
6. The separate public-main Kubernetes replay contained a rejected configuration candidate, preserved healthy traffic, and completed exact rollback across the bounded disposable lifecycle.

The campaign does **not** prove universal superiority, maximum capacity,
dedicated-hardware behavior, production sizing, infrastructure savings,
multi-node global quotas, production-scale SSE or streaming gRPC, or public
availability of the Enterprise management API.

Run the [bounded local reproduction](../../how-to/reproduce-bounded-benchmark/) to
verify your installation and tooling. That single-host workflow is deliberately
not a capacity or competitor benchmark. The broader outcome narrative is also
available on the [RouteSphere performance page](https://routesphere.global/performance/).

