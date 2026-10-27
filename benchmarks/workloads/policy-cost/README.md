# Phase 5 policy-cost workloads

`phase5-policy-cost.json` freezes the first realistic policy-cost matrix after
the four baseline profiles. It separates policy execution from response-body
delivery by measuring 256-byte and 8 KiB controlled responses.

The matrix deliberately distinguishes three security semantics:

- BonVoyage static API-key admission computes an HMAC-SHA256 digest of the
  presented API key and performs a prepared shard-local lookup. It does not
  sign or authenticate the HTTP payload.
- BonVoyage JWT admission verifies an RS256 token and its configured claims.
  The payload in this matrix is the controlled upstream response, not a JWT
  request-body binding.
- Vanilla OSS NGINX can match header transformations, but it cannot provide a
  native JWT comparator. Any future JWT comparison must pin and disclose the
  exact extension and its configuration.

Every accepted run uses the structured Phase 5 client. Generic request headers
are supplied through a regular JSON file, hashed into schema-version-4 evidence,
and excluded from retained output. Framing and hop-by-hop headers are rejected.
JWT tokens are generated immediately before each attempt and the exact header
file digest is bound to that attempt.

The initial matrix uses TLS 1.3/AES over HTTP/1.1 to isolate policy cost. HTTP/2
policy combinations belong to PERF-05 after the HTTP/1.1 costs are understood.

The clean-source AWS semantic preflight is executed by
`benchmarks/scripts/phase5-policy-semantic-preflight.sh`. It validates 12
BonVoyage allow/reject outcomes across all six profiles and three equivalent
NGINX allow outcomes. The runner restores the package service and pre-existing
upstream containers before reporting success. Private CA keys, API keys, JWT
private keys, tokens and request configuration files stay in temporary storage;
retained evidence contains response artifacts, safe identities and checksums.
This preflight proves behavior only and cannot authorize a performance claim.

## Directional cost contract

`benchmarks/scripts/phase5-policy-cost.mjs` freezes the first bounded
measurement pass. It schedules one 24-core repetition for seven points:
`P5-B02`, the 256-byte plain control, followed by `P5-C00` through `P5-C05`.
Every policy point is compared only with a control having the same response
payload and offered rate. This deliberately avoids another paid 8/24-core
matrix on noisy shared virtual machines; the full scaling and repetition gate
remains deferred to stable physical topology.

The result contract binds clean source, binary and support artifacts, snapshot
digests, private three-role topology, CPU placement, active `irqbalance` with a
gateway CPU ban, TLS identity, request-artifact identity, process continuity,
support-role headroom, RSS and descriptor deltas. It records successful RPS,
p50/p95/p99 with p99.9 as reference, application/host/IRQ CPU, cycles,
instructions, IPC, allocations, syscalls, socket writes, bytes per write, queue
waits and every shard's CPU. Response counts and the bounded active measurement
duration must reproduce successful RPS; instructions and cycles must reproduce
IPC.

The analyzer verifies every referenced evidence file and returns only one of
`incomplete`, `product-failure`, or `directional-complete`. Invalid attempts
remain retained but cannot replace the planned repetition. Support-role
saturation makes the evidence incomplete rather than blaming BonVoyage; an
observed correctness, latency, delivery, process, error, or resource failure
remains a product failure. Every plan, result and summary contains
`publication_authorized: false`; this bounded pass can identify policy-cost
candidates, but cannot establish competitive, Dedicated Host, scaling,
repeatability or public benchmark claims.
