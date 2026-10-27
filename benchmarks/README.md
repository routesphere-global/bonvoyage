# Benchmarks

Docker-based benchmark harness for comparing BonVoyage with Envoy, NGINX, HAProxy, and controlled upstream services under identical CPU and memory limits.

Core measurements: RPS/core, p50/p95/p99/p99.9 latency, CPU, RSS, connection
density, errors, context switches, and behavior near saturation.

The normative comparison rules are in
`contracts/benchmark-fairness.md`. Machine-readable workload,
environment, and result contracts live in `benchmarks/spec`; zero-valued files
under `benchmarks/spec/fixtures` validate the schema and are never performance
evidence.

The combined Phase 1-3 dedicated campaign is defined as a pre-execution contract
in `benchmarks/plans/dedicated-qualification-v1.yaml`. Project validation checks
that its 15 load profiles and 23 ordered test groups satisfy
`benchmarks/spec/dedicated-campaign.schema.json`. The human-readable test and
decision matrix is in
`docs/performance/dedicated-qualification-campaign.md`; AWS preparation,
execution, evidence retrieval, and teardown are in
`docs/performance/dedicated-environment-runbook.md`; authorized security testing
is in `contracts/dedicated-security-test-plan.md`.

`DQ-INFRA-001` has an executable fail-closed preflight. Its validation plan,
artifact lock, per-check records, exact-release validation receipt, and
decision report satisfy
`dedicated-validation-plan.schema.json`,
`dedicated-artifact-lock.schema.json`,
`dedicated-validation-check.schema.json`,
`dedicated-validation-receipt.schema.json`, and
`dedicated-preflight.schema.json`. Run the local audit without authorizing paid
infrastructure with:

```bash
make dedicated-preflight-check
make dedicated-preflight-candidate
```

Candidate mode exits successfully after producing a valid audit even when it
finds blockers. It never sets `allocation_authorized` to true. Strict mode is
the only authorization path and requires the exact artifact lock, validation
receipt, and a new output path through
`BONVOYAGE_DEDICATED_ARTIFACT_LOCK`,
`BONVOYAGE_DEDICATED_VALIDATION_RECEIPT`, and
`BONVOYAGE_DEDICATED_PREFLIGHT_OUTPUT`. Keep generated preflight evidence below
the ignored `benchmarks/results/local-archives` tree until the final retained
campaign set is reviewed.

Before campaign freeze, use `make dedicated-preflight-rehearsal` for an
explicitly approved ordinary three-instance rehearsal. It requires the same
clean pushed source, artifact lock, full 13-check receipt, hardening and
comparator evidence. Only pre-execution campaign freeze becomes a warning;
`allocation_authorized` remains false. Require the report's `status` to be
`ready`, not merely a successful command exit. The environment still needs
operator review. Dedicated qualification rejects a rehearsal preflight and
continues to require a frozen, ready strict report. The older accepted RC
receipt cannot be relabeled for a new tooling commit.

After the distributed harness rehearsal passes and the campaign is frozen,
the final clean pushed commit uses:

```bash
make dedicated-rc-images
make dedicated-artifact-lock
make dedicated-validation-check     # once for each planned check ID
make dedicated-validation-receipt
make dedicated-preflight
```

The full environment sequence is in the dedicated environment runbook. Exact
check records can only be issued on Ubuntu 24.04 x86-64. The runner reuses the
locked runtime image, verifies its image ID before and after every command,
routes generated evidence into an ignored per-check directory, and fails if
the source tree changes. These records authorize allocation only; they do not
constitute dedicated performance evidence or an OSS release attestation.

Run `make benchmark-contracts` to validate the contracts and
`make benchmark-upstream-smoke` to verify the controlled upstream's exact
256-byte payload and SHA-256 digest. Docker Desktop results are functional
evidence only. Publishable performance results require the dedicated native
Linux topology defined by the fairness contract.

## Phase 1 scaling gate

Run the repeatable BonVoyage one-core/two-core gate with:

```bash
make benchmark-phase1-scaling
```

The default profile builds native images for the Docker engine, pins gateway,
load-generator, and upstream roles to disjoint CPU sets, verifies payload
identity and upstream headroom, warms each profile, and records five 30-second
measurements. It retains schema-valid result documents, raw `oha` output,
container statistics, metrics, logs, environment identity, image and
executable digests, and a generated report under `benchmarks/results`.

The runner classifies ordinary runs as `local-functional`. On a dedicated
native Linux host, `BONVOYAGE_PUBLISHABLE=1` additionally requires a clean Git
tree, explicit IRQ allocation, and
`BONVOYAGE_QUALIFICATION_ATTESTATION=fairness-contract-reviewed`. That
attestation means the operator separately verified every isolation and host
condition in the fairness contract; the script cannot infer physical-core,
thermal, firmware, or NIC isolation from Docker metadata alone.

## Phase 2 competitive gate

First qualify the immutable comparator images and their exact configurations:

```bash
make benchmark-phase2-products
```

Run planning, decision, shell-syntax, and evidence-contract checks with:

```bash
make benchmark-phase2-tests benchmark-contracts
```

`make benchmark-phase2-smoke` exercises result capture locally but cannot
produce a claim. `make benchmark-phase2` runs capacity discovery, five
randomized confirmations, five complete operating curves, overload recovery,
and connection churn for BonVoyage, Envoy, NGINX, and HAProxy.

Publishable mode requires the dedicated native Linux host, a clean source
tree, disjoint CPU/IRQ allocation, fairness attestation, a passing native Phase
1 summary in `BONVOYAGE_PHASE1_EVIDENCE`, and a matching native AMD64 comparator
qualification in `BONVOYAGE_PHASE2_PRODUCT_QUALIFICATION`. The runner derives
successful throughput from HTTP `200` responses rather than oha's
transport-level success field.

The existing Phase 2 runner and `docs/performance/phase-2-runbook.md` remain the
single-host rehearsal path. The final campaign requires separated generator,
gateway-target, and upstream nodes. Seven test groups still need distributed
adapters and thirteen need new orchestration; no Dedicated Host should be
allocated until those paths pass an ordinary three-instance rehearsal. The
runner exits 2 when the canonical gate does not pass; raw evidence remains
available for the optimization or architecture decision.

## Phase 5 policy-cost evidence

The PERF-06 plan and result contract live in
`benchmarks/scripts/phase5-policy-cost.mjs`. The native normalization adapter
is `benchmarks/scripts/phase5-policy-cost-native.mjs`. Its `describe` command
emits the immutable point contract; its `derive` command accepts only the
exact checksum-bound raw collector directory and writes a capture archive,
environment copy, derivation manifest and normalized result beneath one
evidence root.

Run the offline contract and tamper replay as part of:

```bash
make benchmark-phase2-tests
```

That replay launches no traffic and produces no publishable result.

The native client and remote executor are
`benchmarks/scripts/phase5-policy-cost-client.mjs` and
`benchmarks/scripts/phase5-policy-cost-executor.mjs`. Run `preflight` with the
same option set intended for `capture` before contacting a paid host. The
preflight validates the immutable plan, collector bundle, digest-pinned OHA
client, exact client CPU/lane placement, point-specific request artifact and,
for JWT points, the active JWKS digest and token runway. It emits the probe,
warmup and measurement argument arrays but executes none of them.

`capture` is Linux-root-only. It verifies the three private host identities,
clean source and remote checkout, installed binary, snapshot, TLS bundle,
controlled-upstream artifact and IRQ policy before load. It then performs one
semantic TLS probe, a settled warmup and one all-reactor measurement with
`perf`, socket-write tracing, gateway and whole-host CPU counters, resources,
journal and final drain evidence. Connection count, client CPU set, five-second
request timeout and cleanup deadline are part of the plan rather than executor
defaults. The remote probe directory is fixed to one attempt-scoped path below
`/var/tmp` so cleanup cannot target an operator-selected directory.

Every failed attempt is retained as invalid evidence with one bounded reason
and a post-failure process/drain observation; it is never selected as a product
result. API-key and bearer values are excluded from commands and retained
metadata. Generate JWT material immediately before its attempt with:

```bash
python3 -B scripts/generate-jwt-smoke-material.py PRIVATE_DIR \
  --lifetime-seconds 180
```

The executor checkpoint itself launches no AWS traffic and produces no
publishable result. A clean committed preflight and then the seven-point
shared-VM directional run remain required before PERF-06 has measurements.
