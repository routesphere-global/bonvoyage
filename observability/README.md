# Observability

BonVoyage observability is a bounded decision interface, not an unfiltered dump
of request data. The dataplane updates shard-local metrics; Prometheus pulls
them; recording rules, alerts, and Grafana translate them into operational and
product decisions without placing a remote exporter in the request path.

## Repository layout

- `telemetry-contract.yaml`: collection, identity, privacy, cardinality,
  durability, and ownership contract.
- `control-plane-telemetry-contract.yaml`: authenticated standalone rollout
  metrics, fixed-cardinality labels, paged audit export, and durability bounds.
- `decision-audiences.yaml`: infrastructure, systems, sales, business-analysis,
  CEO, and CTO decisions mapped to the shared dashboard without creating
  conflicting telemetry definitions.
- `logging/events.yaml`: 21 stable operational lifecycle, failure-transition,
  access-sink, and trace-export events. Request completion records use the
  separate bounded `bonvoyage.access.v1` JSONL schema.
- `prometheus/prometheus.yml`: local scrape and rule-loading configuration.
- `prometheus/rules/bonvoyage-recording-rules.yml`: 71 rule entries producing
  49 unique decision series, including HTTP/1 pool-wait mean and conservative
  process-lifetime maximum.
- `prometheus/rules/bonvoyage-alerts.yml`: 22 alerts with explicit owner,
  decision, and action fields.
- `prometheus/tests/bonvoyage-rules.test.yml`: deterministic rule tests.
- `prometheus/rules/bonvoyage-control-plane-alerts.yml`: four standalone
  controller recovery alerts for target loss, authority mismatch, required
  recovery, and unreconciled nodes. Load it only with an authenticated
  `bonvoyage-control-plane` scrape job.
- `prometheus/tests/bonvoyage-control-plane-rules.test.yml`: deterministic
  control-plane recovery decisions.
- `grafana/dashboards/bonvoyage-decision-console.json`: 16-panel decision
  console.
- `grafana/provisioning/`: Prometheus datasource and dashboard provisioning.

## Decision ownership

| Audience | Use these views for | Do not infer |
| --- | --- | --- |
| Infrastructure engineer | Readiness, tail latency, rejection ownership, reactor/memory pressure, shard balance, upstream recovery, and rollout integrity | Capacity or SLO guarantees from a local run |
| Systems expert | Protocol cost, selector and circuit behavior, shard and allocator pressure, active configuration scale, and architecture-review triggers | Dedicated performance or indefinite stability from bounded local evidence |
| Sales | Evidence-backed successful volume, service quality, protocol adoption, payload demand, and rollout confidence | Customer proof, production readiness, or competitive claims without publication approval |
| Business analyst | Served demand, response mix, policy rejection, protocol adoption, payload flow, and retry recovery | Revenue, invoices, customer identity, or contractual usage |
| CEO | Service outcome, failed demand, resource headroom, rollout integrity, and evidence maturity | Billing, contractual SLO, or externally approved performance from operational aggregates |
| CTO | Latency, isolation, resource, failure, configuration-scale, recovery, and residual-risk decisions | A closed architecture or production gate while dedicated and multi-hour work remains open |

Prometheus counters can reset and scrapes can be lost. They are operational
signals with `billing_grade=false`. Durable customer metering belongs in a
future idempotent control-plane pipeline.

The standalone control plane exposes `/metrics` only on its TLS 1.3 mTLS Admin
listener. A viewer-authorized scrape identity can read fixed-dimension rollout,
connection, reconciliation, journal, report, and recovery gauges. Actor, node,
artifact, request, rollout, user, and tenant identities are forbidden metric
labels. Detailed lineage belongs to the paged, SHA-256-bound audit endpoint,
not to Prometheus.

The operational console is only one layer of the final role experience.
Publication-approved benchmark and capability evidence belongs in an evidence
registry; governed usage and cost facts belong in durable control-plane
analytics; support and entitlement data belongs in the support platform; and
revenue, pipeline, retention, and margin belong in CRM, billing, and finance
systems. Executive and commercial dashboards may join those sources later, but
must preserve provenance instead of deriving business truth from resettable
dataplane counters.

## Validate

```bash
make observability-validate
```

This validates the project contract, Prometheus configuration, rules, alerts,
dashboard, event catalog, cardinality policy, and deterministic rule behavior.
The Prometheus tool image is pinned in the root `Makefile`.

Run the live two-shard gate with:

```bash
make dataplane-observability-smoke
```

The live gate exercises controlled success, policy rejection, route miss, and
upstream failure traffic. It checks readiness, snapshot agreement, per-shard
participation, response outcomes, canonical histograms, live recording rules,
and privacy sentinels. Evidence is retained under
`benchmarks/results/verification/` and is classified as local engineering
evidence rather than performance or marketing proof.

Run the representative two-tenant profile with:

```bash
make dataplane-saas-canary-profile
```

That gate combines separate tenant credentials and upstream pools, static 75/25
canary traffic, quota and overload decisions, one-tenant failure containment,
Prometheus loss and restart, blocked metrics readers, privacy sentinels, and
same-process recovery. It retains a role-oriented decision summary without
adding tenant-derived labels or promoting the result to billing or marketing
evidence.

Run and retain the bounded mixed-protocol access-log gate with:

```bash
make dataplane-access-log-smoke
```

The gate validates one HTTP/1.1 and 89 HTTP/2 completion records, exact schema,
forbidden fields, payload-byte accounting, clean drain, and zero delivery loss.
The dataplane defaults logging off; when enabled, each shard owns a preallocated
drop-newest queue and a bounded local JSONL sink. Sink failure is visible but
cannot block or reject request traffic.

Run and retain the bounded OTLP tracing gate with:

```bash
make dataplane-otlp-tracing-smoke
```

The gate validates W3C parent continuation over HTTP/1.1 and HTTP/2, local
sampling authority, bounded queue overflow, retry exhaustion, collector
recovery without a gateway restart, propagation-limit rejection, exact
protobuf decoding, and privacy exclusions. Tracing is default-off and each
shard owns its exporter; collector failure cannot block request service.

## Deployment notes

Prometheus must reach the dataplane `/metrics` endpoint. Add trusted resource
labels such as service, environment, deployment, region, zone, and node in the
scrape layer. Do not relabel request paths, authorities, client addresses,
users, tenants, credentials, headers, cookies, or bodies into time-series
labels.

Load the Grafana provisioning directories using Grafana's standard
`provisioning/datasources` and `provisioning/dashboards` paths. Alert thresholds
are starting guardrails and must be approved against each workload's SLO and
capacity model.

## Deferred boundaries

Prometheus collector loss/slow-reader isolation, bounded local access-log
delivery, and bounded OTLP exporter failure/recovery have local evidence.
Sustained access-log disk pressure, production rotation/retention, sustained
trace-collector pressure, dedicated telemetry cost, multi-hour stability,
rollout/fleet series, and durable billing metering remain separate checkpoints.
None may introduce a synchronous dependency into the gateway request path.
