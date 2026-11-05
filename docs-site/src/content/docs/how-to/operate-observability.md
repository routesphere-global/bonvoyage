---
title: Operate Prometheus, Grafana, and OpenTelemetry
description: Scrape BonVoyage safely, load the shipped rules and dashboard, and export bounded traces without putting telemetry on the request path.
---

BonVoyage `v1.0.4` keeps request execution independent from telemetry
consumers. Prometheus pulls fixed-cardinality metrics, Grafana reads
Prometheus, and each Seastar shard exports sampled traces through a bounded
asynchronous queue. A failed or slow collector is observable, but it does not
become a remote dependency in the request path.

## Interfaces and boundaries

| Interface | Default | Purpose | Exposure rule |
| --- | --- | --- | --- |
| Application traffic | TCP `8080`; TLS commonly `8443` | Client API traffic | Expose only through the intended ingress or service path. |
| Prometheus | `127.0.0.1:9090/metrics` natively; pod port `9090` in Kubernetes | Pull operational metrics | Keep on the management boundary. |
| Admin | `127.0.0.1:9901` natively; pod port `9901` in Kubernetes | Liveness, readiness, and active-snapshot diagnosis | Never expose publicly. |
| OTLP/HTTP collector | Operator supplied, conventionally TCP `4318` at `/v1/traces` | Receive sampled trace batches | Prefer authenticated HTTPS or a protected node-local collector. |

The native service binds admin and metrics to loopback. A remote Prometheus
therefore needs a co-located agent or a separately reviewed secure forwarding
path. Do not change either listener to `0.0.0.0` without host-firewall,
management-network, and access-policy review.

The Kubernetes base exposes metrics through the `bonvoyage-metrics` ClusterIP
Service. Its NetworkPolicy permits only same-namespace pods labeled
`routesphere.global/metrics-access: "true"`. The admin port has no public
Service and is limited to explicitly labeled diagnostic pods.

## Verify the endpoints

For a native or local Compose installation:

```bash
curl --fail http://127.0.0.1:9901/health/live
curl --fail http://127.0.0.1:9901/health/ready
curl --fail http://127.0.0.1:9090/metrics
```

For Kubernetes metrics:

```bash
kubectl -n bonvoyage port-forward service/bonvoyage-metrics 9090:9090
curl --fail http://127.0.0.1:9090/metrics
```

Use a separate short-lived diagnostic port-forward for admin readiness. Do
not add the admin listener to a Service merely to simplify monitoring.

## Configure Prometheus

The repository baseline uses a 10-second scrape interval, a 5-second timeout,
and a 15-second rule-evaluation interval:

```yaml
global:
  scrape_interval: 10s
  scrape_timeout: 5s
  evaluation_interval: 15s

rule_files:
  - rules/bonvoyage-recording-rules.yml
  - rules/bonvoyage-alerts.yml

scrape_configs:
  - job_name: bonvoyage
    honor_labels: false
    metrics_path: /metrics
    static_configs:
      - targets: [bonvoyage:9090]
        labels:
          service: bonvoyage
          environment: production
          deployment: standalone
          region: replace-me
          node: replace-me
```

The shipped operational set contains **71 recording-rule entries**, **49
unique decision series**, and **22 alerts**. Load the recording rules and
alerts together so dependent expressions resolve correctly:

```text
observability/prometheus/rules/bonvoyage-recording-rules.yml
observability/prometheus/rules/bonvoyage-alerts.yml
```

Keep `honor_labels: false`. Add only trusted scrape-layer resource labels such
as `service`, `environment`, `deployment`, `region`, `zone`, and `node`. Never
derive labels from request paths, authorities, client addresses, users,
tenants, credentials, headers, cookies, query strings, or bodies.

Prometheus counters can reset and scrapes can be lost. They are operational
signals, not billing records or contractual usage evidence.

## Provision Grafana

The production engineering dashboard is:

```text
observability/grafana/dashboards/bonvoyage-decision-console.json
```

It contains 16 panels for readiness, traffic outcomes, tail latency,
overload, reactor and memory pressure, shard balance, upstream behavior, and
telemetry delivery. Provision it with:

```text
observability/grafana/provisioning/datasources/prometheus.yml
observability/grafana/provisioning/dashboards/dashboards.yml
```

The separate release-replay dashboard is for bounded campaign evidence. Do
not treat synthetic preview series as production or customer evidence.

## Enable bounded trace export

Tracing is disabled unless `--otlp-traces-endpoint` is supplied. BonVoyage
exports OTLP/HTTP Protobuf to `/v1/traces`; it does not wait for the collector
on the request path.

```text
--otlp-traces-endpoint https://otel-collector.example:4318/v1/traces
--otlp-traces-tls-ca-file /etc/bonvoyage/secrets/otel-ca.pem
--otlp-traces-sample-every 100
--otlp-traces-queue-capacity 8192
--otlp-traces-max-batch-spans 256
--otlp-traces-max-batch-bytes 1048576
--otlp-traces-flush-interval-ms 1000
--otlp-traces-request-timeout-ms 10000
--otlp-traces-max-retries 3
--otlp-traces-retry-initial-backoff-ms 100
--otlp-traces-retry-max-backoff-ms 5000
```

These are the shipped defaults made explicit for review. Tune sampling and
queue limits only after measuring traffic volume, memory allowance, collector
capacity, and acceptable trace loss. Never encode collector credentials in
the endpoint URL.

Each shard uses a preallocated FIFO queue that drops newest spans when full.
Transient failures receive bounded retries; exhausted or permanently rejected
batches are dropped and counted. BonVoyage propagates one validated W3C
`traceparent`. It intentionally does not forward `tracestate` or `baggage`,
and exported attributes exclude request paths, authorities, client addresses,
identities, credentials, cookies, arbitrary headers, and bodies.

## Production acceptance checklist

1. Confirm traffic, metrics, admin, and OTLP paths match the intended network boundaries.
2. Confirm every target is up and every shard reports ready on one active snapshot generation.
3. Validate recording rules before enabling dependent alerts.
4. Verify every dashboard panel against live, non-synthetic series.
5. Cause one controlled collector outage and confirm traffic stays healthy, exporter failure is visible, and delivery recovers without a gateway restart.
6. Review labels and trace attributes against your privacy requirements.
7. Assign an owner, workload SLO, immediate action, and escalation path to every enabled alert.
8. Keep billing, contractual usage, and durable tenant audit outside Prometheus and the bounded trace exporter.

The `v1.0.4` [post-release replay](../../performance/v1-0-4-post-release-replay/)
includes a supplemental observability gate for scrape loss, slow readers,
OTLP rejection, queue overflow, privacy, and same-process recovery.

