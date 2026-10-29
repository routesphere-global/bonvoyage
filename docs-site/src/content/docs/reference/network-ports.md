---
title: Network ports and firewall rules
description: Authoritative BonVoyage data-plane and control-plane network flows for firewall and security-group planning.
---

BonVoyage does not require one broad port range. Traffic listeners, upstream
ports, and optional control-plane listeners are deployment settings. Permit
only the exact flows enabled by the installed configuration.

The tables below distinguish a **runtime default** from a **repository
example**. An example port is not reserved by BonVoyage and may be changed.

## Data-plane ports

| Flow | TCP port | When required | Exposure |
| --- | ---: | --- | --- |
| Client or load balancer to HTTP listener | `8080` in the local example | When that configured plaintext listener is enabled | Application network; public only when plaintext HTTP is intentional |
| Client or load balancer to HTTPS listener | `8443` in the TLS example | When that configured TLS listener is enabled | Application network; commonly reached through external port `443` |
| Prometheus scraper to metrics listener | `9090` by default | Optional; port `0` disables it | Monitoring network only; default bind address is `127.0.0.1` |
| Health probe or operator to data-plane health/admin listener | `9901` by default | Optional; port `0` disables it | Host loopback or a restricted management network only; default bind address is `127.0.0.1` |
| Gateway to an upstream application | Configured per endpoint; `8081` is used by the demo upstream | Required for proxied routes | Outbound from gateway nodes to the exact application addresses and ports |

The `9901` listener is the data-plane process health and inspection surface. It
is not the control-plane management service and must not be exposed as a
public application endpoint.

## Optional control-plane flows

Standalone snapshot compilation is an offline command and opens no network
listener. A data plane started from a local immutable snapshot therefore needs
no control-plane firewall rule.

| Flow | TCP port | When required | Exposure |
| --- | ---: | --- | --- |
| Gateway to discovery service | `9443` data-plane default | Only when `--discovery-address` is configured | Outbound from gateway nodes and inbound to the selected control-plane host; TLS 1.3 and mutual TLS |
| Node to enrollment service | No default; selected explicitly | Only when node enrollment is enabled | Restricted node/bootstrap network; separate from discovery |
| Console or authorized operator to management service | No default; selected explicitly | Only for a deployment that enables the management listener | Restricted management network; TLS 1.3 and mutual TLS; separate from discovery and enrollment |

The control-plane `serve-discovery` command requires an explicit `host:port`
for every listener it enables. The discovery, enrollment, and management
listeners must use distinct addresses. The data-plane discovery client uses
`9443` when discovery is enabled and no port override is supplied, so the
control-plane discovery listener normally uses the same port.

The management listener is listed here so a network administrator can create
an exact firewall rule. Its endpoint catalog, SDK contract, and external
automation guide are not a supported public OSS compatibility surface;
supported programmatic management documentation is Enterprise scope.

## Optional outbound services

| Flow | Port | Notes |
| --- | ---: | --- |
| Gateway to an OpenTelemetry collector | Defined by `--otlp-traces-endpoint`; commonly `4318` for OTLP/HTTP or `443` for HTTPS | No connection is made when the endpoint is empty |
| Gateway or control plane to DNS | Resolver-defined; commonly UDP/TCP `53` | Needed only when configured hostnames require DNS resolution |

Access logging to a local directory or syslog socket does not require a TCP
firewall rule.

## Container and Kubernetes mappings

The supplied local Compose profile publishes only host-loopback bindings:

| Host | Container | Purpose |
| ---: | ---: | --- |
| `127.0.0.1:8080` | `8080` | Example HTTP traffic |
| `127.0.0.1:9090` | `9090` | Metrics |
| `127.0.0.1:9901` | `9901` | Data-plane health/admin |

The base Kubernetes Service maps service port `80` to container port `8080`.
The TLS overlay replaces it with service port `443` mapped to container port
`8443`. Metrics use a separate ClusterIP Service on `9090`; the `9901` health
listener is not exposed by a public Service. Supplied NetworkPolicies restrict
metrics and health/admin access to explicitly labelled workloads.

Port `8081` belongs to the repository's demonstration upstream application. It
is not a fixed BonVoyage listener and should not be opened unless an actual
upstream is configured there.

## Recommended firewall policy

1. Permit clients or the load balancer only to the configured traffic ports.
2. Permit `9090` only from approved monitoring collectors.
3. Keep `9901` on loopback when possible; otherwise permit only orchestrator
   probes and approved diagnostic hosts.
4. If discovery is enabled, permit gateway egress to the selected control-plane
   host on `9443` and accept that port only from gateway networks.
5. Permit enrollment and management listener ports only after assigning
   explicit, distinct ports and trusted source networks.
6. Permit gateway egress only to configured upstream, DNS, and telemetry
   destinations. Do not allow a blanket `8080-9901` range.

## Verify the effective deployment

Rendered deployment state is authoritative. Inspect it before changing a
firewall:

```bash
docker compose -f deploy/compose/local.yml config
kubectl -n bonvoyage get service,deployment,networkpolicy -o yaml
sudo ss -lntp
```

Also inspect the selected YAML listener and cluster endpoint ports and any
`serve-discovery` process arguments. Changing a listener address, protocol, or
TLS setting requires the documented controlled data-plane replacement rather
than an ordinary live snapshot activation.
