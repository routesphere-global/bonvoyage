---
title: Supported capabilities
description: Shipped v1.0.4 capabilities and explicit OSS, Enterprise, and later boundaries.
---

This page describes the public BonVoyage `v1.0.4` boundary. Exact artifact
identities and release notes remain authoritative for installation; this page
separates shipped behavior from planned OSS and Enterprise work.

## Traffic and policy

- HTTP/1.1 and HTTP/2 downstream proxying.
- HTTP/1.1 and HTTP/2 upstream paths.
- TLS and mTLS boundaries.
- Exact and prefix routing, redirects, and route rewrites.
- Round-robin and weighted upstream selection, health checks, bounded retries,
  endpoint circuits, and overload admission.
- API-key and JWT admission, source-IP policy, CORS, request-content controls,
  header transformations, and local rate limiting.
- Unary gRPC, WebSocket forwarding, and incrementally delivered SSE bytes.

## Operations

- Immutable snapshot compilation and standalone serving.
- Go control-plane validation, preview, ACK/NACK distribution, activation, and
  rollback primitives.
- Prometheus metrics, bounded access logging, and OpenTelemetry trace export.
- Docker, a native Ubuntu package, an OCI archive, Kubernetes Deployment
  manifests, benchmark tools, security checks, and plan-first Linux host
  tuning inspection.
- Deterministic offline `validate`, `format`, `explain`, `diff`, `migrate`, and
  `preview` configuration operations.
- Release-matched ChatGPT/Codex and Claude Code configuration skills.

## Boundaries that remain explicit

| Area | Current boundary |
| --- | --- |
| gRPC | Unary mode is implemented; client, server, and bidirectional streaming are not implied. |
| SSE | Incremental forwarding is implemented; production-scale concurrent slow-consumer and event-cadence qualification remains release evidence work. |
| Certificates | One certificate/key pair per TLS listener; no per-domain SNI certificate selector or certificate-upload API. |
| Fleet operations | The OSS control plane provides standalone primitives; enterprise multi-tenant fleet governance is separate. |
| Rate limits | Route-local shard-aware protection is shipped; exact distributed/global quota contracts are Enterprise. |
| Kubernetes packaging | Deployment, Service, PDB, and network policies ship; Helm, DaemonSet mode, and Gateway API translation remain OSS improvements. |
| Other OSS improvements | Proxy Protocol, request mirroring, locality/priority failover, and dynamic endpoint or customer-secret inputs are not shipped in v1.0.4. |
| Management API | Console Free uses an internal management service, but the public product does not publish a supported endpoint, SDK, external automation, or third-party UI contract. Supported programmatic management documentation is Enterprise scope. |
| Performance | Results apply only to their recorded source, artifact, configuration, workload, and environment. |
| Dedicated hardware | Bare-metal NUMA, PCIe, NIC queue, and IRQ advantages require physical-topology qualification. |

Use these boundaries when evaluating fit. Do not infer an unlisted protocol,
deployment, scale, or support promise from a nearby feature.
