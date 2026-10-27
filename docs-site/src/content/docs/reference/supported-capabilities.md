---
title: Supported capabilities
description: Current implementation scope and explicit boundaries for the first BonVoyage OSS candidate.
---

This page describes implemented source scope. Final supported-platform and
release claims belong to the exact published release notes and artifacts.

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
- Docker, native Ubuntu package inputs, Kubernetes manifests, benchmark tools,
  security checks, and plan-first Linux host tuning.

## Boundaries that remain explicit

| Area | Current boundary |
| --- | --- |
| gRPC | Unary mode is implemented; client, server, and bidirectional streaming are not implied. |
| SSE | Incremental forwarding is implemented; production-scale concurrent slow-consumer and event-cadence qualification remains release evidence work. |
| Certificates | One certificate/key pair per TLS listener; no per-domain SNI certificate selector or certificate-upload API. |
| Fleet operations | The OSS control plane provides standalone primitives; enterprise multi-tenant fleet governance is separate. |
| Performance | Results apply only to their recorded source, artifact, configuration, workload, and environment. |
| Dedicated hardware | Bare-metal NUMA, PCIe, NIC queue, and IRQ advantages require physical-topology qualification. |

Use these boundaries when evaluating fit. Do not infer an unlisted protocol,
deployment, scale, or support promise from a nearby feature.
