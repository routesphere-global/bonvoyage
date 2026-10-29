---
title: System model
description: How clients, listeners, shard-local request handling, upstreams, and the optional control plane fit together.
---

BonVoyage separates traffic processing from configuration management. The data
plane can serve its active immutable snapshot without a running control-plane
process.

```text
Configuration source
        |
        v
validation and snapshot compiler ----> immutable snapshot artifact
                                               |
                                               v
Client -> listener -> route/policy -> upstream pool -> application
                         |                  |
                         +---- metrics, access logs, and traces
```

## Data plane

The C++/Seastar data plane owns accepted requests on one shard. Routing, policy
evaluation, upstream selection, response handling, and request-scoped state stay
with that owner. Cross-shard coordination is reserved for bounded lifecycle work
rather than ordinary request forwarding.

## Configuration plane

Declarative YAML is validated and compiled before the data plane consumes it.
The resulting snapshot has a schema version, snapshot identity, generation, and
minimum data-plane version. Invalid input is rejected before activation.

The standalone Go control plane adds versioned distribution, ACK/NACK state,
preview, activation, and rollback primitives. It does not sit in the request
path. A gateway continues serving its active snapshot if the controller is
temporarily unavailable.

## Operational listeners

Traffic, administration, and metrics are separate listener roles:

| Role | Local example | Purpose |
| --- | --- | --- |
| Traffic | `:8080` | Client requests governed by routes and policies |
| Data-plane health/admin | `:9901` | Process readiness and active-state inspection |
| Metrics | `:9090` | Prometheus-format engineering telemetry |

Production deployments should restrict administrative and metrics listeners to
trusted networks rather than exposing them as public application endpoints.
See [Network ports and firewall rules](/reference/network-ports/) for the full
data-plane, control-plane, container, and Kubernetes port matrix.
