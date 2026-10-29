---
title: Requirements
description: Tools and resource expectations for evaluating BonVoyage from source.
---

## Local evaluation

The shortest supported evaluation path uses Docker:

- Docker Engine or Docker Desktop with Compose v2.
- A Linux container runtime capable of building the Seastar data plane.
- `curl` for readiness checks.
- Enough memory and disk for the C++ dependency build and container layers.

The local Compose profile starts a controlled upstream, compiles the declarative
configuration into an immutable snapshot, and starts a one-shard gateway. It is
intended for correctness and workflow evaluation, not publication-grade
performance measurement.

## Source and tooling checks

The repository pins its JavaScript dependency graph and declares these minimum
tool lines:

| Tool | Purpose |
| --- | --- |
| Node.js 22.19 or newer | Public documentation and JavaScript contract checks |
| Go 1.26.10 or newer | Control plane, generated API, and host-tuning utility |
| Docker with Compose v2 | Reproducible Linux/Seastar builds and local stack |

Install JavaScript tooling with `make dependencies`, then use `make test` for
the portable contract suites once the standalone clean-room gate is complete.
Linux/Seastar compilation, sanitizers, fuzzing, and protocol qualification use
the Docker or native Ubuntu workflows documented by each release.

## Production boundary

Ubuntu 24.04 x86-64 is the current native packaging and qualification target.
That target does not imply that every cloud VM, kernel, NIC topology, or CPU
placement has identical capacity. Release notes will identify supported
artifacts and the evidence that applies to them.
