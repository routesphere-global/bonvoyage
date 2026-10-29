# BonVoyage API Gateway

BonVoyage API Gateway is a high-performance, standalone API gateway with a
C++/Seastar data plane and a Go control plane. It is designed around shard-local
request ownership, immutable configuration snapshots, bounded failure behavior,
and evidence-led release engineering.

> **Release-candidate notice:** BonVoyage-owned source and public documentation
> in this repository are licensed under Apache License 2.0. No signed or
> supported BonVoyage 1.0 artifact has been published yet. Treat current source
> builds as evaluation candidates until the release page identifies an exact
> admitted version, checksums, signatures, provenance, SBOMs, and support scope.

## What standalone means

Standalone means the gateway can run without the proprietary RouteSphere
Console. The data plane can start from and continue serving an active immutable
snapshot without a running control-plane process. The included Go control plane
adds validated distribution, ACK/NACK state, rollout, and rollback primitives;
it does not sit in the request path.

## Capabilities

### Proxy and traffic management

- HTTP/1.1 and HTTP/2 proxying with TLS and mTLS boundaries.
- Routing, upstream pools, weighted load balancing, health checks, bounded
  retries, endpoint circuits, and overload admission.
- Unary gRPC, WebSocket forwarding, and incremental SSE delivery.
- Redirects, header transformations, and route rewrites.

### Security and request policy

- API-key and JWT admission, source-IP policy, CORS, request-content controls,
  and local rate limits.

### Operations and observability

- Prometheus metrics, bounded access logging, and OpenTelemetry trace export.
- Docker, native Ubuntu packaging, Kubernetes manifests, benchmark tooling,
  security checks, and a plan-first Linux host-tuning utility.

### Control plane

- Immutable snapshot compilation and validation.
- Pre-release offline `bonvoyage-config validate`, fail-closed `format`, static
  release-matched `explain`, redacted compiled-semantic `diff`, and explicit
  fail-closed `migrate` and immutable-artifact `preview` source commands with
  deterministic machine output.
- Preview, ACK/NACK discovery, safe rollout, and rollback primitives.

### Engineering evidence

- Reproducible benchmark and protocol-qualification tooling.
- Runtime, dependency, and release-security checks.
- Source, artifact, and evidence identity binding.

The proprietary RouteSphere Console, enterprise fleet management, and internal
founder or commercial records are not part of this repository.

## Current status

| Area | Status |
| --- | --- |
| Release state | Licensed source; first signed release pending |
| Public license | Apache License 2.0 for BonVoyage-owned source and documentation |
| Production support | Not yet provided |
| Core proxy path | Implemented and under clean-room release validation |
| Standalone Go control plane | Implemented and under clean-room release validation |
| Public performance package | Pending sanitized evidence publication |
| Proprietary Console | Not included |

## Quick start

Prerequisites: Docker with Compose v2 and enough local resources to build the
Seastar data plane.

```bash
docker compose -f deploy/compose/local.yml up --build --detach --wait
```

The evaluation profile publishes its traffic, metrics, and admin listeners on
host loopback only. Run the bounded verifier after all roles are ready:

```bash
make verify-local-deployment
```

It checks the one-shot snapshot compiler, gateway and upstream lifecycle,
fixed and proxied traffic, exact request-accounting deltas, configuration
gauges, restart counts, and selected runtime failure counters. A passing run
ends with `status=pass`.

You can also verify the fixed readiness route directly:

```bash
curl --fail --show-error http://127.0.0.1:8080/bonvoyage/ready
```

Expected response:

```text
ready
```

Stop and remove the local stack with:

```bash
docker compose -f deploy/compose/local.yml down --volumes
```

## Development checks

Install the pinned JavaScript tooling and run the portable contract suites:

```bash
make dependencies
make test
make config-authoring-corpus-test
make config-authoring-cross-surface-contract-test
make config-authoring-completion-test
make config-authoring-snippets-test
make config-authoring-reason-codes-test
make config-authoring-skill-contract-test
make config-authoring-skill-evaluations-test
make oss-deb-builder-test
```

Linux/Seastar builds, sanitizers, protocol conformance, fuzzing, and release
artifact checks require Docker or an Ubuntu 24.04 x86-64 host. The public
documentation records the prerequisites and evidence boundary for each check.

## Performance evidence

BonVoyage is built to deliver predictable throughput, latency, memory use, and
recovery under realistic gateway policy workloads. Results are accepted only
when correctness, errors, support-role headroom, CPU, memory, p50, p95, p99,
and the test environment are recorded together. This project does not claim
universal superiority over NGINX, Envoy, or any other gateway.

Read the public [system model](https://docs.routesphere.global/concepts/system-model/)
and [supported-capability boundaries](https://docs.routesphere.global/reference/supported-capabilities/)
before interpreting an implementation or performance claim.

## Read next

- [Requirements](https://docs.routesphere.global/getting-started/requirements/)
- [Docker quickstart](https://docs.routesphere.global/getting-started/quickstart/)
- [Verify a local deployment](https://docs.routesphere.global/how-to/verify-local-deployment/)
- [Validate a configuration](https://docs.routesphere.global/how-to/validate-configuration/)
- [Format a configuration](https://docs.routesphere.global/how-to/format-configuration/)
- [Explain a configuration field](https://docs.routesphere.global/how-to/explain-configuration-field/)
- [Compare configurations](https://docs.routesphere.global/how-to/compare-configurations/)
- [Migrate a configuration](https://docs.routesphere.global/how-to/migrate-configuration/)
- [Preview an immutable configuration artifact](https://docs.routesphere.global/how-to/preview-configuration/)
- [Configuration test corpus](https://docs.routesphere.global/reference/configuration-test-corpus/)
- [Configuration completion metadata](https://docs.routesphere.global/reference/configuration-completion-metadata/)
- [Configuration snippets](https://docs.routesphere.global/reference/configuration-snippets/)
- [Configuration diagnostics](https://docs.routesphere.global/reference/configuration-diagnostics/)
- [Assistant skill contract](https://docs.routesphere.global/reference/assistant-skill-contract/)
- [Assistant skill evaluations](https://docs.routesphere.global/reference/assistant-skill-evaluations/)
- [System model](https://docs.routesphere.global/concepts/system-model/)
- [Supported capabilities](https://docs.routesphere.global/reference/supported-capabilities/)
- [Support and security](https://docs.routesphere.global/reference/support-and-security/)

## Documentation and support

- Documentation: <https://docs.routesphere.global>
- Product site: <https://routesphere.global>
- Community questions and reproducible defects: use this repository's issue
  tracker.
- Verified Release Assurance inquiries: <sales@routesphere.global>

Community issue submission does not include a response or incident-resolution
SLA. Read [SUPPORT.md](SUPPORT.md) and [SECURITY.md](SECURITY.md) before sharing
diagnostics or a suspected vulnerability.

## License and trademarks

BonVoyage-owned source and public documentation in this repository are
licensed under the [Apache License 2.0](LICENSE). Third-party material remains
under its identified upstream terms; consult the
[third-party notices](packaging/release/licenses/THIRD_PARTY_NOTICES.md),
[source-availability notice](packaging/release/licenses/THIRD_PARTY_SOURCE.md),
`third_party/`, dependency records and release artifacts before redistribution.

Community participation is issue-based as described in
[CONTRIBUTING.md](CONTRIBUTING.md); external source-code fixes and pull requests
are not accepted at this stage. Maintainer commits use
[Developer Certificate of Origin 1.1](DCO) sign-off. The Apache license does
not grant general rights to RouteSphere or BonVoyage names and logos; see the
[trademark policy](TRADEMARKS.md).

## Project policies

- [License](LICENSE)
- [Trademark policy](TRADEMARKS.md)
- [Developer Certificate of Origin](DCO)
- [Contributing](CONTRIBUTING.md)
- [Dependency policy](DEPENDENCY_POLICY.md)
- [Third-party notices](packaging/release/licenses/THIRD_PARTY_NOTICES.md)
- [Third-party source availability](packaging/release/licenses/THIRD_PARTY_SOURCE.md)
- [Release bundle verification](packaging/release/README.md)
- [Governance](GOVERNANCE.md)
- [Security](SECURITY.md)
- [Support](SUPPORT.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
