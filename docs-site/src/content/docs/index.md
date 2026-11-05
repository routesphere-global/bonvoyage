---
title: RouteSphere BonVoyage API Gateway
description: Public documentation for installing, configuring, operating, and verifying the BonVoyage API gateway.
---

<img class="bonvoyage-doc-mark" src="/routesphere-mark.svg" alt="RouteSphere mark" width="72" height="72" />

BonVoyage is a standalone API gateway with a C++/Seastar data plane and a Go
control plane. Its operating model keeps request ownership shard-local, turns
declarative configuration into immutable snapshots, and makes rejected changes
visible through validation and ACK/NACK outcomes.

:::note[Current release]
This site documents
[BonVoyage v1.0.4](https://github.com/routesphere-global/bonvoyage/releases/tag/v1.0.4),
the current checksum-bound public release. BonVoyage-owned source and
documentation are licensed under Apache License 2.0. Download exact packages,
checksums, Gateway signatures, provenance, SBOMs, and platform scope from the
release page.
:::

## Evidence paths

| Evidence | What it contains |
| --- | --- |
| [v1.0.4 post-release replay](performance/v1-0-4-post-release-replay/) | Release-matched installation, functional, NGINX comparison, policy, protocol, recovery, and observability outcomes. |
| [Current performance evidence](https://routesphere.global/performance/) | Curated current-release results, test conditions, resource trade-offs, acceptance gates, and limitations. |
| [Historical comparison archive](https://routesphere.global/performance-history/) | Earlier NGINX and Envoy engineering measurements, kept separate from the public v1.0.4 replay. |
| [Release evidence](https://routesphere.global/release-evidence/) | Artifact identities, verification material, SBOMs, provenance, assessments, and the A-G proof map. |
| [Kubernetes lifecycle replay](how-to/verify-kubernetes-deployment/#accepted-public-main-replay) | Clean-source installation, controlled upgrade, rejected-candidate containment, exact rollback, and teardown for the named public-main commit. |
| [Supported capabilities](reference/supported-capabilities/) | Shipped v1.0.4 behavior and explicit OSS, Console Free, Enterprise, and later boundaries. |

The current v1.0.4 replay contains an accepted BonVoyage/NGINX comparison.
Envoy results remain in the historical archive because the current-release
campaign did not produce an accepted Envoy comparison. Curated public evidence
does not imply that private infrastructure captures or every raw diagnostic are
published.

## Run the local stack

From the repository root:

```bash
docker compose -f deploy/compose/local.yml up --build
```

Then verify the fixed readiness route:

```bash
curl --fail --show-error http://127.0.0.1:8080/bonvoyage/ready
```

The expected response is `ready`. Continue with the
[Docker quickstart](getting-started/quickstart/) for health, metrics, shutdown,
and troubleshooting checks.

## Choose your path

| Goal | Start with |
| --- | --- |
| Evaluate locally | [Requirements](getting-started/requirements/) and [Docker quickstart](getting-started/quickstart/) |
| Verify a running stack | [Verify a local deployment](how-to/verify-local-deployment/) |
| Verify the disposable Kubernetes lifecycle | [Verify a Kubernetes deployment](how-to/verify-kubernetes-deployment/) |
| Operate metrics, dashboards, alerts, and traces | [Operate Prometheus, Grafana, and OpenTelemetry](how-to/operate-observability/) |
| Validate desired-state YAML offline | [Validate a configuration](how-to/validate-configuration/) |
| Format accepted YAML without changing its meaning | [Format a configuration](how-to/format-configuration/) |
| Look up release-matched help for a field | [Explain a configuration field](how-to/explain-configuration-field/) |
| Compare two accepted configurations without exposing values | [Compare configurations](how-to/compare-configurations/) |
| Check or migrate an explicit configuration-schema pair | [Migrate a configuration](how-to/migrate-configuration/) |
| Preview an immutable artifact and local changes | [Preview a configuration](how-to/preview-configuration/) |
| Operate a standalone installation visually | [Console Free](console/) |
| Understand the runtime | [System model](concepts/system-model/) |
| Understand safe changes | [Configuration lifecycle](concepts/configuration-lifecycle/) |
| Look up every YAML parameter, constraint, and example | [YAML parameter reference](reference/configuration-parameters/) |
| Review tool behavior | [Configuration authoring contract](reference/configuration-authoring-contract/) |
| Integrate release-matched field completion | [Configuration completion metadata](reference/configuration-completion-metadata/) |
| Reuse compiler-backed configuration fragments | [Configuration snippets](reference/configuration-snippets/) |
| Present stable configuration failures and remediation | [Configuration diagnostics](reference/configuration-diagnostics/) |
| Replay accepted and rejected YAML decisions | [Configuration test corpus](reference/configuration-test-corpus/) |
| Review assistant safety, consent, and claim boundaries | [Assistant skill contract](reference/assistant-skill-contract/) |
| Inspect the shared adversarial assistant evaluation corpus | [Assistant skill evaluations](reference/assistant-skill-evaluations/) |
| Install the release-bound ChatGPT/Codex authoring skill | [ChatGPT and Codex configuration skill](reference/openai-codex-configuration-skill/) |
| Install the release-bound Claude Code authoring skill | [Claude Code configuration skill](reference/claude-configuration-skill/) |
| Check current scope | [Supported capabilities](reference/supported-capabilities/) |
| Inspect the post-release qualification | [v1.0.4 post-release replay](performance/v1-0-4-post-release-replay/) |
| Report a defect or vulnerability | [Support and security](reference/support-and-security/) |

## Evidence boundary

Performance and security claims belong to an exact source revision, artifact,
configuration, workload, and environment. This documentation does not turn
shared-host directional measurements into dedicated-hardware claims, and it
does not claim universal superiority over NGINX, Envoy, or another gateway.
