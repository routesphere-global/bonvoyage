---
title: Verify a Kubernetes deployment
description: Check a bounded BonVoyage acceptance deployment without mutating cluster state.
---

The repository contains a read-only verifier for the disposable Kubernetes
acceptance profile. It checks the running gateway rather than treating a
successful manifest apply as proof of correct behavior.

## Safety boundary

The verifier requires the active context to be exactly
`kind-bonvoyage-oss-acceptance` by default. This prevents a developer from
silently running the acceptance probe against another cluster. It never
applies, patches, restarts or deletes a resource.

The profile under
`tests/fixtures/oss-kubernetes-fresh-install/` is test infrastructure. It
contains revisioned baseline, upgrade and deliberately invalid configuration
objects used by the release acceptance campaign. Do not use that overlay as a
production deployment.

## Render before applying

```bash
kubectl kustomize tests/fixtures/oss-kubernetes-fresh-install/
```

Review the output and confirm that:

- the gateway has two replicas;
- `maxUnavailable` is `0` and `maxSurge` is `1`;
- the baseline selects `bonvoyage-config-v1`;
- the Service exposes only HTTP and metrics; and
- every acceptance image is a controlled local image.

The fixture expects these image names to be loaded into the disposable cluster:

```text
bonvoyage-local-bonvoyage:oss-kubernetes
bonvoyage-local-snapshot-compiler:oss-kubernetes
bonvoyage-local-upstream:oss-kubernetes
```

## Run the read-only verifier

After the acceptance deployment and controlled upstream are Ready:

```bash
make verify-kubernetes-deployment
```

The command verifies:

- exactly two Ready and available gateway replicas;
- successful snapshot-compiler init containers;
- non-root execution, RuntimeDefault seccomp, dropped capabilities,
  read-only root filesystems and disabled service-account token mounting;
- exact CPU and memory resource contracts;
- a Service that does not expose the admin listener;
- exact fixed and proxied response bodies;
- exact request, 2xx-response and upstream-selection counter deltas;
- zero selected runtime error counters;
- zero container restarts; and
- unchanged pod UIDs and image identities during the bounded sample.

The default sends 25 fixed-route and 25 proxied-route requests. A different
positive bound may be supplied for diagnosis:

```bash
BONVOYAGE_KUBERNETES_REQUESTS_PER_ROUTE=50 \
  make verify-kubernetes-deployment
```

For the accepted upgrade revision, select the exact expected ConfigMap. The
expected body follows that revision automatically:

```bash
BONVOYAGE_KUBERNETES_EXPECTED_CONFIG_MAP=bonvoyage-config-v2 \
  make verify-kubernetes-deployment
```

This standalone command is a functional observation, not a throughput
benchmark or production-capacity claim. The disposable lifecycle gate below
adds clean-source installation, controlled upgrade, failed-candidate
containment, exact rollback and complete teardown. Neither command alone
admits or publishes a release.

## Run the disposable lifecycle gate

The separate lifecycle runner owns one disposable cluster named
`bonvoyage-oss-acceptance`. It builds three images from the current clean Git
commit, verifies their source labels and immutable image IDs, creates the
cluster, loads those images, and executes the six contract phases. It is
deliberately destructive only within that exact cluster.

The contract pins `kind` `v0.33.0` and the Kubernetes `v1.37.0` node image by
SHA-256. Install the exact `kind` version, then confirm that Docker and
`kubectl` are available. The upstream project recommends stable tagged
releases for CI and digest pinning for reproducibility; see the
[kind quick start](https://kind.sigs.k8s.io/docs/user/quick-start/) and
[v0.33.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0).

Run from a committed, clean source tree. Choose a new ignored evidence path
for every attempt and supply the deletion token that names the exact cluster:

```bash
export BONVOYAGE_KUBERNETES_ACCEPTANCE_CONFIRM=delete-kind-bonvoyage-oss-acceptance
export BONVOYAGE_KUBERNETES_EVIDENCE="$PWD/build/oss-kubernetes-acceptance/run-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$(dirname "$BONVOYAGE_KUBERNETES_EVIDENCE")"
make run-kubernetes-acceptance
```

The runner refuses a dirty source tree, an existing cluster with that name, an
existing acceptance context, an unexpected `kind` version, unbound image
identity, or a pre-existing namespace. It preserves the previously active
Kubernetes context and restores it after the run.

The lifecycle proves:

1. `v1` fresh installation and read-only behavioral verification;
2. a zero-unavailable rolling upgrade to immutable `v2` configuration;
3. rejection of malformed YAML by the snapshot compiler while both healthy
   replicas and service traffic remain available;
4. exact rollback to `v1`; and
5. namespace and cluster teardown.

After Kubernetes reports each rollout complete, the runner also waits for
exact pod quiescence: only the configured number of Ready, non-terminating
replicas may remain, and every replica must select the expected revisioned
ConfigMap. This prevents a lingering old pod from being mistaken for the
accepted steady state.

The output contains command records, phase records, image identities,
diagnostics, cluster logs, a summary and `checksums.sha256`. Failed attempts
remain diagnostic evidence and do not become passing release evidence. The
runner also attempts exact-cluster cleanup after failure or interruption; it
never deletes a cluster that was present before preflight.

This gate is local functional evidence. It does not establish throughput,
production capacity, multi-node availability, benchmark reproducibility, or
release admission.
