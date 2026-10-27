# Tests

Cross-component integration, end-to-end, compatibility, and fixture suites that do not naturally belong inside a single component.

`fixtures/oss-native-fresh-install.yaml` is the bounded native package-lifecycle
configuration. It exposes one exact fixed response and one exact route to a
collector-owned loopback upstream. It is not a production configuration or a
performance workload. `fixtures/oss-native-fresh-install.pb` is its
deterministically compiled, contract-bound artifact; the snapshot package test
must reproduce its exact bytes.

`fixtures/oss-kubernetes-fresh-install/` is the disposable Kubernetes
acceptance profile. It contains revisioned baseline and upgrade ConfigMaps, one
deliberately invalid compiler input, a controlled upstream, explicit
zero-unavailable rolling-update policy and local-only image substitutions. It
is release-test infrastructure, not a production overlay. The read-only live
verifier and its fake-`kubectl` failure tests are in `scripts/`.
