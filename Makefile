SHELL := /bin/sh
export GOCACHE := $(CURDIR)/.cache/go-build

.PHONY: help dependencies test test-go test-node test-python fmt-check \
	config-authoring-contract-test config-authoring-cli-test config-authoring-corpus-test \
	config-authoring-cross-surface-contract-test \
	config-authoring-windows-large-input-test \
	config-authoring-completion-test config-authoring-snippets-test \
	config-authoring-reason-codes-test config-authoring-skill-contract-test \
	config-authoring-skill-evaluations-test config-authoring-skill-evaluation-driver-test \
	config-authoring-skill-lifecycle-test \
	config-authoring-claude-capture-test \
	config-authoring-openai-codex-capture-test \
	config-authoring-openai-codex-skill-test \
	config-authoring-claude-skill-test \
	dco-signoff-test oss-release-bundle-test oss-candidate-intake-test oss-deb-builder-test oss-deb-hosted-contract-test \
	oss-deb-builder-image-test oss-native-install-verifier-test oss-native-install-collector-test oss-kubernetes-deployment-verifier-test oss-kubernetes-acceptance-runner-test oss-bounded-benchmark-verifier-test oss-bounded-benchmark-runner-test oss-oci-builder-test local-deployment-verifier-test \
	oss-oci-hosted-contract-test \
	dataplane-image dataplane-build dataplane-http2-deadline \
	dataplane-http2-cookie dedicated-preflight-rehearsal \
	native-logging-backpressure-ci up verify-local-deployment verify-kubernetes-deployment run-kubernetes-acceptance run-bounded-benchmark down

help:
	@echo "RouteSphere BonVoyage API Gateway OSS"
	@echo ""
	@echo "  dependencies   Install pinned JavaScript tooling"
	@echo "  test           Run portable Go, Node.js, and Python contract tests"
	@echo "  config-authoring-contract-test  Verify the versioned authoring UX contract"
	@echo "  config-authoring-cli-test  Verify all offline authoring operations and result schema"
	@echo "  config-authoring-corpus-test  Replay the versioned shared authoring corpus"
	@echo "  config-authoring-cross-surface-contract-test  Verify the versioned ADOPT-06 agreement boundary"
	@echo "  config-authoring-windows-large-input-test  Verify the inactive supported-Windows acceptance contract"
	@echo "  config-authoring-completion-test  Verify generated release-matched completion metadata"
	@echo "  config-authoring-snippets-test  Verify compiler-backed release-matched configuration snippets"
	@echo "  config-authoring-reason-codes-test  Verify release-matched diagnostic presentation guidance"
	@echo "  config-authoring-skill-contract-test  Verify the shared release-matched assistant-skill contract"
	@echo "  config-authoring-skill-evaluations-test  Verify the shared adversarial assistant evaluation corpus"
	@echo "  config-authoring-skill-evaluation-driver-test  Verify reviewed evidence assembly for assistant evaluations"
	@echo "  config-authoring-skill-lifecycle-test  Verify offline install, recovery, upgrade, downgrade refusal, and uninstall"
	@echo "  config-authoring-claude-capture-test  Verify isolated Claude Code evaluation capture"
	@echo "  config-authoring-openai-codex-capture-test  Verify isolated OpenAI Codex evaluation capture"
	@echo "  config-authoring-openai-codex-skill-test  Verify the release-bound ChatGPT/Codex configuration skill"
	@echo "  config-authoring-claude-skill-test  Verify the release-bound Claude Code configuration skill"
	@echo "  dco-signoff-test  Verify pull-request commit sign-off enforcement"
	@echo "  oss-release-bundle-test  Verify fail-closed release-bundle admission"
	@echo "  oss-candidate-intake-test  Verify hosted candidate intake and authority isolation"
	@echo "  oss-deb-builder-test  Verify public Debian build and reproducibility contracts"
	@echo "  oss-deb-hosted-contract-test  Verify the protected hosted-build contract"
	@echo "  oss-deb-builder-image-test  Verify the offline public Debian builder-image foundation"
	@echo "  oss-native-install-verifier-test  Verify native fresh-install evidence admission"
	@echo "  oss-native-install-collector-test  Verify the fail-closed disposable-host runner"
	@echo "  oss-kubernetes-deployment-verifier-test  Verify Kubernetes fresh-install observation controls"
	@echo "  oss-kubernetes-acceptance-runner-test  Verify disposable Kubernetes lifecycle and teardown controls"
	@echo "  oss-bounded-benchmark-verifier-test  Verify bounded benchmark evidence admission"
	@echo "  oss-bounded-benchmark-runner-test  Verify bounded benchmark execution and cleanup controls"
	@echo "  oss-oci-builder-test  Verify deterministic OCI assembly and offline builder contracts"
	@echo "  oss-oci-hosted-contract-test  Verify the protected hosted OCI build contract"
	@echo "  local-deployment-verifier-test  Verify the fail-closed Docker quickstart checker"
	@echo "  fmt-check      Check authored Go formatting"
	@echo "  dataplane-image Build the Linux/Seastar data-plane image"
	@echo "  dataplane-http2-deadline  Exercise HTTP/2 deadline and cancellation paths"
	@echo "  dataplane-http2-cookie    Exercise repeated HTTP/2 Cookie translation"
	@echo "  dedicated-preflight-rehearsal  Audit campaign readiness without authorizing spend"
	@echo "  native-logging-backpressure-ci  Exercise bounded native logging pressure"
	@echo "  up             Build and start the local stack"
	@echo "  verify-local-deployment  Check local roles, traffic, metrics, and runtime health"
	@echo "  verify-kubernetes-deployment  Check an installed acceptance deployment without mutation"
	@echo "  run-kubernetes-acceptance  Run the destructive disposable-cluster lifecycle gate"
	@echo "  run-bounded-benchmark  Run the bounded local benchmark reproduction"
	@echo "  down           Stop the local stack and remove its volumes"

dependencies:
	@npm ci --ignore-scripts

test: fmt-check test-go test-node test-python

test-go:
	@mkdir -p .cache/go-build
	@cd api/gen && go test ./...
	@cd control-plane && go test ./...
	@cd tools/host-tune && go test ./...

test-node:
	@npm test
	@node --test scripts/go-security-baseline.test.mjs
	@$(MAKE) config-authoring-contract-test
	@$(MAKE) config-authoring-cli-test
	@$(MAKE) config-authoring-corpus-test
	@$(MAKE) config-authoring-cross-surface-contract-test
	@$(MAKE) config-authoring-windows-large-input-test
	@$(MAKE) config-authoring-completion-test
	@$(MAKE) config-authoring-snippets-test
	@$(MAKE) config-authoring-reason-codes-test
	@$(MAKE) config-authoring-skill-contract-test
	@$(MAKE) config-authoring-skill-evaluations-test
	@$(MAKE) config-authoring-skill-evaluation-driver-test
	@$(MAKE) config-authoring-skill-lifecycle-test
	@$(MAKE) config-authoring-claude-capture-test
	@$(MAKE) config-authoring-openai-codex-capture-test
	@$(MAKE) config-authoring-openai-codex-skill-test
	@$(MAKE) config-authoring-claude-skill-test
	@$(MAKE) dco-signoff-test
	@$(MAKE) oss-release-bundle-test
	@$(MAKE) oss-candidate-intake-test
	@$(MAKE) local-deployment-verifier-test
	@$(MAKE) oss-kubernetes-deployment-verifier-test
	@$(MAKE) oss-kubernetes-acceptance-runner-test
	@$(MAKE) oss-bounded-benchmark-verifier-test
	@$(MAKE) oss-bounded-benchmark-runner-test
	@node --test scripts/verify-oss-deb-builder-image.test.mjs
	@$(MAKE) oss-deb-hosted-contract-test
	@node --test scripts/verify-oss-oci-builder-image.test.mjs
	@$(MAKE) oss-oci-hosted-contract-test

oss-release-bundle-test:
	@node --test scripts/verify-oss-release-bundle.test.mjs

oss-candidate-intake-test:
	@node --test scripts/intake-oss-release-candidate.test.mjs

dco-signoff-test:
	@node --test scripts/verify-dco-signoffs.test.mjs

config-authoring-contract-test:
	@node --test scripts/config-authoring-contract.test.mjs

config-authoring-cli-test:
	@node --test scripts/config-authoring-cli.test.mjs

config-authoring-corpus-test:
	@node --test scripts/config-authoring-corpus.test.mjs

config-authoring-cross-surface-contract-test:
	@node --test scripts/config-authoring-cross-surface-contract.test.mjs

config-authoring-windows-large-input-test:
	@node --test scripts/config-authoring-windows-large-input.test.mjs

config-authoring-completion-test:
	@node --test scripts/config-authoring-completion.test.mjs scripts/public-config-reference.test.mjs

config-authoring-snippets-test:
	@node --test scripts/config-authoring-snippets.test.mjs

config-authoring-reason-codes-test:
	@node --test scripts/config-authoring-reason-codes.test.mjs

config-authoring-skill-contract-test:
	@node --test scripts/config-authoring-skill-contract.test.mjs

config-authoring-skill-evaluations-test:
	@node --test scripts/config-authoring-skill-evaluations.test.mjs

config-authoring-skill-evaluation-driver-test:
	@node --test scripts/config-authoring-skill-evaluation-driver.test.mjs

config-authoring-skill-lifecycle-test:
	@node --test scripts/config-authoring-skill-lifecycle.test.mjs

config-authoring-claude-capture-test:
	@node --test scripts/config-authoring-claude-capture.test.mjs

config-authoring-openai-codex-capture-test:
	@node --test scripts/config-authoring-openai-codex-capture.test.mjs

config-authoring-openai-codex-skill-test:
	@node --test scripts/config-authoring-openai-codex-skill.test.mjs

config-authoring-claude-skill-test:
	@node --test scripts/config-authoring-claude-skill.test.mjs

oss-deb-builder-test:
	@python3 -B scripts/test_build_oss_deb.py

oss-deb-builder-image-test:
	@python3 -B scripts/test_oss_deb_builder_entrypoint.py
	@node --test scripts/verify-oss-deb-builder-image.test.mjs

oss-native-install-verifier-test:
	@python3 -B scripts/test_verify_oss_native_install.py

oss-native-install-collector-test:
	@python3 -B scripts/test_collect_oss_native_install.py

oss-kubernetes-deployment-verifier-test:
	@node --test scripts/verify-kubernetes-deployment.test.mjs

oss-kubernetes-acceptance-runner-test:
	@node --test scripts/run-oss-kubernetes-acceptance.test.mjs

oss-bounded-benchmark-verifier-test:
	@node --test scripts/verify-oss-bounded-benchmark.test.mjs

oss-bounded-benchmark-runner-test:
	@node --test scripts/run-oss-bounded-benchmark.test.mjs

run-bounded-benchmark:
	@test -n "$${BONVOYAGE_BOUNDED_BENCHMARK_EVIDENCE}" || \
		(echo "BONVOYAGE_BOUNDED_BENCHMARK_EVIDENCE is required" >&2; exit 2)
	@node scripts/run-oss-bounded-benchmark.mjs \
		--evidence "$${BONVOYAGE_BOUNDED_BENCHMARK_EVIDENCE}"

oss-oci-builder-test:
	@python3 -B scripts/test_build_oss_oci.py
	@python3 -B scripts/test_oss_oci_builder_entrypoint.py
	@node --test scripts/verify-oss-oci-builder-image.test.mjs

oss-deb-hosted-contract-test:
	@node --test scripts/verify-oss-deb-hosted-build.test.mjs

oss-oci-hosted-contract-test:
	@node --test scripts/verify-oss-oci-hosted-build.test.mjs

local-deployment-verifier-test:
	@node --test scripts/verify-local-deployment.test.mjs

test-python:
	@python3 -B -m unittest discover -s scripts -p 'test_*.py'

fmt-check:
	@files="$$(find api/gen control-plane tests/fixtures tools/host-tune \
		-type f -name '*.go' -print | sort | xargs gofmt -l)"; \
		if [ -n "$$files" ]; then \
			echo "Go files require formatting:" >&2; \
			echo "$$files" >&2; \
			exit 1; \
		fi

dataplane-image:
	@docker build --file deploy/docker/bonvoyage/Dockerfile \
		--tag routesphere-global/bonvoyage:dev .

dataplane-build: dataplane-image

dataplane-http2-deadline: dataplane-build
	@./scripts/phase3-http2-deadline.sh all

dataplane-http2-cookie: dataplane-build
	@BONVOYAGE_HTTP2_DEADLINE_EVIDENCE_DIR="$${BONVOYAGE_HTTP2_DEADLINE_EVIDENCE_DIR:+$${BONVOYAGE_HTTP2_DEADLINE_EVIDENCE_DIR}-cookie}" \
		./scripts/phase3-http2-deadline.sh cookie

dedicated-preflight-rehearsal:
	@node benchmarks/scripts/dedicated-preflight.mjs --mode rehearsal

native-logging-backpressure-ci:
	@docker build --target bonvoyage-build -t bonvoyage-native-logging-build:ci \
		-f deploy/docker/bonvoyage/Dockerfile .
	@python3 -B scripts/test-native-logging.py --scenario backpressure \
		--build-image bonvoyage-native-logging-build:ci \
		--output benchmarks/results/native-logging-backpressure-ci

up:
	@docker compose -f deploy/compose/local.yml up --build

verify-local-deployment:
	@./scripts/verify-local-deployment.sh

verify-kubernetes-deployment:
	@node scripts/verify-kubernetes-deployment.mjs

run-kubernetes-acceptance:
	@test -n "$${BONVOYAGE_KUBERNETES_EVIDENCE}" || \
		(echo "BONVOYAGE_KUBERNETES_EVIDENCE is required" >&2; exit 2)
	@node scripts/run-oss-kubernetes-acceptance.mjs \
		--evidence "$${BONVOYAGE_KUBERNETES_EVIDENCE}"

down:
	@docker compose -f deploy/compose/local.yml down --volumes
