# Scripts

`review-native-advisories.py` is a read-only verifier for retained source-bound
public GitHub/OSV observations. It rejects missing pages, response/hash drift,
wrong repository/commit identities and malformed evidence. Exit 0 verifies
observations only; coverage, scan acceptance and publication remain false.
`make native-advisory-review-test` runs 23 fixture methods, not advisory queries
or scans. See [Native Advisory Review](../docs/security/native-advisory-review.md)
for actual primary-source capture, the capped native DNS defect observation,
private evidence and the dependency correction required next.

Native SBOM validation preserves the raw generator's package references and
checks both enriched formats with the pinned official Syft decoder. Run
`make native-runtime-sbom-test vulnerability-summary-test` for focused fixture
regressions; these are not actual scanner, workload or release acceptance runs.

The shared Grype summary requires an explicit expected scanner-side SBOM path:
`node scripts/summarize-vulnerability-scan.mjs grype.json summary.json /out/runtime.cdx.json`.
Invalid/incomplete reports return 2 without creating a summary. Primary
High/Critical findings return 1; a complete report below that threshold returns
0, but always records `coverage_qualified=false`. Full dependency/advisory
coverage and release acceptance require separate evidence. The output must be
new, is mode 0600, and binds the raw report SHA256. Old or differently versioned
reports need their original historical verifier, not a relaxed current gate.

Small workflow entrypoints for development, tests, benchmarks, releases, and local operations.

`verify-oss-release-workflow.mjs` pins the manual protected-tag candidate-intake
and identity foundation in `.github/workflows/release.yml`. The intake job has
only read access to repository contents and Actions evidence. The downstream
identity job alone receives a GitHub OIDC token, solely to sign and verify the
fixed document created by `create-oss-release-identity-probe.mjs`. The verifier
rejects automatic triggers, workflow inputs, secrets, unpinned actions,
excessive permissions, changed tools or identities, product signing,
provenance, publication commands and authority escalation.

`discover-oss-release-candidate-runs.mjs` queries only fixed GitHub Actions API
endpoints. It requires exactly one successful run-attempt-one Debian run and
one OCI run for the exact release tag and commit, both created before the
current protected release run. It rejects duplicates, pagination, mixed
source, changed workflow identity, retries and future runs. The ephemeral
GitHub token is neither accepted as a command argument nor returned in output.
Run `make oss-release-workflow-test` for both focused adversarial suites.

`intake-oss-release-candidate.mjs` performs the fail-closed offline handoff from
the hosted Debian and OCI reproducibility workflows. It requires one exact clean
tagged public source, distinct run IDs, two byte-identical builders per format,
successful compiled tests and checksum-bound hosted receipts. It rejects mixed
runs, changed bytes, links, extra files, authority escalation and intake
contract drift. A successful run retains one payload per format plus all
non-payload evidence in a new directory and writes a canonical
`candidate-intake-receipt.json`. It never signs, uploads, publishes or admits a
release. Run `make oss-candidate-intake-test` for the portable adversarial
fixtures.

`verify-oss-native-install.py` independently admits one complete Ubuntu 24.04
AMD64 fresh-install evidence set. It binds the exact technical-candidate Debian
package and clean public-origin build receipt to six ordered lifecycle phases,
bounded fixed/proxied traffic, metric accounting, process/resource invariants,
the contract-bound deterministic fixture, an exact successful command journal,
raw metric/socket/removal semantics, and a complete checksum-verified
raw-evidence inventory. The verifier rejects
contract weakening, linked or extra evidence, failed checks and any attempt to
claim upgrade, rollback, Kubernetes, benchmark, release or publication
qualification. Run `make oss-native-install-verifier-test` for its portable
fixtures. These tests do not install a package or qualify a real Ubuntu host.

`collect-oss-native-install.py` is the corresponding privileged runner for one
pristine disposable Ubuntu 24.04 AMD64 host. It requires caller-supplied
SHA-256 values for the contract, Debian package, clean public-origin build
receipt and compiled snapshot; refuses existing BonVoyage package/account/state
or systemd overrides, including retained Debian config-files state; proves
install-inactive behavior; explicitly commissions
the service; sends exact fixed and loopback-upstream traffic; stops cleanly; and
removes package-owned files while retaining operator state. Failed attempts are
retained as non-authoritative diagnostics, and the runner never purges state.
Privileged package tools operate on private copies of the checksum-verified
bytes, preventing a mutable source pathname from changing the exercised input.
Command output is bounded, listeners are PID-filtered, and removal must preserve
the complete bounded state-tree and service identity. Run
`make oss-native-install-collector-test` for its 27 portable safety tests.
Those tests do not execute the privileged lifecycle.

`phase4-console-community-package.sh` builds and qualifies the proprietary,
no-cost Console Free Debian package for Ubuntu 24.04 AMD64. It requires a clean
source tree by default, independently rebuilds and compares the frontend,
static Go binary, and package bytes, validates the embedded CycloneDX 1.6,
SPDX 2.3, OpenVEX, payload, dependency, and license records, and exercises the
install/start/restart/upgrade/rollback/remove lifecycle on a network-isolated
target. A pinned ShellCheck image sees temporary script copies only.
Source-level `govulncheck` and raw plus VEX-filtered Grype scans retain
one reviewed module-only `GO-2026-5932` finding while requiring zero reachable
or actionable findings. `BONVOYAGE_ALLOW_DIRTY=1` is an explicit development
rehearsal only; its evidence cannot qualify a release or close the checkpoint.
Run `make console-package-test` for the bounded builder and verifier fixtures,
or `make phase4-console-community-package` for the complete acceptance gate.

`phase4-console-production-live.sh` starts a production HTTPS Console with a
temporary named Administrator, a separate delegation-enabled mTLS identity,
the real Admin API, one live dataplane, and a controlled upstream. Its
`acceptance` action drives a listener NACK, exact rollback, corrected
activation, live traffic, process continuity, and Console audit proof. The
generated password remains under the private runtime directory and is scanned
out of retained evidence.

`phase4-console-exit.sh` is the Checkpoint 13 consolidation gate. It replays
the versioned 21-operation register in
`console/acceptance/phase4-exit-register.json`, verifies 22 retained checksum
manifests with relocation-safe digest replay, reruns Console and focused Go
tests, and binds the production-authenticated browser path to the accepted
three-node controller-outage record. Run it with `make phase4-console-exit`;
the gate makes no performance, signing, or publication claim.

`phase3-accept-recovery.sh` (or `make dataplane-accept-recovery`) forces a
128-descriptor limit on an isolated gateway, opens client connections until
accept exhausts descriptors, releases them, and verifies recovery without a
restart plus clean shutdown. It retains commands' outputs, image/source state,
process identity and gateway logs beneath
`BONVOYAGE_ACCEPT_RECOVERY_EVIDENCE_DIR` (default `build/evidence/`). It is a
bounded resource-failure regression, not a throughput or capacity measurement.

Native internal-network fixtures explicitly disable inherited DNS search
suffixes for the gateway. The route-scale fixture respects a locked runtime
image, sets gateway `nofile=65536:65536`, and caps the configured downstream
limit at 60,000 for headroom. See the internal
[extended verification record](../docs/implementation/aws-amd64-extended-verification.md)
for the reproduced failures, ownership constraints and remaining native gates.

`qualify-runtime-dependencies.sh` retains raw and augmented runtime SBOMs,
saved OCI bytes, independent image binding and both pinned Grype scans.
The production builder stamps the current Git revision and complete-tree dirty
state into the image. Locked qualification requires those labels to match a
clean Linux AMD64 checkout, exports the same never-started container used for image
records, runs `inspect-runtime-glibc-reachability.py`, and then uses
`bind-runtime-glibc-reachability.py` to bind source, image, scan and analyzer
receipts. The binding does not authorize VEX, suppression, reachability closure,
publisher authenticity or release.
`scan-runtime-sbom-pair.py` downloads one fresh database into
`dual-format/database`, then mounts it read-only for two offline scans.
An 8 GiB free-disk preflight replaces transient database tmpfs capacity;
unset the obsolete `BONVOYAGE_GRYPE_CACHE_MIB` variable. The database is
retained for replay, not deleted automatically. Both schemas still require
their separate official validators before release acceptance.

Real Syft decoders must recover equal nonempty package/PURL/CPE/upstream
inventories and Ubuntu 24.04. `verify-runtime-scan-parity.mjs` checks exact
representation-specific image identities, policies, database metadata and
full normalized finding multisets. Physical database files are checksum-bound
before and after each scan. Exit 1 means valid evidence blocked by High/Critical
findings; exit 2 means invalid/incomplete evidence. Legacy CDX summary filenames
remain available to existing artifact-lock consumers, but do not substitute
for the additional pair receipt. Coverage/native/release acceptance is not
inferred from a zero-match result. Commands, errors and failed attempts are
retained; a database activation failure is never a zero-finding result.

`phase3-route-scale-connection-density.sh` builds a deterministic test-only
Protobuf snapshot generator and verified keep-alive holder, then qualifies one
shard at 1K/10K/100K exact routes and 1K/4K/8K held downstream connections. It
asserts positional route correctness, configured-route and active-connection
gauges, zero admission rejection, concurrent active progress, complete release,
same-process recovery, bounded retained RSS, graceful exit, source/image
identity, and checksummed evidence. Its Docker Desktop measurements are local,
directional, and explicitly barred from capacity or marketing use.

`phase3-protocol-interoperability.sh` runs one unchanged single-shard gateway
against a pinned libcurl client, the existing grpc-go fixture, a hash-locked
gRPC Python client, and a hash-locked Python websockets client. The isolated
matrix covers cleartext and CA-verified TLS HTTP/1.1, CA-verified TLS HTTP/2,
unary gRPC metadata/status/large-response/recovery behavior, and RFC 6455
text/binary/ping/subprotocol behavior over cleartext and TLS. Wrong-hostname
negative checks, exact client versions, final active gauges, process identity,
clean drain, image identities, source checksums, and non-publishable retained
evidence are mandatory. This is a manual local/release gate and is deliberately
not added to every GitHub Actions push.

`phase3-observability-decision-telemetry.sh` runs a two-shard gateway and pinned
Prometheus on an isolated network, drives controlled success, rejection,
route-miss, and upstream-failure traffic, and verifies configuration metadata,
response outcomes, canonical histograms, shard participation, live recording
rules, and the telemetry privacy boundary. It retains checksum-bound local
engineering evidence and explicitly disallows performance, marketing, billing,
or SLO use.

`phase3-saas-canary-telemetry-failure.sh` composes two synthetic tenants with
separate API keys and upstream pools, static 75/25 canary routing, quota and
overload admission, one-tenant failure, collector loss, slow metrics consumers,
privacy canaries, and no-restart recovery. Its retained persona summary maps the
same evidence to infrastructure, systems, sales, business-analysis, CEO, and CTO
decisions without turning operational counters into billing or marketing data.
`phase3-saas-canary-client.py` supplies the dependency-free request, isolation,
privacy, and slow-consumer workloads without retaining ephemeral credentials.

`phase3-composite-hardening.sh` runs one checksum-bound local matrix across two
or more dataplane shards. It combines independent HTTP/1.1 connections, TLS
HTTP/2 streams, native unary gRPC, and HTTP/1.1 WebSocket churn with route
saturation, weighted-route degradation, endpoint ejection/reactivation,
no-restart recovery, per-shard participation, final-gauge, allocator-failure,
RSS-growth, and clean-drain assertions. The retained result is explicitly local
and non-publishable; dedicated feature cost and multi-hour qualification remain
separate gates.

`phase3-multi-hour-hardening.sh` keeps one two-shard gateway process alive under
rate-limited TLS HTTP/2 while repeated cycles add HTTP/1.1, unary gRPC,
WebSocket, route saturation, canary failure, endpoint ejection, and OTLP
collector loss/recovery. Bounded access logging and tracing remain enabled. The
harness samples CPU, RSS, process count, file descriptors, support-container
headroom, metrics, sink state, and process identity; validates final queue and
active-gauge drain; checks access-log privacy; and retains checksum-bound local
evidence. Canary recovery first uses a separately recorded connection-fanout
probe and requires every shard's open and half-open circuit gauges to reach
zero before the strict concurrent all-success window. Long runs disable
per-request logging in the synthetic HTTP upstreams to keep Docker and failure
archives bounded. The default eight-hour target and explicit three-minute
preflight are manual only and are not part of per-push GitHub Actions.

`phase5-http1-slow-reader.sh` (or `make dataplane-http1-slow-reader`) exercises
plaintext and CA-verified TLS HTTP/1.1 cancellation with a client that stops
reading a bounded 32 MiB streamed response. It also stalls a valid declared
request body, verifies the exact pre-response `504 request_timeout` contract,
then proves same-process recovery. Three repetitions per protocol must release
the request, route, upstream and connection gauges while the peer remains open;
the enclosing gate requires unchanged process identity, no descriptor growth,
bounded RSS, clean shutdown, a clean sanitizer/assertion log scan and replayable
SHA-256 evidence. The default 16 MiB RSS bound is the release contract. Any
larger sanitizer-only bound must be explicit in retained evidence and cannot be
used as release RSS evidence.

`phase3-http2-deadline.sh all` exercises zero-window responses below and above
the session queue cap, peer cancellation, healthy-stream isolation, normal
fixed/proxied transfers, and a TLS client that stops reading a 16 MiB response.
The pinned frame-level Go client verifies deadline-bound reset or transport
cleanup, route-permit release, exact counters, unchanged process identity, and
clean shutdown. It retains checksummed evidence without ephemeral private keys.
This manual local regression is not a throughput or long-duration qualification.

`phase3-http2-deadline.sh cookie` (or `make dataplane-http2-cookie`) reuses
that isolated client and harness for split Cookie translation into an HTTP/1.1
upstream. It checks exact values and order, same-connection state isolation,
bounded large headers, rejection before upstream dispatch, and recovery. The
Cookie mode is a separate gate from the deadline matrix.

`phase3-websocket-smoke.sh` runs a controlled raw RFC 6455 upstream and client
against cleartext and TLS HTTP/1.1 listeners. It verifies strict client and
upstream handshakes, immediate post-header bytes, opaque bidirectional
tunneling, route concurrency, request and idle deadlines, ordinary non-101
responses, fixed-cardinality metrics, recovery, coordinated drain, and
checksum-bound local engineering evidence.

`phase4-console-websocket-lifecycle.sh` qualifies the guided Console ownership
of the existing bounded HTTP/1.1 WebSocket policy. It verifies fail-closed YAML
inspection, the shared route-concurrency safeguard, generated Admin contracts,
unit and desktop/compact browser matrices, dependency audit, sanitized compiler
rejection, exact immutable activation, authoritative `ADMISSION` plus
`WEBSOCKET` inventory, and an independent raw-client `426`/`101` frame and
recovery proof. Evidence is checksum-bound local functional engineering
evidence; it does not claim HTTP/2 extended CONNECT, production capacity, or
performance.

`phase4-console-runtime-limits-lifecycle.sh` qualifies guided ownership of all
seven global runtime limits. It verifies exact compiler bounds, dependency-safe
body and retry timeout reductions, fail-closed future YAML, generated contracts,
unit and desktop/compact browser matrices, dependency audit, immutable live
activation, request header/body limits, upstream header/chunk limits, request
and idle deadlines, per-shard connection rejection, unchanged process identity,
zero restarts, and post-probe recovery. The retained record is dirty-source
local functional evidence and makes no capacity or marketing claim.

`phase4-console-listener-lifecycle.sh` qualifies guided listener ownership and
keeps operational consequences explicit. It verifies round-trip add, duplicate,
edit, and remove behavior; fail-closed future YAML; complete unit and browser
matrices; and the live-safe name, virtual-host, and trusted-proxy path. A port
change must return a structured `snapshot.listener_restart_required` NACK while
the last-known-good listener and process continue serving. Separate controlled
restart and restoration probes then prove the proposed and prior bindings. The
pinned ShellCheck container sees only temporary copies of the reviewed scripts;
private source, credentials, and evidence are not mounted. The retained record
is local functional evidence and does not claim listener hot replacement,
capacity, or performance.

`phase4-console-node-lifecycle.sh` qualifies durable standalone node identity
and lifecycle management. It verifies one-time enrollment, consumed-token
replay rejection, token reissue invalidation, metadata edits, linked
replacement, exact rollout target selection, drain semantics, disconnected
retirement, connected-node retirement rejection, identity revocation, bounded
append-only history, and post-revocation traffic continuity. Its companion
`phase4-console-node-lifecycle-live.sh` drives two real dataplanes through the
Console, scans retained evidence for all three raw enrollment tokens, and binds
the result to source, browser, API, process, and checksum evidence. The record
is local functional engineering evidence and makes no capacity or performance
claim.

`phase4-console-rollout-recovery.sh` qualifies operator diagnosis and recovery
from a real pre-activation NACK. Its live companion changes a listener binding,
proves the rejected candidate never replaces last-known-good traffic, renders
structured node and field diagnostics, restores the exact retained artifact
under a new monotonic sequence, and loads the immutable rejected YAML for a
corrected activation. The gate replays the OpenAPI, Go, fixture, Console,
browser, audit, process-identity, dependency, and checksum evidence. The record
is dirty-source local functional engineering evidence and makes no capacity or
performance claim.

`phase3-weighted-traffic-splitting-smoke.sh` runs separate stable and canary
upstreams behind one shard-local gateway. It verifies exact 75/25 cycles over
HTTP/1.1 and TLS HTTP/2, policy and local-response ordering, retry pinning,
pre-upstream rewrite-limit isolation, an unchanged direct route, exact metrics,
credential sanitation, and checksum-bound local engineering evidence.

`phase3-header-transformations-smoke.sh` builds an isolated compiler, gateway,
and controlled upstream; verifies static request/response field mutations over
HTTP/1.1 and TLS HTTP/2; checks authentication, CORS ordering, transformed
request/response limits, and no-restart recovery; prevents an ephemeral API key
from entering retained artifacts; validates fixed-cardinality metrics; and
writes checksum-bound local engineering evidence under
`benchmarks/results/verification/`.

`phase3-route-rewrites-smoke.sh` compiles and runs one immutable snapshot that
combines API-key and CORS policy, request-header transformation, static
authority replacement, full-path replacement, matched-prefix replacement,
retry reconstruction, rewritten-target limits, and an untouched route. Its
HTTP/1.1 and TLS HTTP/2 clients assert exact statuses while a controlled
upstream records authority, raw target, forwarding identity, retry equality,
pre-upstream `414` isolation, and same-process recovery. The checksum-bound
record is local engineering evidence under `benchmarks/results/verification/`.
