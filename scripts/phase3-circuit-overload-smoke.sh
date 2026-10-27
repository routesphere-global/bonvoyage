#!/bin/sh
set -eu

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="circuit-overload-smoke-$timestamp"
suffix="$$"
network="bonvoyage-circuit-overload-$suffix"
volume="bonvoyage-circuit-overload-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-circuit-overload-gateway-$suffix"
upstream="bonvoyage-circuit-overload-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-circuit-overload.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_CIRCUIT_OVERLOAD_EVIDENCE_ROOT:-benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"

cleanup() {
  status="$?"
  if [ -d "$stage_dir" ] && docker inspect "$gateway" >/dev/null 2>&1; then
    docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1 || true
  fi
  if [ -d "$stage_dir" ] && docker inspect "$upstream" >/dev/null 2>&1; then
    docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1 || true
  fi
  if [ "$status" -ne 0 ]; then
    echo "circuit/overload smoke failed; temporary evidence: $stage_dir" >&2
    if [ -f "$stage_dir/gateway.log" ]; then
      cat "$stage_dir/gateway.log" >&2
    fi
  fi
  docker rm --force "$gateway" "$upstream" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$work_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  if [ "$status" -eq 0 ]; then
    rm -rf "$work_dir"
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

for command_name in date docker git mktemp openssl uname; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name is required" >&2
    exit 1
  }
done

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage Circuit Test CA" \
  -keyout "$work_dir/ca-key.pem" -out "$work_dir/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=api.example.test" \
  -keyout "$work_dir/server-key.pem" -out "$work_dir/server.csr" \
  >/dev/null 2>&1
printf '%s\n' \
  "subjectAltName=DNS:api.example.test" \
  "extendedKeyUsage=serverAuth" \
  "keyUsage=digitalSignature,keyEncipherment" >"$work_dir/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work_dir/server.csr" \
  -CA "$work_dir/ca.pem" -CAkey "$work_dir/ca-key.pem" -CAcreateserial \
  -extfile "$work_dir/server-ext.cnf" -out "$work_dir/server-chain.pem" \
  >/dev/null 2>&1
chmod 600 "$work_dir"/*-key.pem

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-circuit-overload.yaml:/etc/bonvoyage/circuit-overload.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/circuit-overload.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --env BONVOYAGE_UPSTREAM_ID=upstream \
  --volume "$work_dir:/tls:ro" "$upstream_image" >/dev/null
docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$image" \
  --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 256M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug >/dev/null

bv_wait_gateway_ready "$gateway" "$upstream" "http://$gateway:9901/health/ready"

docker exec "$upstream" python -c '
import concurrent.futures
import json
import time
import urllib.error
import urllib.request

gateway = "http://bonvoyage-circuit-overload-gateway-'"$suffix"':8080"

def request(path, expected_status=200):
    value = urllib.request.Request(
        gateway + path,
        headers={"Host": "api.example.test"},
    )
    try:
        with urllib.request.urlopen(value, timeout=5) as response:
            status = response.status
            body = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read()
    assert status == expected_status, (path, status, body)
    return body

def error_code(body):
    return json.loads(body)["error"]["code"]

assert error_code(request("/circuit-http1/always-fail", 502)) == "upstream_failure"
assert error_code(request("/circuit-http1/identity", 503)) == "no_healthy_upstream"
time.sleep(0.65)
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    probe = executor.submit(request, "/circuit-http1/slow/500")
    time.sleep(0.15)
    blocked_probe = request("/circuit-http1/identity", 503)
    assert error_code(blocked_probe) == "upstream_overloaded"
    assert probe.result() == b"upstream\n"
assert request("/circuit-http1/identity") == b"upstream\n"

assert error_code(request("/circuit-http1/always-fail", 502)) == "upstream_failure"
time.sleep(0.65)
assert error_code(request("/circuit-http1/always-fail", 502)) == "upstream_failure"
assert error_code(request("/circuit-http1/identity", 503)) == "no_healthy_upstream"
time.sleep(0.65)
assert request("/circuit-http1/identity") == b"upstream\n"

with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    active = executor.submit(request, "/endpoint-overload/slow/500")
    time.sleep(0.15)
    endpoint_rejection = request("/endpoint-overload/identity", 503)
    assert error_code(endpoint_rejection) == "upstream_overloaded"
    assert active.result() == b"upstream\n"
assert request("/endpoint-overload/identity") == b"upstream\n"

with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    first = executor.submit(request, "/cluster-overload/slow/700")
    second = executor.submit(request, "/cluster-overload/slow/700")
    time.sleep(0.2)
    cluster_rejection = request("/cluster-overload/identity", 503)
    assert error_code(cluster_rejection) == "upstream_overloaded"
    assert first.result() == b"upstream\n"
    assert second.result() == b"upstream\n"
assert request("/cluster-overload/identity") == b"upstream\n"

assert error_code(request("/circuit-http2/always-fail", 502)) == "upstream_failure"
assert error_code(request("/circuit-http2/identity", 503)) == "no_healthy_upstream"

print(json.dumps({
    "cluster_admission": "third concurrent request rejected and recovered",
    "endpoint_admission": "second endpoint request rejected and recovered",
    "half_open_probe": "one slow probe admitted and concurrent probe rejected",
    "http1_circuit": "opened, half-opened, closed, reopened, and recovered",
    "http2_circuit": "opened and blocked before HTTP/2 recovery",
}, indent=2, sort_keys=True))
' >"$stage_dir/http1-results.json"

sleep 1
docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  -n 1 -c 1 -p 1 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/circuit-http2/identity \
  >"$stage_dir/http2.oha.json"

docker exec "$upstream" python -c '
import json
import urllib.request

with open("/tls/evidence/http2.oha.json", encoding="utf-8") as source:
    result = json.load(source)
assert result["summary"]["successRate"] == 1, result
assert result["statusCodeDistribution"] == {"200": 1}, result

value = urllib.request.Request(
    "http://bonvoyage-circuit-overload-gateway-'"$suffix"':8080/circuit-http2/identity",
    headers={"Host": "api.example.test"},
)
with urllib.request.urlopen(value, timeout=5) as response:
    assert response.status == 200 and response.read() == b"upstream\n"
print("HTTP/2 half-open recovery and subsequent HTTP/1.1 traffic passed")
' >"$stage_dir/http2-validation.txt"

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-circuit-overload-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$upstream" python -c '
import urllib.request

metrics = urllib.request.urlopen(
    "http://bonvoyage-circuit-overload-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode()

def total(suffix):
    value = 0.0
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        if name.split("{", 1)[0] == "bonvoyage_bonvoyage_gateway_" + suffix:
            value += float(raw)
    return value

assert total("overload_rejections_total") == 3
assert total("cluster_overload_rejections_total") == 1
assert total("endpoint_overload_rejections_total") == 1
assert total("endpoint_circuit_opens_total") == 3
assert total("endpoint_circuit_half_open_transitions_total") == 4
assert total("endpoint_circuit_closes_total") == 3
assert total("endpoint_circuit_reopens_total") == 1
assert total("endpoint_circuit_probe_rejections_total") == 1
assert total("upstream_no_eligible_endpoints_total") == 3
assert total("open_endpoint_circuits") == 0
assert total("half_open_endpoint_circuits") == 0
assert total("active_upstream_requests") == 0
pool_waits = total("upstream_http1_pool_waits_total")
pool_wait_nanoseconds = total("upstream_http1_pool_wait_nanoseconds_total")
pool_wait_max_nanoseconds = total("upstream_http1_pool_wait_max_nanoseconds")
assert pool_waits >= 1
assert pool_wait_nanoseconds > 0
assert pool_wait_max_nanoseconds > 0
assert pool_wait_nanoseconds / pool_waits <= pool_wait_max_nanoseconds
print(
    "circuit, overload, and HTTP/1 pool-wait duration metrics passed "
    f"(waits={pool_waits:.0f}, total_ns={pool_wait_nanoseconds:.0f}, "
    f"max_ns={pool_wait_max_nanoseconds:.0f})"
)
' >"$stage_dir/metrics-validation.txt"

docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1
docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1

source_commit="$(git rev-parse HEAD)"
if [ -z "$(git status --porcelain)" ]; then
  source_dirty=false
else
  source_dirty=true
fi
runtime_image_id="$(docker image inspect "$image" --format '{{.Id}}')"
cat >"$stage_dir/metadata.txt" <<EOF
captured_at_utc=$timestamp
run_id=$run_id
source_commit=$source_commit
source_dirty=$source_dirty
host=$(uname -s) $(uname -r) $(uname -m)
platform=$platform
runtime_image=$image
runtime_image_id=$runtime_image_id
gateway_shards=1
circuit_failure_threshold=1
circuit_open_interval_ms=500
circuit_half_open_max_active_probes=1
circuit_success_threshold=1
endpoint_concurrency_limit=1
cluster_admission_limit=2
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 endpoint-circuit and overload evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway exercised passive endpoint circuits through closed, open, half-open, closed, and reopened states. Exactly one half-open probe was admitted. Concurrent recovery work, per-endpoint saturation, and cluster-wide saturation failed immediately with stable 503 responses. Healthy traffic recovered without a gateway restart.

The circuit recovery path was exercised through cleartext HTTP/1.1 and TLS HTTP/2 downstream listeners. Metrics, logs, image identity, source checksums, and evidence checksums preserve the record. This run does not qualify dedicated-host feature cost, saturation curves, memory growth, or production readiness.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
dataplane/include/bonvoyage/runtime/endpoint_selector.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/endpoint_selector.cc
dataplane/src/gateway.cc
dataplane/src/runtime_snapshot.cc
dataplane/tests/endpoint_selector_test.cc
dataplane/tests/runtime_snapshot_test.cc
deploy/docker/upstream/server.py
scripts/phase3-circuit-overload-smoke.sh
scripts/test-fixture-secrets.sh
tests/fixtures/phase3-circuit-overload.yaml
EOF
while IFS= read -r source_file; do
  hash_file "$source_file"
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md compiler.txt gateway.inspect.json \
    gateway.log http1-results.json http2-validation.txt http2.oha.json \
    metadata.txt metrics-validation.txt metrics.prom \
    runtime-image.inspect.json source-checksums.sha256 upstream.log; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-circuit-overload-smoke.txt.tmp"
mv "$output_root/current-circuit-overload-smoke.txt.tmp" \
  "$output_root/current-circuit-overload-smoke.txt"

printf 'Endpoint circuit and overload integration passed: %s\n' "$output_dir"
cat "$output_dir/metrics-validation.txt"
