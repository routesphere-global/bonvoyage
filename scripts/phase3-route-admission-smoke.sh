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
run_id="route-admission-smoke-$timestamp"
suffix="$$"
network="bonvoyage-route-admission-$suffix"
volume="bonvoyage-route-admission-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-route-admission-gateway-$suffix"
upstream="bonvoyage-route-admission-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-route-admission.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_ROUTE_ADMISSION_EVIDENCE_ROOT:-benchmarks/results/verification}"
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
    echo "route admission smoke failed; temporary evidence: $stage_dir" >&2
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
  -subj "/CN=BonVoyage Route Admission Test CA" \
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
  --volume "$PWD/tests/fixtures/phase3-route-admission.yaml:/etc/bonvoyage/route-admission.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/route-admission.yaml \
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

gateway = "http://bonvoyage-route-admission-gateway-'"$suffix"':8080"

def request(path, expected_status=200):
    value = urllib.request.Request(
        gateway + path,
        headers={"Host": "api.example.test"},
    )
    try:
        with urllib.request.urlopen(value, timeout=5) as response:
            status = response.status
            body = response.read()
            headers = dict(response.headers.items())
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read()
        headers = dict(error.headers.items())
    assert status == expected_status, (path, status, body)
    return body, headers

def error_code(body):
    return json.loads(body)["error"]["code"]

with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    admitted = executor.submit(request, "/circuit-http1/slow/700")
    time.sleep(0.15)
    rejected, _ = request("/circuit-http1/identity", 503)
    assert error_code(rejected) == "route_overloaded"
    assert admitted.result()[0] == b"upstream\n"
assert request("/circuit-http1/identity")[0] == b"upstream\n"

assert request("/identity/rate-http1")[0] == b"upstream\n"
assert request("/identity/rate-http1")[0] == b"upstream\n"
rejected, headers = request("/identity/rate-http1", 429)
assert error_code(rejected) == "rate_limited"
assert headers.get("Retry-After") == "1", headers
time.sleep(1.1)
assert request("/identity/rate-http1")[0] == b"upstream\n"

print(json.dumps({
    "concurrency": "one request rejected with route_overloaded and the route recovered",
    "rate_limit": "two requests admitted, one rejected with rate_limited, and one admitted after refill",
    "retry_after_seconds": 1,
}, indent=2, sort_keys=True))
' >"$stage_dir/http1-results.json"

docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  -n 2 -c 2 -p 1 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/endpoint-overload/slow/700 \
  >"$stage_dir/http2-concurrency.oha.json"

docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  -n 1 -c 1 -p 1 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/endpoint-overload/identity \
  >"$stage_dir/http2-concurrency-recovery.oha.json"

docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  -n 3 -c 1 -p 1 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/identity/rate-http2 \
  >"$stage_dir/http2-rate.oha.json"

sleep 2
docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  -n 1 -c 1 -p 1 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/identity/rate-http2 \
  >"$stage_dir/http2-rate-recovery.oha.json"

docker exec "$upstream" python -c '
import json

def distribution(path):
    with open(path, encoding="utf-8") as source:
        result = json.load(source)
    return result["statusCodeDistribution"]

concurrency = distribution("/tls/evidence/http2-concurrency.oha.json")
concurrency_recovery = distribution("/tls/evidence/http2-concurrency-recovery.oha.json")
rate = distribution("/tls/evidence/http2-rate.oha.json")
rate_recovery = distribution("/tls/evidence/http2-rate-recovery.oha.json")
assert concurrency == {"200": 1, "503": 1}, concurrency
assert concurrency_recovery == {"200": 1}, concurrency_recovery
assert rate == {"200": 2, "429": 1}, rate
assert rate_recovery == {"200": 1}, rate_recovery
print(json.dumps({
    "concurrency": concurrency,
    "concurrency_recovery": concurrency_recovery,
    "rate": rate,
    "rate_recovery": rate_recovery,
}, indent=2, sort_keys=True))
' >"$stage_dir/http2-validation.json"

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-route-admission-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$upstream" python -c '
import urllib.request

metrics = urllib.request.urlopen(
    "http://bonvoyage-route-admission-gateway-'"$suffix"':9090/metrics",
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

assert total("overload_rejections_total") == 2
assert total("route_overload_rejections_total") == 2
assert total("route_rate_limit_rejections_total") == 2
assert total("cluster_overload_rejections_total") == 0
assert total("endpoint_overload_rejections_total") == 0
assert total("active_route_requests") == 0
assert total("active_upstream_requests") == 0
print("route admission metrics and permit recovery passed")
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
route_concurrency_limit=1
route_rate_capacity=2
route_rate_refill_tokens_per_second=1
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 route admission and local rate-limit evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway enforced per-route concurrency and unkeyed local token buckets over cleartext HTTP/1.1 and TLS HTTP/2. Each protocol produced an exact concurrency rejection, an exact rate rejection, and a successful recovery without restart. The final metrics prove that no route or upstream request permits remained active.

Rate capacity and refill are independently owned by every shard, so aggregate capacity scales with shard count. This run validates correctness and bounded state. It does not qualify production throughput, fairness between clients, distributed/global quotas, or dedicated-host feature cost.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
dataplane/include/bonvoyage/runtime/route_admission.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/gateway.cc
dataplane/src/route_admission.cc
dataplane/src/runtime_snapshot.cc
dataplane/tests/route_admission_test.cc
dataplane/tests/runtime_snapshot_test.cc
scripts/phase3-route-admission-smoke.sh
scripts/test-fixture-secrets.sh
tests/fixtures/phase3-route-admission.yaml
EOF
while IFS= read -r source_file; do
  hash_file "$source_file"
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md compiler.txt gateway.inspect.json \
    gateway.log http1-results.json http2-concurrency-recovery.oha.json \
    http2-concurrency.oha.json http2-rate-recovery.oha.json \
    http2-rate.oha.json http2-validation.json metadata.txt \
    metrics-validation.txt metrics.prom runtime-image.inspect.json \
    source-checksums.sha256 upstream.log; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-route-admission-smoke.txt.tmp"
mv "$output_root/current-route-admission-smoke.txt.tmp" \
  "$output_root/current-route-admission-smoke.txt"

printf 'Route admission integration passed: %s\n' "$output_dir"
cat "$output_dir/http1-results.json"
cat "$output_dir/http2-validation.json"
cat "$output_dir/metrics-validation.txt"
