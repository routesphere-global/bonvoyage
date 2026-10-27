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
run_id="retry-smoke-$timestamp"
suffix="$$"
network="bonvoyage-retry-$suffix"
volume="bonvoyage-retry-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-retry-gateway-$suffix"
upstream="bonvoyage-retry-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-retry.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_RETRY_EVIDENCE_ROOT:-benchmarks/results/verification}"
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
    echo "retry smoke failed; temporary evidence: $stage_dir" >&2
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
  -subj "/CN=BonVoyage Retry Test CA" \
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
  --volume "$PWD/tests/fixtures/phase3-retry.yaml:/etc/bonvoyage/retry.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/retry.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
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

# Keep the successful retry and immediate budget rejection in one process so
# the second failure arrives well before the one-token-per-second refill.
docker exec "$upstream" python -c '
import json
import urllib.error
import urllib.request

gateway = "http://bonvoyage-retry-gateway-'"$suffix"':8080"

def request(path, method="GET", data=None):
    value = urllib.request.Request(
        gateway + path,
        method=method,
        data=data,
        headers={"Host": "api.example.test"},
    )
    try:
        with urllib.request.urlopen(value, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()

status, body = request("/retry/fail-once/http1-success")
assert status == 200 and body == b"attempt=2\n", (status, body)

status, body = request("/retry/fail-once/token-rejected")
assert status == 502 and b"upstream_failure" in body, (status, body)
attempts = urllib.request.urlopen(
    "http://upstream:8081/retry/attempts/token-rejected", timeout=5
).read()
assert attempts == b"1\n", attempts

payload = b"non-replayable-body"
status, body = request(
    "/retry/fail-once/bodyful-put", method="PUT", data=payload
)
assert status == 502 and b"upstream_failure" in body, (status, body)
attempts = urllib.request.urlopen(
    "http://upstream:8081/retry/attempts/bodyful-put", timeout=5
).read()
assert attempts == b"1\n", attempts
status, body = request(
    "/retry/fail-once/bodyful-put", method="PUT", data=payload
)
assert status == 200 and body == payload, (status, body)

print(json.dumps({
    "http1_fail_once": "retried_to_attempt_2",
    "token_budget": "second_retry_suppressed_before_refill",
    "bodyful_put": "not_retried_and_recovered_on_next_request",
}, indent=2, sort_keys=True))
' >"$stage_dir/http1-results.json"

sleep 2
docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  -n 1 -c 1 -p 1 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/retry/fail-once/http2-success \
  >"$stage_dir/http2.oha.json"

docker exec "$upstream" python -c '
import json
with open("/tls/evidence/http2.oha.json", encoding="utf-8") as source:
    result = json.load(source)
assert result["summary"]["successRate"] == 1, result
assert result["statusCodeDistribution"] == {"200": 1}, result
print("HTTP/2 fail-once retry passed")
' >"$stage_dir/http2-validation.txt"

sleep 2
docker exec "$upstream" python -c '
import json
import time
import urllib.error
import urllib.request

started = time.monotonic()
value = urllib.request.Request(
    "http://bonvoyage-retry-gateway-'"$suffix"':8080/slow-identity/250",
    headers={"Host": "api.example.test"},
)
try:
    urllib.request.urlopen(value, timeout=5)
    raise AssertionError("slow request unexpectedly succeeded")
except urllib.error.HTTPError as error:
    body = error.read()
    assert error.code == 504 and b"upstream_attempt_timeout" in body, (
        error.code, body
    )
elapsed = time.monotonic() - started
assert 0.15 <= elapsed < 1.5, elapsed

healthy = urllib.request.Request(
    "http://bonvoyage-retry-gateway-'"$suffix"':8080/identity/recovery",
    headers={"Host": "api.example.test"},
)
with urllib.request.urlopen(healthy, timeout=5) as response:
    assert response.status == 200 and response.read() == b"upstream\n"

print(json.dumps({
    "per_try_timeout_seconds": elapsed,
    "maximum_attempts": 2,
    "same_process_recovery": True,
}, indent=2, sort_keys=True))
' >"$stage_dir/timeout-recovery.json"

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-retry-gateway-'"$suffix"':9090/metrics", timeout=10
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$upstream" python -c '
import urllib.request

metrics = urllib.request.urlopen(
    "http://bonvoyage-retry-gateway-'"$suffix"':9090/metrics", timeout=10
).read().decode()

def total(suffix):
    value = 0.0
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        if name.split("{", 1)[0].endswith(suffix):
            value += float(raw)
    return value

assert total("retry_attempts_total") == 3
assert total("retry_successes_total") == 2
assert total("retry_exhausted_total") == 1
assert total("retry_token_rejections_total") == 1
assert total("retry_concurrency_rejections_total") == 0
assert total("retry_per_try_timeouts_total") == 2
assert total("retry_commit_suppressions_total") == 0
assert total("retry_non_replayable_suppressions_total") == 2
assert total("active_retries") == 0
assert total("active_upstream_requests") == 0
print("retry metrics passed")
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
retry_max_attempts=2
retry_per_try_timeout_ms=100
retry_budget_capacity=1
retry_budget_refill_tokens_per_second=1
retry_max_concurrent_per_shard=1
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 bounded retry evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway exercised one bounded cluster retry policy through cleartext HTTP/1.1 and TLS HTTP/2 downstream listeners. A transport failure before any response head was retried for a bodyless GET. A second immediate failure was denied by the empty token bucket. A bodyful PUT was never replayed. A slow upstream exhausted exactly two 100 ms response-head attempts, then the same gateway process served healthy traffic.

The concurrent-retry circuit breaker is covered deterministically by the C++ policy test; this live run also proves its gauge returns to zero. HTTP status retries, request-body buffering, hedging, and retries after response handoff remain unsupported by design.

The JSON records, Prometheus metrics, logs, image identity, source checksums, and evidence checksums preserve the supporting record.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
dataplane/CMakeLists.txt
dataplane/include/bonvoyage/runtime/retry_policy.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/gateway.cc
dataplane/src/retry_policy.cc
dataplane/src/runtime_snapshot.cc
dataplane/tests/retry_policy_test.cc
deploy/docker/upstream/server.py
scripts/phase3-retry-smoke.sh
scripts/test-fixture-secrets.sh
tests/fixtures/phase3-retry.yaml
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
    runtime-image.inspect.json source-checksums.sha256 \
    timeout-recovery.json upstream.log; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-retry-smoke.txt.tmp"
mv "$output_root/current-retry-smoke.txt.tmp" \
  "$output_root/current-retry-smoke.txt"

printf 'Bounded retry integration passed: %s\n' "$output_dir"
cat "$output_dir/metrics-validation.txt"
