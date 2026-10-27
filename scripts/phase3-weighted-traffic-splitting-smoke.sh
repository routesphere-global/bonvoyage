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
run_id="weighted-traffic-splitting-smoke-$timestamp"
suffix="$$"
network="bonvoyage-weighted-traffic-$suffix"
volume="bonvoyage-weighted-traffic-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-weighted-traffic-gateway-$suffix"
stable="bonvoyage-weighted-traffic-stable-$suffix"
canary="bonvoyage-weighted-traffic-canary-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-weighted-traffic.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_WEIGHTED_TRAFFIC_EVIDENCE_ROOT:-benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"

cleanup() {
  status="$?"
  if [ -d "$stage_dir" ]; then
    docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1 || true
    docker logs "$stable" >"$stage_dir/stable-upstream.log" 2>&1 || true
    docker logs "$canary" >"$stage_dir/canary-upstream.log" 2>&1 || true
  fi
  docker rm --force "$gateway" "$stable" "$canary" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$work_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  if [ "$status" -eq 0 ]; then
    rm -rf "$work_dir"
  else
    echo "weighted traffic smoke failed; temporary evidence: $stage_dir" >&2
    sed -n '1,240p' "$stage_dir/gateway.log" >&2 || true
    sed -n '1,160p' "$stage_dir/stable-upstream.log" >&2 || true
    sed -n '1,160p' "$stage_dir/canary-upstream.log" >&2 || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

for command_name in date docker git grep mktemp openssl python3 sed sleep uname; do
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

h2_request() {
  output="$1"
  shift
  raw_output="$work_dir/$output.raw"
  docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" --volume "$work_dir:/tls:ro" "$oha_image" --debug --no-color --http-version 2 --disable-compression --no-tui -n 1 --cacert /tls/ca.pem "$@" >"$raw_output" 2>&1
  sed "s/$api_key/[REDACTED]/g" "$raw_output" >"$stage_dir/$output"
  rm "$raw_output"
}

assert_h2_status() {
  file="$1"
  status="$2"
  grep -Eiq "status[^0-9]*$status|HTTP/2(\.0)?[[:space:]]+$status" "$stage_dir/$file"
}

assert_h2_upstream() {
  file="$1"
  upstream_id="$2"
  grep -Fiq "\"x-upstream-id\": \"$upstream_id\"" "$stage_dir/$file"
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 -subj "/CN=BonVoyage Weighted Traffic Test CA" -keyout "$work_dir/ca-key.pem" -out "$work_dir/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 -subj "/CN=api.example.test" -keyout "$work_dir/server-key.pem" -out "$work_dir/server.csr" >/dev/null 2>&1
printf '%s\n' "subjectAltName=DNS:api.example.test" "extendedKeyUsage=serverAuth" "keyUsage=digitalSignature,keyEncipherment" >"$work_dir/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work_dir/server.csr" -CA "$work_dir/ca.pem" -CAkey "$work_dir/ca-key.pem" -CAcreateserial -extfile "$work_dir/server-ext.cnf" -out "$work_dir/server-chain.pem" >/dev/null 2>&1
api_key="$(openssl rand -hex 16)"
printf '%s\n' "$api_key" >"$work_dir/weighted-api-keys.txt"
chmod 600 "$work_dir"/*-key.pem "$work_dir/weighted-api-keys.txt"

docker buildx build --platform "$platform" --load --tag "$compiler_image" --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem weighted-api-keys.txt

docker run --rm --platform "$platform" --volume "$PWD/tests/fixtures/phase3-weighted-traffic-splitting.yaml:/etc/bonvoyage/weighted.yaml:ro" --volume "$volume:/var/lib/bonvoyage" "$compiler_image" -input /etc/bonvoyage/weighted.yaml -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

for upstream_id in stable canary; do
  if [ "$upstream_id" = "stable" ]; then
    container="$stable"
  else
    container="$canary"
  fi
  docker run --detach --platform "$platform" --name "$container" --network "$network" --network-alias "$upstream_id" --env "BONVOYAGE_UPSTREAM_ID=$upstream_id" --entrypoint python --volume "$PWD/scripts/phase3-weighted-traffic-upstream.py:/weighted-upstream.py:ro" --volume "$PWD/scripts/phase3-weighted-traffic-client.py:/weighted-client.py:ro" "$upstream_image" /weighted-upstream.py >/dev/null
done

for container in "$stable" "$canary"; do
  attempt=0
  until docker exec "$container" python -c 'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:8081/healthz", timeout=1).status == 200' >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
      echo "controlled upstream did not become ready: $container" >&2
      exit 1
    fi
    sleep 1
  done
done

docker run --detach --platform "$platform" --name "$gateway" --network "$network" --network-alias api.example.test --volume "$volume:/snapshot:ro" --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$image" --snapshot /snapshot/snapshot.pb --secrets-directory /etc/bonvoyage/secrets --admin-address 0.0.0.0 --metrics-address 0.0.0.0 --smp 1 --memory 256M --overprovisioned --logger-log-level bonvoyage-gateway=debug >/dev/null

bv_wait_gateway_ready "$gateway" "$stable" "http://$gateway:9901/health/ready"

docker exec "$stable" python /weighted-client.py "bonvoyage-weighted-traffic-gateway-$suffix" "$api_key" >"$stage_dir/http1-results.json"

h2_request http2-auth-missing.txt -H "x-client-protocol: h2" 'https://api.example.test:8443/split/item?request=h2-missing'
assert_h2_status http2-auth-missing.txt 401
grep -Fq unauthorized "$stage_dir/http2-auth-missing.txt"

h2_request http2-preflight.txt -m OPTIONS -H "origin: https://app.example.com" -H "access-control-request-method: GET" -H "x-client-protocol: h2" 'https://api.example.test:8443/split/item'
assert_h2_status http2-preflight.txt 204

index=0
for expected in stable stable canary stable stable stable canary stable; do
  output="http2-split-$index.txt"
  h2_request "$output" -H "x-api-key: $api_key" -H "origin: https://app.example.com" -H "x-client-protocol: h2" "https://api.example.test:8443/split/item?request=h2-$index"
  assert_h2_status "$output" 200
  assert_h2_upstream "$output" "$expected"
  index=$((index + 1))
done

h2_request http2-retry.txt -H "x-request-id: retry-h2" -H "x-client-protocol: h2" 'https://api.example.test:8443/retry'
assert_h2_status http2-retry.txt 200
assert_h2_upstream http2-retry.txt canary

long_query="$(python3 -c 'print("q" * 400)')"
h2_request http2-limit.txt -H "x-client-protocol: h2" "https://api.example.test:8443/bounded?padding=$long_query"
assert_h2_status http2-limit.txt 414
grep -Fq rewritten_request_target_too_large "$stage_dir/http2-limit.txt"

h2_request http2-bounded.txt -H "x-client-protocol: h2" 'https://api.example.test:8443/bounded?ok=h2'
assert_h2_status http2-bounded.txt 200
assert_h2_upstream http2-bounded.txt canary

h2_request http2-direct.txt -H "x-client-protocol: h2" 'https://api.example.test:8443/direct'
assert_h2_status http2-direct.txt 200
assert_h2_upstream http2-direct.txt stable

docker exec "$stable" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-weighted-traffic-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$stable" python -c '
import urllib.request
metrics = urllib.request.urlopen(
    "http://bonvoyage-weighted-traffic-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode()
def total(suffix):
    result = 0.0
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        if name.split("{", 1)[0] == "bonvoyage_bonvoyage_gateway_" + suffix:
            result += float(raw)
    return result
assert total("requests_total") == 28
assert total("responses_2xx_total") == 24
assert total("responses_4xx_total") == 4
assert total("responses_5xx_total") == 0
assert total("api_key_auth_successes_total") == 16
assert total("api_key_auth_rejections_total") == 2
assert total("cors_actual_allows_total") == 16
assert total("cors_preflight_successes_total") == 2
assert total("route_weighted_cluster_selections_total") == 20
assert total("request_header_transformation_applications_total") == 20
assert total("request_path_rewrite_applications_total") == 22
assert total("request_rewrite_limit_rejections_total") == 2
assert total("retry_attempts_total") == 2
assert total("retry_successes_total") == 2
assert total("upstream_endpoint_selections_total") == 24
assert total("upstream_failures_total") == 0
assert total("route_misses_total") == 0
assert total("active_route_requests") == 0
assert total("active_upstream_requests") == 0
assert total("active_retries") == 0
print("weighted route metrics and final gauges passed")
' >"$stage_dir/metrics-validation.txt"

docker logs "$stable" >"$stage_dir/stable-upstream.log" 2>&1
docker logs "$canary" >"$stage_dir/canary-upstream.log" 2>&1
python3 - "$stage_dir/stable-upstream.log" "$stage_dir/canary-upstream.log" >"$stage_dir/upstream-validation.txt" <<'PY'
import json
import sys


def records(path):
    result = []
    with open(path, encoding="utf-8") as source:
        for line in source:
            if line.startswith("REQUEST "):
                result.append(json.loads(line.removeprefix("REQUEST ")))
    return result


stable = records(sys.argv[1])
canary = records(sys.argv[2])
assert len(stable) == 17, len(stable)
assert len(canary) == 7, len(canary)
all_records = stable + canary
assert sum(item["path"].startswith("/weighted/item") for item in stable) == 12
assert sum(item["path"].startswith("/weighted/item") for item in canary) == 4
assert sum(item["path"] == "/weighted-retry" for item in stable) == 2
assert sum(item["path"] == "/weighted-retry" for item in canary) == 2
assert sum(item["path"] == "/direct" for item in stable) == 2
assert sum(item["path"] == "/direct" for item in canary) == 0
assert sum(item["path"].startswith("/x") for item in stable) == 1
assert sum(item["path"].startswith("/x") for item in canary) == 1
assert all("padding=" not in item["path"] for item in all_records)
assert all("x-api-key" not in item["headers"] for item in all_records)
assert all(
    item["headers"].get("x-route-action") == "weighted"
    for item in all_records
    if item["path"].startswith("/weighted/item")
)
assert all(
    item["headers"].get("x-route-action") == "weighted-retry"
    for item in all_records
    if item["path"] == "/weighted-retry"
)
stable_retry = [
    item for item in stable
    if item["headers"].get("x-request-id") == "retry-h1"
]
canary_retry = [
    item for item in canary
    if item["headers"].get("x-request-id") == "retry-h2"
]
assert len(stable_retry) == 2
assert len(canary_retry) == 2
assert not any(
    item["headers"].get("x-request-id") == "retry-h1"
    for item in canary
)
assert not any(
    item["headers"].get("x-request-id") == "retry-h2"
    for item in stable
)
print("stable_records=17")
print("canary_records=7")
print("split_distribution=12:4")
print("retry_h1=stable_attempts_2")
print("retry_h2=canary_attempts_2")
print("rewrite_limit_upstream_attempts=0")
PY

docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1

{
  printf 'run_id=%s\n' "$run_id"
  printf 'timestamp_utc=%s\n' "$timestamp"
  printf 'git_commit=%s\n' "$(git rev-parse HEAD)"
  printf 'git_dirty=%s\n' "$(test -n "$(git status --porcelain)" && echo true || echo false)"
  printf 'platform=%s\n' "$platform"
  printf 'runtime_image=%s\n' "$image"
  printf 'runtime_image_id=%s\n' "$(docker image inspect "$image" --format '{{.Id}}')"
  printf 'evidence_class=local-engineering\n'
  printf 'publishable=false\n'
  printf 'marketing_use_authorized=false\n'
  uname -a
} >"$stage_dir/metadata.txt"

cat >"$stage_dir/README.md" <<EOF
# Weighted traffic splitting local evidence

This checksum-bound run validates one shard-local static weighted route
schedule over HTTP/1.1 and TLS HTTP/2. Two complete 75/25 cycles produced
12 stable and 4 canary requests. Authentication failures and CORS preflights
did not advance the schedule. Retry attempts stayed in the initially selected
cluster. Request-derived rewrite-limit failures selected no cluster, and the
next valid request retained its expected slot. The direct route remained
single-cluster.

This is local engineering evidence. It does not establish multi-shard global
fairness, sticky assignment, dynamic rollout, long-duration stability,
dedicated-host feature cost, production readiness, or a marketing claim.
EOF

for source in api/proto/bonvoyage/v1/config.proto config/schemas/bonvoyage-config.schema.json control-plane/internal/snapshot/snapshot.go dataplane/include/bonvoyage/runtime/runtime_snapshot.hh dataplane/include/bonvoyage/runtime/weighted_cluster_selector.hh dataplane/src/gateway.cc dataplane/src/runtime_snapshot.cc dataplane/src/weighted_cluster_selector.cc scripts/phase3-weighted-traffic-client.py scripts/phase3-weighted-traffic-splitting-smoke.sh scripts/test-fixture-secrets.sh scripts/phase3-weighted-traffic-upstream.py tests/fixtures/phase3-weighted-traffic-splitting.yaml; do
  hash_file "$source"
done >"$stage_dir/source-checksums.sha256"

(
  cd "$stage_dir"
  for artifact in *; do
    [ "$artifact" = "checksums.sha256" ] || hash_file "$artifact"
  done
) >"$stage_dir/checksums.sha256"

mkdir -p "$output_root"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-weighted-traffic-splitting.txt"
echo "$output_dir"
