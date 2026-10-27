#!/bin/sh
set -eu

umask 077

script_dir="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
repo_root="$(CDPATH='' cd "$script_dir/.." && pwd)"
cd "$repo_root"

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
grpc_image="${BONVOYAGE_GRPC_FIXTURE_IMAGE:-bonvoyage-grpc-unary-fixture:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
fixture="$repo_root/tests/fixtures/phase3-composite-hardening.yaml"

shards="${BONVOYAGE_COMPOSITE_SHARDS:-2}"
churn_rounds="${BONVOYAGE_COMPOSITE_CHURN_ROUNDS:-3}"
http_requests_per_round="${BONVOYAGE_COMPOSITE_HTTP_REQUESTS_PER_ROUND:-400}"
websocket_cycles_per_round="${BONVOYAGE_COMPOSITE_WEBSOCKET_CYCLES_PER_ROUND:-40}"
h2_seconds="${BONVOYAGE_COMPOSITE_HTTP2_SECONDS:-60}"
grpc_clients="${BONVOYAGE_COMPOSITE_GRPC_CLIENTS:-8}"
failure_requests="${BONVOYAGE_COMPOSITE_FAILURE_REQUESTS:-256}"
rss_settle_seconds="${BONVOYAGE_COMPOSITE_RSS_SETTLE_SECONDS:-3}"
rss_max_growth_bytes="${BONVOYAGE_COMPOSITE_RSS_MAX_GROWTH_BYTES:-33554432}"
rss_max_growth_percent="${BONVOYAGE_COMPOSITE_RSS_MAX_GROWTH_PERCENT:-20}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="composite-hardening-$timestamp"
suffix="$$"
network="bonvoyage-composite-$suffix"
volume="bonvoyage-composite-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-composite-gateway-$suffix"
stable="bonvoyage-composite-stable-$suffix"
canary="bonvoyage-composite-canary-$suffix"
websocket="bonvoyage-composite-websocket-$suffix"
grpc_upstream="bonvoyage-composite-grpc-$suffix"
loadgen="bonvoyage-composite-loadgen-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-composite.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_COMPOSITE_EVIDENCE_ROOT:-$repo_root/benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir" "$work_dir/secrets"

checksum_tool=""
evidence_ready=1

fail() {
  message="$1"
  printf 'FAIL: %s\n' "$message" >&2
  if [ "$evidence_ready" -eq 1 ]; then
    printf '%s\n' "$message" >"$stage_dir/failure.txt"
  fi
  exit 1
}

capture_container() {
  container="$1"
  label="$2"
  if docker inspect "$container" >/dev/null 2>&1; then
    docker inspect "$container" >"$stage_dir/$label.inspect.json" 2>&1 || true
    docker logs "$container" >"$stage_dir/$label.log" 2>&1 || true
  fi
}

write_checksums() {
  (
    cd "$stage_dir" || exit 1
    manifest_list="$work_dir/checksum-files.txt"
    find . -type f ! -name checksums.sha256 ! -name checksums.sha256.tmp -print \
      | LC_ALL=C sort >"$manifest_list"
    while IFS= read -r path; do
      path="${path#./}"
      if [ "$checksum_tool" = sha256sum ]; then
        sha256sum "$path"
      else
        shasum -a 256 "$path"
      fi
    done <"$manifest_list" >checksums.sha256.tmp
    rm "$manifest_list"
    mv checksums.sha256.tmp checksums.sha256
    if [ "$checksum_tool" = sha256sum ]; then
      sha256sum --check --quiet checksums.sha256
    else
      shasum -a 256 --check --quiet checksums.sha256
    fi
  )
}

cleanup() {
  status="$?"
  trap - EXIT INT TERM
  set +e
  if [ -d "$stage_dir" ]; then
    capture_container "$gateway" gateway
    capture_container "$stable" stable-upstream
    capture_container "$canary" canary-upstream
    capture_container "$websocket" websocket-upstream
    capture_container "$grpc_upstream" grpc-upstream
    capture_container "$loadgen" loadgen
    if [ "$status" -ne 0 ]; then
      printf 'outcome=FAIL\nexit_code=%s\n' "$status" >"$stage_dir/run-status.env"
      write_checksums >/dev/null 2>&1 || true
      printf 'Composite hardening failed; temporary evidence: %s\n' "$stage_dir" >&2
      sed -n '1,240p' "$stage_dir/gateway.log" >&2 || true
    fi
  fi
  docker rm --force "$gateway" "$stable" "$canary" "$websocket" \
    "$grpc_upstream" "$loadgen" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$work_dir/secrets" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  if [ "$status" -eq 0 ]; then
    rm -rf "$work_dir"
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command_name in awk date docker find git grep mktemp openssl python3 sed sort; do
  command -v "$command_name" >/dev/null 2>&1 \
    || fail "required command is unavailable: $command_name"
done
if command -v sha256sum >/dev/null 2>&1; then
  checksum_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  checksum_tool=shasum
else
  fail "either sha256sum or shasum is required"
fi

positive_integer() {
  name="$1"
  value="$2"
  case "$value" in
    ''|*[!0-9]*) fail "$name must be a positive integer, got '$value'" ;;
  esac
  [ "$value" -gt 0 ] || fail "$name must be greater than zero"
}

nonnegative_integer() {
  name="$1"
  value="$2"
  case "$value" in
    ''|*[!0-9]*) fail "$name must be a nonnegative integer, got '$value'" ;;
  esac
}

positive_integer BONVOYAGE_COMPOSITE_SHARDS "$shards"
[ "$shards" -ge 2 ] || fail "BONVOYAGE_COMPOSITE_SHARDS must be at least 2"
positive_integer BONVOYAGE_COMPOSITE_CHURN_ROUNDS "$churn_rounds"
positive_integer BONVOYAGE_COMPOSITE_HTTP_REQUESTS_PER_ROUND "$http_requests_per_round"
positive_integer BONVOYAGE_COMPOSITE_WEBSOCKET_CYCLES_PER_ROUND "$websocket_cycles_per_round"
positive_integer BONVOYAGE_COMPOSITE_HTTP2_SECONDS "$h2_seconds"
positive_integer BONVOYAGE_COMPOSITE_GRPC_CLIENTS "$grpc_clients"
positive_integer BONVOYAGE_COMPOSITE_FAILURE_REQUESTS "$failure_requests"
nonnegative_integer BONVOYAGE_COMPOSITE_RSS_SETTLE_SECONDS "$rss_settle_seconds"
positive_integer BONVOYAGE_COMPOSITE_RSS_MAX_GROWTH_BYTES "$rss_max_growth_bytes"
nonnegative_integer BONVOYAGE_COMPOSITE_RSS_MAX_GROWTH_PERCENT "$rss_max_growth_percent"
[ -f "$fixture" ] || fail "composite fixture is missing: $fixture"
case "$oha_image" in
  *@sha256:*) ;;
  *) fail "BONVOYAGE_OHA_IMAGE must use an immutable sha256 digest" ;;
esac
[ ! -e "$output_dir" ] || fail "evidence directory already exists: $output_dir"

docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"
docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile . \
  >"$stage_dir/compiler-image-build.log" 2>&1 \
  || fail "snapshot compiler image build failed"
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream \
  >"$stage_dir/upstream-image-build.log" 2>&1 \
  || fail "controlled upstream image build failed"
docker buildx build --platform "$platform" --load --tag "$grpc_image" \
  --file tests/fixtures/grpc-unary/Dockerfile tests/fixtures/grpc-unary \
  >"$stage_dir/grpc-image-build.log" 2>&1 \
  || fail "native gRPC fixture image build failed"

dataplane_image_id="$(docker image inspect --format '{{.Id}}' "$image")" \
  || fail "dataplane image is unavailable: $image"
compiler_image_id="$(docker image inspect --format '{{.Id}}' "$compiler_image")"
upstream_image_id="$(docker image inspect --format '{{.Id}}' "$upstream_image")"
grpc_image_id="$(docker image inspect --format '{{.Id}}' "$grpc_image")"
oha_image_id="$(docker image inspect --format '{{.Id}}' "$oha_image")" \
  || fail "pinned oha image is unavailable: $oha_image"
docker image inspect "$dataplane_image_id" "$compiler_image_id" \
  "$upstream_image_id" "$grpc_image_id" "$oha_image_id" \
  >"$stage_dir/images.inspect.json"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage Composite Hardening CA" \
  -keyout "$work_dir/ca-key.pem" -out "$work_dir/secrets/ca.pem" \
  >/dev/null 2>&1
cp "$work_dir/secrets/ca.pem" "$work_dir/secrets/upstream-ca.pem"
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=api.example.test" -keyout "$work_dir/secrets/server-key.pem" \
  -out "$work_dir/server.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:api.example.test' \
  'extendedKeyUsage=serverAuth' 'keyUsage=digitalSignature,keyEncipherment' \
  >"$work_dir/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work_dir/server.csr" \
  -CA "$work_dir/secrets/ca.pem" -CAkey "$work_dir/ca-key.pem" \
  -CAcreateserial -extfile "$work_dir/server-ext.cnf" \
  -out "$work_dir/secrets/server-chain.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=upstream-grpc.example.test" \
  -keyout "$work_dir/secrets/upstream-key.pem" \
  -out "$work_dir/upstream.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:upstream-grpc.example.test' \
  'extendedKeyUsage=serverAuth' 'keyUsage=digitalSignature,keyEncipherment' \
  >"$work_dir/upstream-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work_dir/upstream.csr" \
  -CA "$work_dir/secrets/ca.pem" -CAkey "$work_dir/ca-key.pem" \
  -CAcreateserial -extfile "$work_dir/upstream-ext.cnf" \
  -out "$work_dir/secrets/upstream-chain.pem" >/dev/null 2>&1
chmod 600 "$work_dir/ca-key.pem" "$work_dir/secrets"/*-key.pem

bv_stage_fixture_secrets "$secret_volume" "$work_dir/secrets" "$upstream_image_id" "$platform" \
  server-chain.pem server-key.pem upstream-ca.pem
openssl x509 -in "$work_dir/secrets/server-chain.pem" -noout \
  -fingerprint -sha256 -serial -dates -subject \
  >"$stage_dir/ephemeral-downstream-certificate.txt"
openssl x509 -in "$work_dir/secrets/upstream-chain.pem" -noout \
  -fingerprint -sha256 -serial -dates -subject \
  >"$stage_dir/ephemeral-upstream-certificate.txt"

docker network create --internal "$network" >/dev/null \
  || fail "could not create isolated Docker network"
docker volume create "$volume" >/dev/null \
  || fail "could not create snapshot volume"
docker run --rm --platform "$platform" --network none --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$fixture:/etc/bonvoyage/composite.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" "$compiler_image_id" \
  -input /etc/bonvoyage/composite.yaml \
  -output /var/lib/bonvoyage/snapshot.pb \
  >"$stage_dir/snapshot-compiler.log" 2>&1 \
  || fail "composite snapshot compilation failed"

docker run --detach --platform "$platform" --name "$loadgen" \
  --user "$(id -u):$(id -g)" \
  --network "$network" --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true --cap-drop ALL --entrypoint python \
  --volume "$script_dir/phase3-composite-hardening-client.py:/composite-client.py:ro" \
  "$upstream_image_id" -m http.server 18080 >/dev/null \
  || fail "could not start isolated load-generator container"
for endpoint in stable canary; do
  if [ "$endpoint" = stable ]; then
    container="$stable"
  else
    container="$canary"
  fi
  docker run --detach --platform "$platform" --name "$container" \
    --user "$(id -u):$(id -g)" \
    --network "$network" --network-alias "$endpoint" --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --security-opt no-new-privileges:true --cap-drop ALL --entrypoint python \
    --env "BONVOYAGE_UPSTREAM_ID=$endpoint" \
    --volume "$script_dir/phase3-composite-hardening-upstream.py:/composite-upstream.py:ro" \
    "$upstream_image_id" /composite-upstream.py >/dev/null \
    || fail "could not start controlled $endpoint upstream"
done
docker run --detach --platform "$platform" --name "$websocket" \
  --user "$(id -u):$(id -g)" \
  --network "$network" --network-alias websocket --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true --cap-drop ALL --entrypoint python \
  --volume "$script_dir/phase3-websocket-upstream.py:/websocket-upstream.py:ro" \
  "$upstream_image_id" /websocket-upstream.py >/dev/null \
  || fail "could not start controlled WebSocket upstream"
docker run --detach --platform "$platform" --name "$grpc_upstream" \
  --user "$(id -u):$(id -g)" \
  --network "$network" --network-alias upstream-grpc.example.test --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$work_dir/secrets:/secrets:ro" "$grpc_image_id" server \
  --certificate /secrets/upstream-chain.pem --key /secrets/upstream-key.pem \
  >/dev/null || fail "could not start native gRPC upstream"

wait_for_url() {
  url="$1"
  label="$2"
  attempt=0
  until docker exec "$loadgen" python -c \
    'import sys, urllib.request; assert urllib.request.urlopen(sys.argv[1], timeout=1).status in (200, 204)' \
    "$url" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 40 ] || fail "$label did not become ready"
    sleep 1
  done
}

wait_for_url http://stable:8081/healthz "stable upstream"
wait_for_url http://canary:8081/healthz "canary upstream"
wait_for_url http://websocket:8081/healthz "WebSocket upstream"
wait_for_url http://upstream-grpc.example.test:8081/healthz "gRPC upstream"

docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test --dns-search . --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
  "$dataplane_image_id" --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --runtime-log-transport stderr-pipe \
  --smp "$shards" --memory 512M --overprovisioned \
  --logger-log-level bonvoyage-gateway=info >/dev/null \
  || fail "could not start the multi-shard BonVoyage dataplane"
bv_wait_gateway_ready "$gateway" "$loadgen" "http://$gateway:9901/health/ready"

capture_metrics() {
  destination="$1"
  docker exec "$loadgen" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1], timeout=5).read())
' "http://$gateway:9090/metrics" >"$destination"
}

wait_for_zero_gauges() {
  phase="$1"
  attempt=0
  while [ "$attempt" -lt 150 ]; do
    capture_metrics "$work_dir/active-metrics.prom" || true
    if python3 - "$work_dir/active-metrics.prom" <<'PY' >/dev/null 2>&1
import sys

text = open(sys.argv[1], encoding="utf-8").read()
names = {
    "bonvoyage_bonvoyage_gateway_active_connections",
    "bonvoyage_bonvoyage_gateway_active_http2_connections",
    "bonvoyage_bonvoyage_gateway_active_http2_streams",
    "bonvoyage_bonvoyage_gateway_active_route_requests",
    "bonvoyage_bonvoyage_gateway_active_upstream_requests",
    "bonvoyage_bonvoyage_gateway_active_retries",
    "bonvoyage_bonvoyage_gateway_active_websocket_connections",
}
totals = {name: 0.0 for name in names}
for line in text.splitlines():
    if not line or line.startswith("#"):
        continue
    metric, raw = line.split(None, 1)
    name = metric.split("{", 1)[0]
    if name in totals:
        totals[name] += float(raw)
assert all(value == 0 for value in totals.values()), totals
PY
    then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  fail "$phase did not drain all bounded request, stream, connection, and tunnel gauges"
}

measure_rss_kib() {
  docker top "$gateway" -eo pid,rss 2>/dev/null \
    | awk 'NR > 1 && $2 ~ /^[0-9]+$/ { total += $2; count += 1 }
      END { if (count == 0) exit 1; printf "%.0f\n", total }'
}

record_state() {
  phase="$1"
  index="$2"
  wait_for_zero_gauges "$phase"
  rss="$(measure_rss_kib)" || fail "could not measure RSS after $phase"
  printf '%s,%s,%s,%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$phase" "$index" "$rss" >>"$stage_dir/lifecycle-samples.csv"
  printf '%s\n' "$rss"
}

run_http() {
  output="$1"
  path="$2"
  count="$3"
  concurrency="$4"
  docker exec "$loadgen" python /composite-client.py http "$gateway" \
    "$path" "$count" "$concurrency" >"$stage_dir/$output" \
    || fail "HTTP workload failed: $output"
}

run_websocket() {
  output="$1"
  count="$2"
  concurrency="$3"
  docker exec "$loadgen" python /composite-client.py websocket "$gateway" \
    "$count" "$concurrency" >"$stage_dir/$output" \
    || fail "WebSocket workload failed: $output"
}

toggle_canary_failure() {
  enabled="$1"
  docker exec "$loadgen" python -c '
import sys
import urllib.request
body = urllib.request.urlopen(
    "http://canary:8081/control/failure?enabled=" + sys.argv[1], timeout=5
).read()
sys.stdout.buffer.write(body)
' "$enabled"
}

capture_upstream_stats() {
  endpoint="$1"
  destination="$2"
  docker exec "$loadgen" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(
    urllib.request.urlopen("http://" + sys.argv[1] + ":8081/stats", timeout=5).read()
)
' "$endpoint" >"$stage_dir/$destination"
}

printf 'timestamp_utc,phase,index,rss_kib\n' >"$stage_dir/lifecycle-samples.csv"
initial_identity="$(docker inspect --format \
  '{{.Id}}|{{.State.Pid}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.State.Running}}' \
  "$gateway")"
printf 'initial=%s\n' "$initial_identity" >"$stage_dir/gateway-identities.txt"

run_http warmup.json /ready 128 16
sleep "$rss_settle_seconds"
baseline_rss_kib="$(record_state baseline 0)"
capture_metrics "$stage_dir/metrics-baseline.prom"

round=1
while [ "$round" -le "$churn_rounds" ]; do
  run_http "http1-churn-$round.json" /ready "$http_requests_per_round" 32
  run_websocket "websocket-churn-$round.json" \
    "$websocket_cycles_per_round" 12
  record_state mixed-churn "$round" >/dev/null
  round=$((round + 1))
done

docker run --rm --platform "$platform" --network "$network" --read-only \
  --user "$(id -u):$(id -g)" \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$work_dir/secrets:/tls:ro" "$oha_image_id" \
  -z "${h2_seconds}s" -c 8 -p 16 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/ready >"$stage_dir/http2-churn.oha.json" \
  || fail "sustained HTTP/2 churn workload failed"
record_state http2-churn 0 >/dev/null

: >"$stage_dir/grpc-client-pids.txt"
client=1
while [ "$client" -le "$grpc_clients" ]; do
  docker run --rm --platform "$platform" --network "$network" --read-only \
    --user "$(id -u):$(id -g)" \
    --security-opt no-new-privileges:true --cap-drop ALL \
    --volume "$work_dir/secrets:/secrets:ro" "$grpc_image_id" client \
    --target api.example.test:8443 --ca /secrets/ca.pem \
    --server-name api.example.test --case concurrent \
    >"$stage_dir/grpc-client-$client.json" \
    2>"$stage_dir/grpc-client-$client.stderr" &
  printf '%s\n' "$!" >>"$stage_dir/grpc-client-pids.txt"
  client=$((client + 1))
done
grpc_status=0
while IFS= read -r client_pid; do
  wait "$client_pid" || grpc_status=1
done <"$stage_dir/grpc-client-pids.txt"
[ "$grpc_status" -eq 0 ] || fail "one or more native gRPC churn clients failed"
record_state grpc-churn 0 >/dev/null

run_http saturation.json /saturate 32 32
record_state route-saturation 0 >/dev/null
run_http saturation-recovery.json /ready 64 16

run_http weighted-baseline.json /split "$failure_requests" 32
run_http load-balancing-baseline.json /lb "$failure_requests" 32
toggle_canary_failure 1 >"$stage_dir/canary-failure-enabled.json"
run_http weighted-failure.json /split "$failure_requests" 32
run_http load-balancing-failure.json /lb "$failure_requests" 32
capture_upstream_stats stable stable-stats-failure.json
capture_upstream_stats canary canary-stats-failure.json
toggle_canary_failure 0 >"$stage_dir/canary-failure-disabled.json"
sleep 1
run_http weighted-recovery.json /split "$failure_requests" 32
run_http load-balancing-recovery.json /lb "$failure_requests" 32
run_http final-recovery.json /ready 64 16
record_state failure-recovery 0 >/dev/null
capture_upstream_stats stable stable-stats-final.json
capture_upstream_stats canary canary-stats-final.json

capture_metrics "$stage_dir/metrics-final.prom"
python3 - "$stage_dir" "$shards" "$churn_rounds" "$grpc_clients" \
  "$failure_requests" >"$stage_dir/results-validation.txt" <<'PY'
import glob
import json
import re
import sys

root, expected_shards, rounds, grpc_clients, failure_requests = sys.argv[1:]
expected_shards = int(expected_shards)
rounds = int(rounds)
grpc_clients = int(grpc_clients)
failure_requests = int(failure_requests)


def load(name):
    with open(root + "/" + name, encoding="utf-8") as source:
        return json.load(source)


def require_http_success(name):
    result = load(name)
    assert result["completed"] == result["requested"], (name, result)
    assert result["statuses"] == {"200": result["requested"]}, (name, result)
    assert not result["errors"], (name, result)


require_http_success("warmup.json")
require_http_success("saturation-recovery.json")
require_http_success("final-recovery.json")
for index in range(1, rounds + 1):
    require_http_success(f"http1-churn-{index}.json")
    websocket = load(f"websocket-churn-{index}.json")
    assert websocket["successes"] == websocket["requested"], websocket
    assert not websocket["errors"], websocket

saturation = load("saturation.json")
successes = int(saturation["statuses"].get("200", 0))
rejections = int(saturation["statuses"].get("503", 0))
assert not saturation["errors"], saturation
assert 2 <= successes <= expected_shards * 2, saturation
assert successes + rejections == saturation["requested"], saturation
assert rejections > 0, saturation


def require_weighted(name, *, degraded=False):
    result = load(name)
    assert result["completed"] == failure_requests, (name, result)
    assert not result["errors"], (name, result)
    successes = int(result["statuses"].get("200", 0))
    failures = sum(
        int(value) for status, value in result["statuses"].items()
        if status in {"502", "503"}
    )
    assert set(result["statuses"]) <= {"200", "502", "503"}, (name, result)
    if degraded:
        assert 0.60 <= successes / failure_requests <= 0.85, (name, result)
        assert failures == failure_requests - successes and failures > 0, (name, result)
        assert result["upstreams"] == {"stable": successes}, (name, result)
    else:
        assert successes == failure_requests and failures == 0, (name, result)
        canary = int(result["upstreams"].get("canary", 0))
        stable = int(result["upstreams"].get("stable", 0))
        assert stable + canary == failure_requests, (name, result)
        assert 0.18 <= canary / failure_requests <= 0.32, (name, result)


require_weighted("weighted-baseline.json")
require_weighted("weighted-failure.json", degraded=True)
require_weighted("weighted-recovery.json")


def require_balancing(name, *, degraded=False):
    result = load(name)
    assert result["completed"] == failure_requests, (name, result)
    assert not result["errors"], (name, result)
    successes = int(result["statuses"].get("200", 0))
    failures = sum(
        int(value) for status, value in result["statuses"].items()
        if status in {"502", "503"}
    )
    assert set(result["statuses"]) <= {"200", "502", "503"}, (name, result)
    if degraded:
        assert 1 <= failures <= expected_shards * 8, (name, result)
        assert successes + failures == failure_requests, (name, result)
        assert result["upstreams"].get("stable", 0) == successes, (name, result)
    else:
        assert successes == failure_requests and failures == 0, (name, result)
        assert set(result["upstreams"]) == {"stable", "canary"}, (name, result)


require_balancing("load-balancing-baseline.json")
require_balancing("load-balancing-failure.json", degraded=True)
require_balancing("load-balancing-recovery.json")

for index in range(1, grpc_clients + 1):
    result = load(f"grpc-client-{index}.json")
    assert result["case"] == "concurrent", result
    assert result["code"] == "OK", result
    assert result["successful_requests"] == 16, result

with open(root + "/http2-churn.oha.json", encoding="utf-8") as source:
    h2 = json.load(source)
assert h2["summary"]["requestsPerSec"] > 0, h2["summary"]
assert h2["summary"]["successRate"] == 1, h2["summary"]
distribution = h2.get("statusCodeDistribution", {})
errors = h2.get("errorDistribution", {})
assert set(distribution) <= {"200"}, distribution
assert int(distribution.get("200", 0)) >= 128, distribution
assert set(errors) <= {"aborted due to deadline"}, errors
assert int(errors.get("aborted due to deadline", 0)) <= 128, errors

stable_stats = load("stable-stats-final.json")
canary_stats = load("canary-stats-final.json")
assert stable_stats["active"] == 0 and canary_stats["active"] == 0
assert stable_stats["forced_failures"] == 0, stable_stats
assert canary_stats["forced_failures"] >= expected_shards * 2, canary_stats
assert stable_stats["maximum_active"] <= 128, stable_stats
assert canary_stats["maximum_active"] <= 128, canary_stats

text = open(root + "/metrics-final.prom", encoding="utf-8").read()


def by_shard(metric_name):
    values = {}
    for line in text.splitlines():
        if not line.startswith(metric_name + "{"):
            continue
        labels, raw = line.split(None, 1)
        match = re.search(r'shard="(\d+)"', labels)
        assert match, line
        values[int(match.group(1))] = values.get(int(match.group(1)), 0.0) + float(raw)
    return values


prefix = "bonvoyage_bonvoyage_gateway_"
requests = by_shard(prefix + "requests_total")
assert set(requests) == set(range(expected_shards)), requests
assert all(value >= 100 for value in requests.values()), requests
assert min(requests.values()) / sum(requests.values()) >= 0.25, requests

for suffix in (
    "route_weighted_cluster_selections_total",
    "route_overload_rejections_total",
    "upstream_passive_failures_total",
    "upstream_passive_ejections_total",
    "upstream_passive_reactivations_total",
    "endpoint_circuit_closes_total",
    "grpc_requests_total",
    "websocket_connections_total",
    "http2_streams_total",
):
    values = by_shard(prefix + suffix)
    assert set(values) == set(range(expected_shards)), (suffix, values)
    assert all(value > 0 for value in values.values()), (suffix, values)

zero_final_gauges = (
    "active_connections",
    "active_http2_connections",
    "active_http2_streams",
    "active_requests",
    "active_route_requests",
    "active_upstream_requests",
    "active_upstream_http2_streams",
    "active_retries",
    "active_tls_handshakes",
    "active_upstream_tls_handshakes",
    "active_unhealthy_endpoints",
    "active_websocket_connections",
)
for suffix in zero_final_gauges:
    values = by_shard(prefix + suffix)
    assert set(values) == set(range(expected_shards)), (suffix, values)
    assert all(value == 0 for value in values.values()), (suffix, values)

pooled_h2_connections = by_shard(prefix + "active_upstream_http2_connections")
assert set(pooled_h2_connections) == set(range(expected_shards)), pooled_h2_connections
assert all(0 <= value <= 1 for value in pooled_h2_connections.values()), pooled_h2_connections

malloc_failures = by_shard("bonvoyage_memory_malloc_failed")
assert set(malloc_failures) == set(range(expected_shards)), malloc_failures
assert all(value == 0 for value in malloc_failures.values()), malloc_failures

with open(root + "/metrics-validation.json", "w", encoding="utf-8") as destination:
    json.dump(
        {
            "request_share_by_shard": requests,
            "minimum_shard_share": min(requests.values()) / sum(requests.values()),
            "all_shards_exercised": True,
            "all_required_final_gauges_zero": True,
            "zero_required_final_gauges": list(zero_final_gauges),
            "pooled_upstream_http2_connections": pooled_h2_connections,
            "malloc_failures": malloc_failures,
        },
        destination,
        indent=2,
        sort_keys=True,
    )
    destination.write("\n")
print("mixed protocol, shard fairness, saturation, failure, recovery, and final metric assertions passed")
PY

sleep "$rss_settle_seconds"
final_rss_kib="$(record_state final 0)"
final_identity="$(docker inspect --format \
  '{{.Id}}|{{.State.Pid}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.State.Running}}' \
  "$gateway")"
printf 'final=%s\n' "$final_identity" >>"$stage_dir/gateway-identities.txt"
[ "$final_identity" = "$initial_identity" ] \
  || fail "gateway process identity changed during composite hardening"

rss_absolute_limit_kib=$(((rss_max_growth_bytes + 1023) / 1024))
rss_percent_limit_kib=$(((baseline_rss_kib * rss_max_growth_percent + 99) / 100))
rss_allowed_growth_kib="$rss_absolute_limit_kib"
if [ "$rss_percent_limit_kib" -gt "$rss_allowed_growth_kib" ]; then
  rss_allowed_growth_kib="$rss_percent_limit_kib"
fi
rss_growth_kib=$((final_rss_kib - baseline_rss_kib))
[ "$rss_growth_kib" -ge 0 ] || rss_growth_kib=0
[ "$rss_growth_kib" -le "$rss_allowed_growth_kib" ] \
  || fail "retained RSS grew ${rss_growth_kib} KiB; limit is ${rss_allowed_growth_kib} KiB"
peak_rss_kib="$(awk -F, 'NR > 1 && $4 > peak { peak = $4 } END { print peak + 0 }' \
  "$stage_dir/lifecycle-samples.csv")"

capture_metrics "$stage_dir/metrics-post-settle.prom"
capture_container "$gateway" gateway
capture_container "$stable" stable-upstream
capture_container "$canary" canary-upstream
capture_container "$websocket" websocket-upstream
capture_container "$grpc_upstream" grpc-upstream
docker kill --signal=TERM "$gateway" >/dev/null
attempt=0
while [ "$(docker inspect --format '{{.State.Running}}' "$gateway")" = true ]; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 150 ] || fail "gateway did not drain within 15 seconds"
  sleep 0.1
done
docker inspect --format '{{.State.ExitCode}}' "$gateway" \
  >"$stage_dir/gateway-exit-code.txt"
grep -qx 0 "$stage_dir/gateway-exit-code.txt" \
  || fail "gateway did not exit cleanly"
capture_container "$gateway" gateway

source_commit="$(git rev-parse HEAD)"
if [ -z "$(git status --porcelain)" ]; then source_dirty=false; else source_dirty=true; fi
cat >"$stage_dir/metadata.txt" <<EOF
captured_at_utc=$timestamp
run_id=$run_id
source_commit=$source_commit
source_dirty=$source_dirty
platform=$platform
gateway_shards=$shards
http_churn_rounds=$churn_rounds
http_requests_per_round=$http_requests_per_round
websocket_cycles_per_round=$websocket_cycles_per_round
http2_churn_seconds=$h2_seconds
grpc_clients=$grpc_clients
grpc_requests_per_client=16
failure_requests_per_phase=$failure_requests
rss_settle_seconds=$rss_settle_seconds
rss_max_growth_bytes=$rss_max_growth_bytes
rss_max_growth_percent=$rss_max_growth_percent
dataplane_image_id=$dataplane_image_id
compiler_image_id=$compiler_image_id
upstream_image_id=$upstream_image_id
grpc_image_id=$grpc_image_id
oha_image_id=$oha_image_id
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/summary.txt" <<EOF
outcome: PASS
scope: bounded local Phase 3 multi-shard composite hardening
gateway_shards: $shards
mixed_http1_requests: $((churn_rounds * http_requests_per_round))
websocket_tunnel_cycles: $((churn_rounds * websocket_cycles_per_round))
http2_churn_seconds: $h2_seconds
grpc_unary_requests: $((grpc_clients * 16))
route_saturation: bounded local rejection and recovery passed on every shard
weighted_failure: stable share continued while canary failed; distribution recovered
load_balancing_failure: canary ejected per shard; stable endpoint continued; canary recovered
gateway_identity_unchanged: true
gateway_exit_code: 0
baseline_rss_kib: $baseline_rss_kib
final_rss_kib: $final_rss_kib
peak_sampled_rss_kib: $peak_rss_kib
retained_rss_growth_kib: $rss_growth_kib
retained_rss_growth_limit_kib: $rss_allowed_growth_kib
claim_limit: local Docker functional evidence; not indefinite leak freedom, dedicated performance, or marketing authorization
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 composite hardening evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This record does not authorize
performance, competitive, customer-facing, or indefinite leak-freedom claims.

The ${shards}-shard BonVoyage process carried independent HTTP/1.1 connections,
TLS HTTP/2 streams, native unary gRPC calls, and HTTP/1.1 WebSocket tunnels.
Every shard handled requests, weighted selections, route overload, passive
endpoint failure and recovery, gRPC, HTTP/2, and WebSocket traffic. A bounded
route saturation phase rejected excess work locally and recovered without a
restart.

The canary endpoint was then forced to close before a response head. Static
weighted traffic continued serving the stable share while the failed share was
rejected, and the two-endpoint load-balanced cluster ejected canary while stable
continued. Both shard-local circuits reactivated and closed after canary was
restored. Final downstream, request, stream, route, retry, upstream-request, and
tunnel in-flight gauges were zero. The gRPC pool retained at most one idle
upstream HTTP/2 connection per shard, allocator failure counters were zero,
process identity did not change, and SIGTERM completed with exit code zero.

RSS is bounded only for the configured run and threshold recorded in
\`summary.txt\`. Dedicated hosts, multi-hour execution, separated load-generator
and upstream capacity proof, feature-cost curves, and publication qualification
remain separate gates.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
Makefile
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
dataplane/CMakeLists.txt
dataplane/include/bonvoyage/http/websocket_protocol.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/gateway.cc
dataplane/src/runtime_snapshot.cc
dataplane/src/websocket_protocol.cc
scripts/phase3-composite-hardening-client.py
scripts/phase3-composite-hardening-upstream.py
scripts/phase3-composite-hardening.sh
scripts/test-fixture-secrets.sh
scripts/phase3-websocket-upstream.py
tests/fixtures/grpc-unary/Dockerfile
tests/fixtures/grpc-unary/go.mod
tests/fixtures/grpc-unary/go.sum
tests/fixtures/grpc-unary/main.go
tests/fixtures/phase3-composite-hardening.yaml
EOF
while IFS= read -r source_file; do
  if [ "$checksum_tool" = sha256sum ]; then
    sha256sum "$source_file"
  else
    shasum -a 256 "$source_file"
  fi
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt" "$stage_dir/grpc-client-pids.txt"
printf 'outcome=PASS\nexit_code=0\n' >"$stage_dir/run-status.env"
write_checksums || fail "could not create the composite evidence manifest"

mkdir -p "$output_root"
mv "$stage_dir" "$output_dir"
if [ "$source_dirty" = false ]; then
  printf '%s\n' "$run_id" >"$output_root/current-composite-hardening.txt.tmp"
  mv "$output_root/current-composite-hardening.txt.tmp" \
    "$output_root/current-composite-hardening.txt"
fi

printf 'Composite hardening passed: %s\n' "$output_dir"
cat "$output_dir/results-validation.txt"
cat "$output_dir/summary.txt"
