#!/bin/sh
set -eu

umask 077
PYTHONOPTIMIZE=0
export PYTHONOPTIMIZE

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
if [ -n "${BONVOYAGE_BUILD_PLATFORM:-}" ]; then
  platform="$BONVOYAGE_BUILD_PLATFORM"
else
  case "$(uname -m)" in
    arm64 | aarch64) platform=linux/arm64 ;;
    *) platform=linux/amd64 ;;
  esac
fi
fixture="$repo_root/tests/fixtures/phase3-composite-hardening.yaml"

profile="${BONVOYAGE_HARDENING_PROFILE:-eight-hour-rehearsal}"
duration_seconds="${BONVOYAGE_HARDENING_DURATION_SECONDS:-28800}"
cycle_interval_seconds="${BONVOYAGE_HARDENING_CYCLE_INTERVAL_SECONDS:-60}"
qps="${BONVOYAGE_HARDENING_HTTP2_QPS:-200}"
h2_connections="${BONVOYAGE_HARDENING_HTTP2_CONNECTIONS:-4}"
h2_parallel="${BONVOYAGE_HARDENING_HTTP2_PARALLEL:-8}"
shards="${BONVOYAGE_HARDENING_SHARDS:-2}"
http_requests_per_cycle="${BONVOYAGE_HARDENING_HTTP_REQUESTS_PER_CYCLE:-128}"
websocket_cycles_per_cycle="${BONVOYAGE_HARDENING_WEBSOCKET_CYCLES_PER_CYCLE:-8}"
failure_requests="${BONVOYAGE_HARDENING_FAILURE_REQUESTS:-64}"
failure_every_cycles="${BONVOYAGE_HARDENING_FAILURE_EVERY_CYCLES:-5}"
saturation_every_cycles="${BONVOYAGE_HARDENING_SATURATION_EVERY_CYCLES:-3}"
metrics_every_cycles="${BONVOYAGE_HARDENING_METRICS_EVERY_CYCLES:-5}"
collector_outage_seconds="${BONVOYAGE_HARDENING_COLLECTOR_OUTAGE_SECONDS:-3}"
access_sample_every="${BONVOYAGE_HARDENING_ACCESS_SAMPLE_EVERY:-100}"
trace_sample_every="${BONVOYAGE_HARDENING_TRACE_SAMPLE_EVERY:-100}"
rss_max_growth_bytes="${BONVOYAGE_HARDENING_RSS_MAX_GROWTH_BYTES:-67108864}"
rss_max_growth_percent="${BONVOYAGE_HARDENING_RSS_MAX_GROWTH_PERCENT:-25}"
rss_max_slope_kib_per_hour="${BONVOYAGE_HARDENING_RSS_MAX_SLOPE_KIB_PER_HOUR:-8192}"
fd_max_growth="${BONVOYAGE_HARDENING_FD_MAX_GROWTH:-16}"
fd_max_slope_per_hour="${BONVOYAGE_HARDENING_FD_MAX_SLOPE_PER_HOUR:-4}"
trace_payload_file_limit="${BONVOYAGE_HARDENING_TRACE_PAYLOAD_FILE_LIMIT:-512}"
h2_deadline_abort_limit=0

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="multi-hour-hardening-$profile-$timestamp"
suffix="$$"
network="bonvoyage-hardening-$suffix"
snapshot_volume="bonvoyage-hardening-snapshot-$suffix"
secret_volume="${snapshot_volume}-secrets"
access_volume="bonvoyage-hardening-access-$suffix"
gateway="bonvoyage-hardening-gateway-$suffix"
stable="bonvoyage-hardening-stable-$suffix"
canary="bonvoyage-hardening-canary-$suffix"
websocket="bonvoyage-hardening-websocket-$suffix"
grpc_upstream="bonvoyage-hardening-grpc-$suffix"
collector="bonvoyage-hardening-collector-$suffix"
loadgen="bonvoyage-hardening-loadgen-$suffix"
h2_load="bonvoyage-hardening-h2-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-hardening.XXXXXX")"
stage_dir="$work_dir/evidence"
cycle_dir="$stage_dir/cycles"
metrics_dir="$stage_dir/metrics"
output_root="${BONVOYAGE_HARDENING_EVIDENCE_ROOT:-$repo_root/benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$cycle_dir" "$metrics_dir" "$work_dir/secrets"

checksum_tool=""
start_epoch=0

fail() {
  message="$1"
  printf 'phase3-multi-hour-hardening: %s\n' "$message" >&2
  printf '%s\n' "$message" >"$stage_dir/failure.txt"
  exit 1
}

container_exists() {
  docker inspect "$1" >/dev/null 2>&1
}

capture_container() {
  container_name="$1"
  label="$2"
  if container_exists "$container_name"; then
    docker inspect "$container_name" >"$stage_dir/$label.inspect.json" 2>&1 || true
    docker logs "$container_name" >"$stage_dir/$label.log" 2>&1 || true
  fi
}

write_checksums() {
  (
    cd "$stage_dir" || exit 1
    find . -type f ! -name checksums.sha256 ! -name checksums.sha256.tmp -print \
      | LC_ALL=C sort >"$work_dir/checksum-files.txt"
    while IFS= read -r path; do
      path="${path#./}"
      if [ "$checksum_tool" = sha256sum ]; then
        sha256sum "$path"
      else
        shasum -a 256 "$path"
      fi
    done <"$work_dir/checksum-files.txt" >checksums.sha256.tmp
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
    capture_container "$collector" collector
    capture_container "$loadgen" loadgen
    capture_container "$h2_load" http2-load
    if [ "$status" -ne 0 ]; then
      printf 'outcome=FAIL\nexit_code=%s\n' "$status" >"$stage_dir/run-status.env"
      write_checksums >/dev/null 2>&1 || true
      printf 'Temporary hardening evidence retained at %s\n' "$stage_dir" >&2
      sed -n '1,240p' "$stage_dir/gateway.log" >&2 || true
    fi
  fi
  docker rm --force "$h2_load" "$gateway" "$stable" "$canary" \
    "$websocket" "$grpc_upstream" "$collector" "$loadgen" \
    >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$snapshot_volume" "$access_volume" >/dev/null 2>&1 || true
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

for command_name in awk cmp date docker find git grep mktemp openssl python3 sed sleep sort uname; do
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
    '' | *[!0-9]*) fail "$name must be a positive integer, got '$value'" ;;
  esac
  [ "$value" -gt 0 ] || fail "$name must be greater than zero"
}

for pair in \
  "BONVOYAGE_HARDENING_DURATION_SECONDS:$duration_seconds" \
  "BONVOYAGE_HARDENING_CYCLE_INTERVAL_SECONDS:$cycle_interval_seconds" \
  "BONVOYAGE_HARDENING_HTTP2_QPS:$qps" \
  "BONVOYAGE_HARDENING_HTTP2_CONNECTIONS:$h2_connections" \
  "BONVOYAGE_HARDENING_HTTP2_PARALLEL:$h2_parallel" \
  "BONVOYAGE_HARDENING_SHARDS:$shards" \
  "BONVOYAGE_HARDENING_HTTP_REQUESTS_PER_CYCLE:$http_requests_per_cycle" \
  "BONVOYAGE_HARDENING_WEBSOCKET_CYCLES_PER_CYCLE:$websocket_cycles_per_cycle" \
  "BONVOYAGE_HARDENING_FAILURE_REQUESTS:$failure_requests" \
  "BONVOYAGE_HARDENING_FAILURE_EVERY_CYCLES:$failure_every_cycles" \
  "BONVOYAGE_HARDENING_SATURATION_EVERY_CYCLES:$saturation_every_cycles" \
  "BONVOYAGE_HARDENING_METRICS_EVERY_CYCLES:$metrics_every_cycles" \
  "BONVOYAGE_HARDENING_COLLECTOR_OUTAGE_SECONDS:$collector_outage_seconds" \
  "BONVOYAGE_HARDENING_ACCESS_SAMPLE_EVERY:$access_sample_every" \
  "BONVOYAGE_HARDENING_TRACE_SAMPLE_EVERY:$trace_sample_every" \
  "BONVOYAGE_HARDENING_RSS_MAX_GROWTH_BYTES:$rss_max_growth_bytes" \
  "BONVOYAGE_HARDENING_RSS_MAX_GROWTH_PERCENT:$rss_max_growth_percent" \
  "BONVOYAGE_HARDENING_FD_MAX_GROWTH:$fd_max_growth" \
  "BONVOYAGE_HARDENING_TRACE_PAYLOAD_FILE_LIMIT:$trace_payload_file_limit"; do
  positive_integer "${pair%%:*}" "${pair#*:}"
done
h2_deadline_abort_limit=$((h2_connections * h2_parallel))
[ "$duration_seconds" -ge 120 ] \
  || fail "BONVOYAGE_HARDENING_DURATION_SECONDS must be at least 120"
[ "$cycle_interval_seconds" -ge 10 ] \
  || fail "BONVOYAGE_HARDENING_CYCLE_INTERVAL_SECONDS must be at least 10"
[ "$shards" -ge 2 ] || fail "BONVOYAGE_HARDENING_SHARDS must be at least 2"
case "$rss_max_slope_kib_per_hour:$fd_max_slope_per_hour" in
  *[!0-9.:]*) fail "slope controls must be nonnegative decimal numbers" ;;
esac
case "$profile" in
  preflight | eight-hour-rehearsal | twenty-four-hour | custom) ;;
  *) fail "unsupported BONVOYAGE_HARDENING_PROFILE: $profile" ;;
esac
case "$oha_image" in
  *@sha256:*) ;;
  *) fail "BONVOYAGE_OHA_IMAGE must use an immutable sha256 digest" ;;
esac

for path in \
  "$fixture" \
  "$script_dir/phase3-composite-hardening-client.py" \
  "$script_dir/phase3-composite-hardening-upstream.py" \
  "$script_dir/phase3-websocket-upstream.py" \
  "$script_dir/phase3-otlp-collector.py" \
  "$script_dir/phase3-hardening-access-validate.py" \
  "$script_dir/phase3-multi-hour-analyze.py"; do
  [ -f "$path" ] || fail "required hardening input is missing: $path"
done
[ ! -e "$output_dir" ] || fail "evidence directory already exists: $output_dir"
python3 -c 'import sys; raise SystemExit(0 if sys.flags.optimize == 0 else 1)' \
  || fail "Python optimization must be disabled so evidence assertions remain active"

cat >"$stage_dir/source-files.txt" <<'EOF'
Makefile
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
dataplane/include/bonvoyage/runtime/access_log.hh
dataplane/include/bonvoyage/runtime/gateway.hh
dataplane/include/bonvoyage/runtime/trace_exporter.hh
dataplane/src/access_log.cc
dataplane/src/gateway.cc
dataplane/src/main.cc
dataplane/src/trace_exporter.cc
deploy/docker/bonvoyage/Dockerfile
deploy/docker/control-plane/Dockerfile
deploy/docker/upstream/Dockerfile
docs/implementation/phase-3-multi-hour-local-hardening.md
scripts/README.md
scripts/phase3-composite-hardening-client.py
scripts/phase3-composite-hardening-upstream.py
scripts/phase3-hardening-access-validate.py
scripts/phase3-multi-hour-analyze.py
scripts/phase3-multi-hour-hardening.sh
scripts/test-fixture-secrets.sh
scripts/phase3-otlp-collector.py
scripts/phase3-websocket-upstream.py
tests/fixtures/grpc-unary/Dockerfile
tests/fixtures/phase3-composite-hardening.yaml
website/sidebars.js
EOF
initial_source_commit="$(git rev-parse HEAD)"
git status --porcelain=v1 --untracked-files=all >"$stage_dir/source-status-start.txt"
if [ -s "$stage_dir/source-status-start.txt" ]; then
  source_dirty=true
else
  source_dirty=false
fi
while IFS= read -r source_file; do
  [ -f "$source_file" ] || fail "source checksum input is missing: $source_file"
  if [ "$checksum_tool" = sha256sum ]; then
    sha256sum "$source_file"
  else
    shasum -a 256 "$source_file"
  fi
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"

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
if ! docker image inspect "$oha_image" >/dev/null 2>&1; then
  docker pull --platform "$platform" "$oha_image" \
    >"$stage_dir/oha-image-pull.log" 2>&1 \
    || fail "pinned oha image is unavailable"
fi

dataplane_image_id="$(docker image inspect --format '{{.Id}}' "$image")" \
  || fail "dataplane image is unavailable: $image"
compiler_image_id="$(docker image inspect --format '{{.Id}}' "$compiler_image")"
upstream_image_id="$(docker image inspect --format '{{.Id}}' "$upstream_image")"
grpc_image_id="$(docker image inspect --format '{{.Id}}' "$grpc_image")"
oha_image_id="$(docker image inspect --format '{{.Id}}' "$oha_image")"
docker image inspect "$dataplane_image_id" "$compiler_image_id" \
  "$upstream_image_id" "$grpc_image_id" "$oha_image_id" \
  >"$stage_dir/images.inspect.json"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -sha256 \
  -subj "/CN=BonVoyage Multi-Hour Hardening CA" \
  -keyout "$work_dir/ca-key.pem" -out "$work_dir/secrets/ca.pem" \
  >/dev/null 2>&1
cp "$work_dir/secrets/ca.pem" "$work_dir/secrets/upstream-ca.pem"
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=api.example.test" -keyout "$work_dir/secrets/server-key.pem" \
  -out "$work_dir/server.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:api.example.test' \
  'extendedKeyUsage=serverAuth' 'keyUsage=digitalSignature,keyEncipherment' \
  >"$work_dir/server-ext.cnf"
openssl x509 -req -days 2 -sha256 -in "$work_dir/server.csr" \
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
openssl x509 -req -days 2 -sha256 -in "$work_dir/upstream.csr" \
  -CA "$work_dir/secrets/ca.pem" -CAkey "$work_dir/ca-key.pem" \
  -CAcreateserial -extfile "$work_dir/upstream-ext.cnf" \
  -out "$work_dir/secrets/upstream-chain.pem" >/dev/null 2>&1
chmod 600 "$work_dir/ca-key.pem" "$work_dir/secrets"/*-key.pem

bv_stage_fixture_secrets "$secret_volume" "$work_dir/secrets" "$upstream_image_id" "$platform" \
  server-chain.pem server-key.pem upstream-ca.pem

docker network create --internal "$network" >/dev/null \
  || fail "could not create isolated Docker network"
docker volume create "$snapshot_volume" >/dev/null \
  || fail "could not create snapshot volume"
docker volume create "$access_volume" >/dev/null \
  || fail "could not create access-log volume"
docker run --rm --platform "$platform" --network none \
  --volume "$access_volume:/access" --entrypoint chown "$upstream_image_id" \
  -R 65532:65532 /access >/dev/null \
  || fail "could not prepare the access-log volume"
docker run --rm --platform "$platform" --network none --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$fixture:/etc/bonvoyage/hardening.yaml:ro" \
  --volume "$snapshot_volume:/var/lib/bonvoyage" "$compiler_image_id" \
  -input /etc/bonvoyage/hardening.yaml \
  -output /var/lib/bonvoyage/snapshot.pb \
  >"$stage_dir/snapshot-compiler.log" 2>&1 \
  || fail "hardening snapshot compilation failed"

docker run --detach --platform "$platform" --name "$loadgen" \
  --user "$(id -u):$(id -g)" \
  --network "$network" --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true --cap-drop ALL --entrypoint python \
  --env PYTHONOPTIMIZE=0 \
  --volume "$script_dir/phase3-composite-hardening-client.py:/composite-client.py:ro" \
  "$upstream_image_id" -m http.server 18080 >/dev/null \
  || fail "could not start isolated load generator"
for endpoint in stable canary; do
  if [ "$endpoint" = stable ]; then container="$stable"; else container="$canary"; fi
  docker run --detach --platform "$platform" --name "$container" \
    --user "$(id -u):$(id -g)" \
    --network "$network" --network-alias "$endpoint" --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --security-opt no-new-privileges:true --cap-drop ALL --entrypoint python \
    --env "BONVOYAGE_UPSTREAM_ID=$endpoint" \
    --env BONVOYAGE_UPSTREAM_LOG_REQUESTS=0 \
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
docker run --detach --platform "$platform" --name "$collector" \
  --user "$(id -u):$(id -g)" \
  --network "$network" --network-alias collector --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true --cap-drop ALL --entrypoint python \
  --env PYTHONDONTWRITEBYTECODE=1 --env PYTHONOPTIMIZE=0 \
  --env BONVOYAGE_EVIDENCE_DIR=/evidence \
  --env "BONVOYAGE_OTLP_MAX_PAYLOAD_FILES=$trace_payload_file_limit" \
  --volume "$script_dir/phase3-otlp-collector.py:/collector.py:ro" \
  --volume "$stage_dir:/evidence" "$upstream_image_id" -B /collector.py \
  >/dev/null || fail "could not start controlled OTLP collector"

wait_for_url() {
  url="$1"
  label="$2"
  attempt=0
  until docker exec "$loadgen" python -c \
    'import sys, urllib.request; assert urllib.request.urlopen(sys.argv[1], timeout=1).status in (200, 204)' \
    "$url" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 60 ] || fail "$label did not become ready"
    sleep 1
  done
}

wait_for_url http://stable:8081/healthz "stable upstream"
wait_for_url http://canary:8081/healthz "canary upstream"
wait_for_url http://websocket:8081/healthz "WebSocket upstream"
wait_for_url http://upstream-grpc.example.test:8081/healthz "gRPC upstream"
wait_for_url http://collector:4318/healthz "OTLP collector"

docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test --dns-search . --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$snapshot_volume:/snapshot:ro" \
  --volume "$access_volume:/var/log/bonvoyage" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
  "$dataplane_image_id" --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --runtime-log-transport stderr-pipe \
  --access-log-directory /var/log/bonvoyage \
  --access-log-queue-capacity 8192 \
  --access-log-max-file-bytes 268435456 \
  --access-log-flush-interval-ms 500 \
  --access-log-sample-every "$access_sample_every" \
  --otlp-traces-endpoint http://collector:4318/v1/traces \
  --otlp-traces-allow-insecure \
  --otlp-traces-queue-capacity 2048 \
  --otlp-traces-max-batch-spans 64 \
  --otlp-traces-max-batch-bytes 1048576 \
  --otlp-traces-flush-interval-ms 500 \
  --otlp-traces-request-timeout-ms 500 \
  --otlp-traces-sample-every "$trace_sample_every" \
  --otlp-traces-max-retries 1 \
  --otlp-traces-retry-initial-backoff-ms 100 \
  --otlp-traces-retry-max-backoff-ms 100 \
  --smp "$shards" --memory 512M --overprovisioned \
  --logger-log-level bonvoyage-gateway=info \
  --logger-log-level bonvoyage-access-log=info \
  --logger-log-level bonvoyage-otlp-traces=info >/dev/null \
  || fail "could not start the hardening dataplane"
bv_wait_gateway_ready "$gateway" "$loadgen" "http://$gateway:9901/health/ready"

capture_url() {
  url="$1"
  destination="$2"
  docker exec "$loadgen" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1], timeout=10).read())
' "$url" >"$destination"
}

post_collector() {
  action="$1"
  docker exec "$loadgen" python -c '
import sys
import urllib.request
request = urllib.request.Request(
    "http://collector:4318/" + sys.argv[1], data=b"", method="POST"
)
with urllib.request.urlopen(request, timeout=5) as response:
    assert response.status == 200
' "$action"
}

capture_metrics() {
  destination="$1"
  capture_url "http://$gateway:9090/metrics" "$destination"
}

wait_for_final_drains() {
  attempt=0
  while [ "$attempt" -lt 300 ]; do
    capture_metrics "$work_dir/drain-metrics.prom" || true
    if python3 - "$work_dir/drain-metrics.prom" "$shards" <<'PY' >/dev/null 2>&1
import sys

text = open(sys.argv[1], encoding="utf-8").read()
shards = float(sys.argv[2])
names = {
    "bonvoyage_bonvoyage_gateway_access_log_queue_depth": 0.0,
    "bonvoyage_bonvoyage_gateway_active_connections": 0.0,
    "bonvoyage_bonvoyage_gateway_active_http2_connections": 0.0,
    "bonvoyage_bonvoyage_gateway_active_http2_streams": 0.0,
    "bonvoyage_bonvoyage_gateway_active_requests": 0.0,
    "bonvoyage_bonvoyage_gateway_active_route_requests": 0.0,
    "bonvoyage_bonvoyage_gateway_active_upstream_requests": 0.0,
    "bonvoyage_bonvoyage_gateway_active_upstream_http2_streams": 0.0,
    "bonvoyage_bonvoyage_gateway_active_retries": 0.0,
    "bonvoyage_bonvoyage_gateway_active_websocket_connections": 0.0,
    "bonvoyage_bonvoyage_gateway_otlp_trace_queue_depth": 0.0,
    "bonvoyage_bonvoyage_gateway_access_log_sink_healthy": shards,
    "bonvoyage_bonvoyage_gateway_otlp_trace_exporter_healthy": shards,
}
totals = {name: 0.0 for name in names}
seen = set()
accounting_names = {
    "bonvoyage_bonvoyage_gateway_access_log_records_enqueued_total",
    "bonvoyage_bonvoyage_gateway_access_log_records_written_total",
    "bonvoyage_bonvoyage_gateway_otlp_trace_spans_sampled_total",
    "bonvoyage_bonvoyage_gateway_otlp_trace_spans_exported_total",
    "bonvoyage_bonvoyage_gateway_otlp_trace_spans_dropped_total",
}
accounting = {name: 0.0 for name in accounting_names}
for line in text.splitlines():
    if not line or line.startswith("#"):
        continue
    metric, raw = line.split(None, 1)
    name = metric.split("{", 1)[0]
    if name in totals:
        totals[name] += float(raw)
        seen.add(name)
    if name in accounting:
        accounting[name] += float(raw)
        seen.add(name)
assert seen == set(names) | accounting_names, seen
assert totals == names, totals
assert accounting[
    "bonvoyage_bonvoyage_gateway_access_log_records_written_total"
] == accounting["bonvoyage_bonvoyage_gateway_access_log_records_enqueued_total"]
assert accounting[
    "bonvoyage_bonvoyage_gateway_otlp_trace_spans_exported_total"
] + accounting[
    "bonvoyage_bonvoyage_gateway_otlp_trace_spans_dropped_total"
] == accounting["bonvoyage_bonvoyage_gateway_otlp_trace_spans_sampled_total"]
PY
    then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.2
  done
  fail "gateway queues, requests, streams, tunnels, or sinks did not reach the final healthy drain state"
}

wait_for_exporter_state() {
  expected="$1"
  label="$2"
  attempt=0
  while [ "$attempt" -lt 200 ]; do
    capture_metrics "$work_dir/exporter-state.prom" || true
    if python3 - "$work_dir/exporter-state.prom" "$shards" "$expected" <<'PY' >/dev/null 2>&1
import sys
import re

name = "bonvoyage_bonvoyage_gateway_otlp_trace_exporter_healthy"
text = open(sys.argv[1], encoding="utf-8").read()
values = {}
for line in text.splitlines():
    if not line.startswith(name + "{"):
        continue
    labels, raw = line.split(None, 1)
    match = re.search(r'shard="(\d+)"', labels)
    assert match, line
    values[int(match.group(1))] = float(raw)
assert set(values) == set(range(int(sys.argv[2]))), values
assert all(value == float(sys.argv[3]) for value in values.values()), values
PY
    then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  fail "OTLP exporters did not reach $label on every shard"
}

wait_for_exporter_healthy() {
  wait_for_exporter_state 1 healthy
}

wait_for_exporter_unhealthy() {
  wait_for_exporter_state 0 unhealthy
}

run_http() {
  output="$1"
  path="$2"
  count="$3"
  concurrency="$4"
  docker exec "$loadgen" python /composite-client.py http "$gateway" \
    "$path" "$count" "$concurrency" >"$output" \
    || fail "HTTP workload failed: $(basename "$output")"
}

run_websocket() {
  output="$1"
  count="$2"
  concurrency="$3"
  docker exec "$loadgen" python /composite-client.py websocket "$gateway" \
    "$count" "$concurrency" >"$output" \
    || fail "WebSocket workload failed: $(basename "$output")"
}

run_grpc() {
  output="$1"
  docker run --rm --platform "$platform" --network "$network" --read-only \
    --user "$(id -u):$(id -g)" \
    --security-opt no-new-privileges:true --cap-drop ALL \
    --volume "$work_dir/secrets:/secrets:ro" "$grpc_image_id" client \
    --target api.example.test:8443 --ca /secrets/ca.pem \
    --server-name api.example.test --case concurrent >"$output" \
    || fail "native unary gRPC workload failed: $(basename "$output")"
}

toggle_canary_failure() {
  enabled="$1"
  docker exec "$loadgen" python -c '
import sys
import urllib.request
urllib.request.urlopen(
    "http://canary:8081/control/failure?enabled=" + sys.argv[1], timeout=5
).read()
' "$enabled"
}

wait_for_endpoint_circuits_closed() {
  cycle_label="$1"
  attempt=1
  while [ "$attempt" -le 20 ]; do
    attempt_label="$(printf '%02d' "$attempt")"
    run_http "$cycle_dir/weighted-recovery-probe-$cycle_label-$attempt_label.json" \
      /split 32 32
    run_http "$cycle_dir/load-balancing-recovery-probe-$cycle_label-$attempt_label.json" \
      /lb 32 32
    ready_metrics="$metrics_dir/circuit-recovery-ready-$cycle_label.prom"
    capture_metrics "$ready_metrics"
    if python3 - "$ready_metrics" "$shards" <<'PY' >/dev/null 2>&1
import re
import sys

prefix = "bonvoyage_bonvoyage_gateway_"
names = {
    prefix + "open_endpoint_circuits",
    prefix + "half_open_endpoint_circuits",
}
values = {name: {} for name in names}
for line in open(sys.argv[1], encoding="utf-8"):
    if not line or line.startswith("#"):
        continue
    metric, raw = line.split(None, 1)
    name = metric.split("{", 1)[0]
    if name not in names:
        continue
    match = re.search(r'shard="(\d+)"', metric)
    assert match, line
    shard = int(match.group(1))
    values[name][shard] = values[name].get(shard, 0.0) + float(raw)
expected_shards = set(range(int(sys.argv[2])))
for name in names:
    assert set(values[name]) == expected_shards, (name, values[name])
    assert all(value == 0 for value in values[name].values()), (
        name,
        values[name],
    )
PY
    then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  fail "endpoint circuits did not close on every shard before recovery verification"
}

measure_rss_kib() {
  docker top "$gateway" -eo pid,rss 2>/dev/null \
    | awk 'NR > 1 && $2 ~ /^[0-9]+$/ { total += $2; count += 1 }
      END { if (count == 0) exit 1; printf "%.0f\n", total }'
}

measure_fd_count() {
  docker run --rm --platform "$platform" --pid "container:$gateway" \
    --network none --read-only --security-opt no-new-privileges:true \
    --cap-drop ALL --user 65532:65532 --entrypoint python "$upstream_image_id" -c \
    'import os; print(len(os.listdir("/proc/1/fd")))'
}

record_resource_sample() {
  phase="$1"
  cycle="$2"
  now="$(date +%s)"
  elapsed=$((now - start_epoch))
  rss_kib="$(measure_rss_kib)" || fail "could not measure gateway RSS"
  fd_count="$(measure_fd_count)" || fail "could not measure gateway file descriptors"
  stats="$(docker stats --no-stream --format '{{.CPUPerc}}|{{.PIDs}}' "$gateway")" \
    || fail "could not sample gateway CPU and process count"
  cpu_percent="${stats%%|*}"
  cpu_percent="${cpu_percent%%%}"
  pids="${stats#*|}"
  identity="$(docker inspect --format '{{.Id}}|{{.State.Pid}}|{{.State.StartedAt}}' "$gateway")"
  restart_count="$(docker inspect --format '{{.RestartCount}}' "$gateway")"
  running="$(docker inspect --format '{{.State.Running}}' "$gateway")"
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$elapsed" "$phase" "$cycle" \
    "$rss_kib" "$cpu_percent" "$pids" "$fd_count" "$restart_count" \
    "$running" "$identity" >>"$stage_dir/resource-samples.csv"
  printf '%s cycle=%s phase=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$cycle" "$phase" >>"$stage_dir/support-resource-samples.log"
  docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.PIDs}}' \
    "$gateway" "$loadgen" "$stable" "$canary" "$websocket" \
    "$grpc_upstream" "$collector" >>"$stage_dir/support-resource-samples.log" \
    || fail "could not sample supporting container resources"
}

post_collector recover
run_http "$stage_dir/warmup.json" /ready 512 32
sleep 2
wait_for_exporter_healthy

printf 'timestamp_utc,elapsed_seconds,phase,cycle,rss_kib,cpu_percent,pids,fd_count,restart_count,running,identity\n' \
  >"$stage_dir/resource-samples.csv"
start_epoch="$(date +%s)"
deadline_epoch=$((start_epoch + duration_seconds))
initial_identity="$(docker inspect --format '{{.Id}}|{{.State.Pid}}|{{.State.StartedAt}}' "$gateway")"
printf 'initial=%s\n' "$initial_identity" >"$stage_dir/gateway-identities.txt"
capture_metrics "$metrics_dir/metrics-baseline.prom"
record_resource_sample baseline 0

docker run --detach --platform "$platform" --name "$h2_load" \
  --user "$(id -u):$(id -g)" \
  --network "$network" --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$work_dir/secrets:/tls:ro" "$oha_image_id" \
  -z "${duration_seconds}s" -q "$qps" --latency-correction \
  -c "$h2_connections" -p "$h2_parallel" \
  --no-tui --output-format json --http-version 2 \
  --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/ready >/dev/null \
  || fail "could not start continuous TLS HTTP/2 workload"

cycle=1
failure_cycles=0
while [ "$(date +%s)" -lt "$deadline_epoch" ]; do
  now="$(date +%s)"
  h2_running="$(docker inspect --format '{{.State.Running}}' "$h2_load")"
  if [ "$h2_running" != true ] && [ "$now" -lt $((deadline_epoch - 5)) ]; then
    fail "continuous TLS HTTP/2 workload exited before its deadline"
  fi

  cycle_label="$(printf '%04d' "$cycle")"
  run_http "$cycle_dir/http1-$cycle_label.json" /ready \
    "$http_requests_per_cycle" 16
  run_websocket "$cycle_dir/websocket-$cycle_label.json" \
    "$websocket_cycles_per_cycle" 4
  run_grpc "$cycle_dir/grpc-$cycle_label.json"

  if [ $(((cycle - 1) % saturation_every_cycles)) -eq 0 ]; then
    run_http "$cycle_dir/saturation-$cycle_label.json" /saturate 32 32
    run_http "$cycle_dir/saturation-recovery-$cycle_label.json" /ready 64 16
  fi

  if [ $(((cycle - 1) % failure_every_cycles)) -eq 0 ]; then
    failure_cycles=$((failure_cycles + 1))
    toggle_canary_failure 1
    run_http "$cycle_dir/weighted-failure-$cycle_label.json" /split \
      "$failure_requests" 32
    run_http "$cycle_dir/load-balancing-failure-$cycle_label.json" /lb \
      "$failure_requests" 32
    toggle_canary_failure 0
    sleep 1
    # Expired circuits become half-open lazily and admit one probe. Complete
    # that documented transition before asserting concurrent steady recovery.
    wait_for_endpoint_circuits_closed "$cycle_label"
    run_http "$cycle_dir/weighted-recovery-$cycle_label.json" /split \
      "$failure_requests" 32
    run_http "$cycle_dir/load-balancing-recovery-$cycle_label.json" /lb \
      "$failure_requests" 32

    capture_metrics "$metrics_dir/collector-before-$cycle_label.prom"
    post_collector fail
    run_http "$cycle_dir/collector-loss-$cycle_label.json" /ready 64 16
    sleep "$collector_outage_seconds"
    wait_for_exporter_unhealthy
    capture_metrics "$metrics_dir/collector-failed-$cycle_label.prom"
    post_collector recover
    run_http "$cycle_dir/collector-recovery-$cycle_label.json" /ready 64 16
    wait_for_exporter_healthy
    capture_metrics "$metrics_dir/collector-recovered-$cycle_label.prom"
  fi

  if [ $(((cycle - 1) % metrics_every_cycles)) -eq 0 ]; then
    capture_metrics "$metrics_dir/metrics-cycle-$cycle_label.prom"
  fi
  record_resource_sample cycle "$cycle"

  next_cycle_epoch=$((start_epoch + cycle * cycle_interval_seconds))
  [ "$next_cycle_epoch" -le "$deadline_epoch" ] \
    || next_cycle_epoch="$deadline_epoch"
  now="$(date +%s)"
  if [ "$next_cycle_epoch" -gt "$now" ]; then
    sleep $((next_cycle_epoch - now))
  fi
  cycle=$((cycle + 1))
done

h2_exit_code="$(docker wait "$h2_load")"
[ "$h2_exit_code" -eq 0 ] || fail "continuous TLS HTTP/2 workload exited with $h2_exit_code"
docker logs "$h2_load" >"$stage_dir/http2-soak.oha.json" 2>"$stage_dir/http2-soak.stderr"
run_http "$stage_dir/final-recovery.json" /ready 128 16
wait_for_final_drains
sleep 2
wait_for_final_drains
capture_metrics "$stage_dir/metrics-final.prom"
record_resource_sample final "$cycle"
capture_url http://collector:4318/observations "$stage_dir/collector-observations.json"

final_identity="$(docker inspect --format '{{.Id}}|{{.State.Pid}}|{{.State.StartedAt}}' "$gateway")"
printf 'final=%s\n' "$final_identity" >>"$stage_dir/gateway-identities.txt"
[ "$final_identity" = "$initial_identity" ] \
  || fail "gateway process identity changed during multi-hour hardening"

capture_container "$gateway" gateway-before-stop
docker stop --signal TERM --time 30 "$gateway" >/dev/null \
  || fail "gateway did not stop within the bounded drain window"
gateway_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
[ "$gateway_exit_code" -eq 0 ] || fail "gateway exit code was $gateway_exit_code"
printf '%s\n' "$gateway_exit_code" >"$stage_dir/gateway-exit-code.txt"
capture_container "$gateway" gateway

# The dataplane owns its access-log files as the runtime UID and intentionally
# creates them without world-read access. After it has stopped, let that same
# UID grant the isolated validator read-only access to the completed evidence.
docker run --rm --platform "$platform" --network none --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL --user 65532:65532 \
  --volume "$access_volume:/access" --entrypoint chmod "$upstream_image_id" \
  -R u=rwX,go=rX /access >/dev/null \
  || fail "could not make completed access logs readable by the validator"

docker run --rm --platform "$platform" --network none --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL --entrypoint python \
  --user "$(id -u):$(id -g)" \
  --env PYTHONOPTIMIZE=0 \
  --volume "$access_volume:/access:ro" \
  --volume "$stage_dir:/evidence" \
  --volume "$script_dir/phase3-hardening-access-validate.py:/validate.py:ro" \
  "$upstream_image_id" -B /validate.py \
  || fail "access-log schema and privacy validation failed"

python3 "$script_dir/phase3-multi-hour-analyze.py" \
  --evidence "$stage_dir" \
  --duration-seconds "$duration_seconds" \
  --qps "$qps" \
  --h2-max-deadline-aborts "$h2_deadline_abort_limit" \
  --shards "$shards" \
  --rss-max-growth-bytes "$rss_max_growth_bytes" \
  --rss-max-growth-percent "$rss_max_growth_percent" \
  --rss-max-slope-kib-per-hour "$rss_max_slope_kib_per_hour" \
  --fd-max-growth "$fd_max_growth" \
  --fd-max-slope-per-hour "$fd_max_slope_per_hour" \
  >"$stage_dir/validation.txt" \
  || fail "multi-hour evidence assertions failed"

finish_epoch="$(date +%s)"
actual_duration_seconds=$((finish_epoch - start_epoch))
final_source_commit="$(git rev-parse HEAD)"
[ "$final_source_commit" = "$initial_source_commit" ] \
  || fail "source commit changed during the hardening run"
git status --porcelain=v1 --untracked-files=all >"$stage_dir/source-status-end.txt"
cmp -s "$stage_dir/source-status-start.txt" "$stage_dir/source-status-end.txt" \
  || fail "source working-tree state changed during the hardening run"
while IFS= read -r source_file; do
  [ -f "$source_file" ] || fail "source checksum input disappeared: $source_file"
  if [ "$checksum_tool" = sha256sum ]; then
    sha256sum "$source_file"
  else
    shasum -a 256 "$source_file"
  fi
done <"$stage_dir/source-files.txt" >"$work_dir/source-checksums-end.sha256"
cmp -s "$stage_dir/source-checksums.sha256" "$work_dir/source-checksums-end.sha256" \
  || fail "source content changed during the hardening run"
docker version >"$stage_dir/docker-version.txt" 2>&1
docker info >"$stage_dir/docker-info.txt" 2>&1
uname -a >"$stage_dir/uname.txt"

cat >"$stage_dir/metadata.txt" <<EOF
captured_at_utc=$timestamp
run_id=$run_id
profile=$profile
source_commit=$initial_source_commit
source_dirty=$source_dirty
platform=$platform
configured_duration_seconds=$duration_seconds
actual_duration_seconds=$actual_duration_seconds
cycle_interval_seconds=$cycle_interval_seconds
cycles_completed=$((cycle - 1))
failure_cycles=$failure_cycles
gateway_shards=$shards
http2_qps=$qps
http2_connections=$h2_connections
http2_parallel_per_connection=$h2_parallel
http2_max_deadline_aborts=$h2_deadline_abort_limit
http_requests_per_cycle=$http_requests_per_cycle
websocket_cycles_per_cycle=$websocket_cycles_per_cycle
failure_requests_per_window=$failure_requests
collector_outage_seconds=$collector_outage_seconds
access_log_sample_every=$access_sample_every
trace_sample_every=$trace_sample_every
rss_max_growth_bytes=$rss_max_growth_bytes
rss_max_growth_percent=$rss_max_growth_percent
rss_max_slope_kib_per_hour=$rss_max_slope_kib_per_hour
fd_max_growth=$fd_max_growth
fd_max_slope_per_hour=$fd_max_slope_per_hour
dataplane_image_id=$dataplane_image_id
compiler_image_id=$compiler_image_id
upstream_image_id=$upstream_image_id
grpc_image_id=$grpc_image_id
oha_image_id=$oha_image_id
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
performance_claim_authorized=false
EOF

cat >"$stage_dir/summary.txt" <<EOF
outcome: PASS
scope: Phase 3 $profile local hardening
configured_duration_seconds: $duration_seconds
actual_duration_seconds: $actual_duration_seconds
gateway_shards: $shards
continuous_http2_qps: $qps
continuous_http2_workers: $h2_deadline_abort_limit
mixed_protocol_cycles: $((cycle - 1))
controlled_failure_recovery_cycles: $failure_cycles
gateway_identity_unchanged: true
gateway_exit_code: $gateway_exit_code
access_log_final_state: healthy and drained with zero unexpected loss
otlp_final_state: healthy and drained after repeated controlled collector loss
claim_limit: local Docker hardening evidence; not dedicated performance, capacity, indefinite leak freedom, production readiness, or marketing authorization
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 multi-hour local hardening evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This record does not authorize
performance, competitive, capacity, production-readiness, or marketing claims.

One unchanged ${shards}-shard BonVoyage process carried rate-limited TLS HTTP/2
traffic continuously for ${duration_seconds} configured seconds while repeated
cycles exercised HTTP/1.1, unary gRPC, WebSocket, route saturation, static
weighted-canary failure, load-balancer ejection, OTLP collector loss, and
same-process recovery. Bounded shard-local access logging and OTLP tracing were
enabled throughout.

The machine-readable decision is in \`validation-summary.json\`. It covers
unexpected request errors, process identity, sampled CPU/RSS/PID/file-descriptor
state, post-warmup RSS and descriptor trends, final queue and active gauges,
access-log schema/privacy, collector failure/recovery, allocator failures, and
clean shutdown. Slope assertions are authoritative only for runs of at least one
hour; shorter preflights validate harness behavior and retained-growth bounds.

Dedicated native Linux qualification, separated load-generator/upstream
headroom, competitive performance, and longer-duration leak claims remain
separate gates.
EOF

printf 'outcome=PASS\nexit_code=0\n' >"$stage_dir/run-status.env"
write_checksums || fail "could not create the hardening evidence manifest"

mkdir -p "$output_root"
mv "$stage_dir" "$output_dir"
if [ "$source_dirty" = false ] && [ "$profile" = twenty-four-hour ]; then
  printf '%s\n' "$run_id" >"$output_root/current-multi-hour-hardening.txt.tmp"
  mv "$output_root/current-multi-hour-hardening.txt.tmp" \
    "$output_root/current-multi-hour-hardening.txt"
fi

printf 'Multi-hour local hardening passed: %s\n' "$output_dir"
cat "$output_dir/validation.txt"
