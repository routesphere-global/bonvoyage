#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo="${BONVOYAGE_REPO:-$(CDPATH='' cd -- "$script_dir/../.." && pwd)}"
# shellcheck source=scripts/test-fixture-secrets.sh
. "$repo/scripts/test-fixture-secrets.sh"

gateway_image="${BONVOYAGE_RESPONSE_GATEWAY_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-benchmark-upstream:response-boundary}"
fixture_image="${BONVOYAGE_FIXTURE_IMAGE:-bonvoyage-upstream:dev}"
loadgen_image="${BONVOYAGE_LOADGEN_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
gateway_cpus="${BONVOYAGE_RESPONSE_GATEWAY_CPUS:-2-3}"
loadgen_cpus="${BONVOYAGE_RESPONSE_LOADGEN_CPUS:-4-7}"
upstream_cpus="${BONVOYAGE_RESPONSE_UPSTREAM_CPUS:-8-13}"
gateway_cores="${BONVOYAGE_RESPONSE_GATEWAY_CORES:-2}"
loadgen_cores="${BONVOYAGE_RESPONSE_LOADGEN_CORES:-4}"
upstream_cores="${BONVOYAGE_RESPONSE_UPSTREAM_CORES:-6}"
connections="${BONVOYAGE_RESPONSE_CONNECTIONS:-64}"
repetitions="${BONVOYAGE_RESPONSE_REPETITIONS:-5}"
warmup_seconds="${BONVOYAGE_RESPONSE_WARMUP_SECONDS:-5}"
measurement_seconds="${BONVOYAGE_RESPONSE_MEASUREMENT_SECONDS:-10}"
maximum_support_capacity="${BONVOYAGE_MAXIMUM_SUPPORT_ROLE_CAPACITY_PERCENT:-80}"
minimum_upstream_headroom="${BONVOYAGE_MINIMUM_UPSTREAM_HEADROOM_RATIO:-1.2}"
upstream_capacity_seconds="${BONVOYAGE_RESPONSE_UPSTREAM_CAPACITY_SECONDS:-5}"
require_clean="${BONVOYAGE_RESPONSE_REQUIRE_CLEAN:-1}"
seed="${BONVOYAGE_RESPONSE_SEED:-bonvoyage-response-boundary-v1}"
stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
run_id="response-boundary-local-$stamp"
run_dir="${BONVOYAGE_RESPONSE_RESULT_DIR:-${TMPDIR:-/tmp}/$run_id}"
suffix="$$-$stamp"
network="bonvoyage-response-boundary-$suffix"
http_volume="bonvoyage-response-http-$suffix"
https_volume="bonvoyage-response-https-$suffix"
secret_volume="bonvoyage-response-secrets-$suffix"
upstream="bonvoyage-response-upstream-$suffix"
probe="bonvoyage-response-probe-$suffix"
gateway=''
loadgen=''
tls_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-response-tls.XXXXXX")"
ca_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-response-ca.XXXXXX")"

fail() { echo "response-boundary: $*" >&2; exit 1; }
require_positive_integer() {
  case "$2" in ''|*[!0-9]*|0) fail "$1 must be a positive integer" ;; esac
}

cleanup() {
  status="$?"
  set +e
  [ -z "$loadgen" ] || docker rm --force "$loadgen" >/dev/null 2>&1
  [ -z "$gateway" ] || docker rm --force "$gateway" >/dev/null 2>&1
  docker rm --force "$upstream" "$probe" >/dev/null 2>&1
  docker network rm "$network" >/dev/null 2>&1
  docker volume rm "$http_volume" "$https_volume" >/dev/null 2>&1
  bv_remove_fixture_secrets "$secret_volume" "$tls_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  rm -rf "$tls_dir" "$ca_dir"
  exit "$status"
}
trap cleanup EXIT INT TERM

for item in "$gateway_cores" "$loadgen_cores" "$upstream_cores" "$connections" \
  "$repetitions" "$warmup_seconds" "$measurement_seconds"; do
  require_positive_integer value "$item"
done
require_positive_integer BONVOYAGE_RESPONSE_UPSTREAM_CAPACITY_SECONDS "$upstream_capacity_seconds"
case "$require_clean" in 0|1) ;; *) fail 'BONVOYAGE_RESPONSE_REQUIRE_CLEAN must be 0 or 1' ;; esac
command -v openssl >/dev/null 2>&1 || fail 'openssl is required'
command -v jq >/dev/null 2>&1 || fail 'jq is required'

mkdir -p "$run_dir/results"
git -C "$repo" rev-parse HEAD >"$run_dir/git-commit.txt"
git -C "$repo" status --short >"$run_dir/git-status-before.txt"
git -C "$repo" diff --binary >"$run_dir/source.diff"
git -C "$repo" ls-files --others --exclude-standard >"$run_dir/untracked-files.txt"
if [ "$require_clean" -eq 1 ] && [ -s "$run_dir/git-status-before.txt" ]; then
  fail 'clean source is required; commit the harness before the full matrix'
fi
source_commit="$(cat "$run_dir/git-commit.txt")"
source_dirty=false
[ ! -s "$run_dir/git-status-before.txt" ] || source_dirty=true

node "$script_dir/response-boundary.mjs" plan --repetitions "$repetitions" --seed "$seed" \
  >"$run_dir/plan.json"
cp "$0" "$run_dir/run-response-boundary-local.sh"
cp "$script_dir/response-boundary.mjs" "$run_dir/response-boundary.mjs"
docker image inspect "$gateway_image" >"$run_dir/gateway-image-inspect.json"
docker image inspect "$compiler_image" >"$run_dir/compiler-image-inspect.json"
docker image inspect "$upstream_image" >"$run_dir/upstream-image-inspect.json"
docker image inspect "$fixture_image" >"$run_dir/fixture-image-inspect.json"
docker image inspect "$loadgen_image" >"$run_dir/loadgen-image-inspect.json"
docker info >"$run_dir/docker-info.txt"
uname -a >"$run_dir/uname.txt"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj '/CN=BonVoyage Response Boundary CA' \
  -keyout "$tls_dir/ca-key.pem" -out "$tls_dir/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 -subj '/CN=api.example.test' \
  -keyout "$tls_dir/server-key.pem" -out "$tls_dir/server.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:api.example.test' 'extendedKeyUsage=serverAuth' \
  'keyUsage=digitalSignature,keyEncipherment' >"$tls_dir/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$tls_dir/server.csr" \
  -CA "$tls_dir/ca.pem" -CAkey "$tls_dir/ca-key.pem" -CAcreateserial \
  -extfile "$tls_dir/server-ext.cnf" -out "$tls_dir/server-chain.pem" >/dev/null 2>&1
chmod 600 "$tls_dir"/*-key.pem
cp "$tls_dir/ca.pem" "$ca_dir/ca.pem"
openssl x509 -in "$tls_dir/server-chain.pem" -noout -subject -issuer -dates \
  -fingerprint -sha256 >"$run_dir/tls-certificate-metadata.txt"
{
  printf 'ca.pem  '; shasum -a 256 "$tls_dir/ca.pem" | awk '{print $1}'
  printf 'server-chain.pem  '; shasum -a 256 "$tls_dir/server-chain.pem" | awk '{print $1}'
} >"$run_dir/tls-public-artifact-sha256.txt"

docker network create "$network" >/dev/null
docker volume create "$http_volume" >/dev/null
docker volume create "$https_volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$tls_dir" "$fixture_image" "$platform" \
  server-chain.pem server-key.pem

prepare_snapshot_volume() {
  docker run --rm --pull never --platform "$platform" --network none --read-only \
    --user 0:0 --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges:true \
    --volume "$1:/output" --entrypoint python "$fixture_image" -c \
    'import os; os.chmod("/output", 0o700); os.chown("/output", 65532, 65532)'
}
prepare_snapshot_volume "$http_volume"
prepare_snapshot_volume "$https_volume"

docker run --rm --pull never --platform "$platform" \
  --volume "$repo/config/examples/local.yaml:/config/input.yaml:ro" \
  --volume "$http_volume:/output" "$compiler_image" \
  -input /config/input.yaml -output /output/snapshot.pb >/dev/null
docker run --rm --pull never --platform "$platform" \
  --volume "$repo/config/examples/tls.yaml:/config/input.yaml:ro" \
  --volume "$https_volume:/output" "$compiler_image" \
  -input /config/input.yaml -output /output/snapshot.pb >/dev/null

snapshot_sha() {
  docker run --rm --pull never --platform "$platform" --network none \
    --volume "$1:/snapshot:ro" --entrypoint python "$fixture_image" -c \
    'import hashlib; print(hashlib.sha256(open("/snapshot/snapshot.pb", "rb").read()).hexdigest())'
}
http_snapshot_sha256="$(snapshot_sha "$http_volume")"
https_snapshot_sha256="$(snapshot_sha "$https_volume")"

docker run --detach --pull never --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream --cpuset-cpus "$upstream_cpus" \
  --memory 1g --memory-swap 1g --pids-limit 2048 \
  --ulimit nofile=1048576:1048576 "$upstream_image" >/dev/null
docker run --detach --pull never --platform "$platform" --name "$probe" \
  --network "$network" --cpuset-cpus "$loadgen_cpus" --volume "$ca_dir:/tls:ro" \
  --entrypoint sleep "$fixture_image" 86400 >/dev/null
attempt=0
until docker exec "$upstream" wget -q -O - http://127.0.0.1:8081/healthz >/dev/null 2>&1; do
  attempt=$((attempt + 1)); [ "$attempt" -lt 30 ] || fail 'controlled upstream not ready'; sleep 1
done

gateway_image_id="$(docker image inspect --format '{{.Id}}' "$gateway_image")"
compiler_image_id="$(docker image inspect --format '{{.Id}}' "$compiler_image")"
upstream_image_id="$(docker image inspect --format '{{.Id}}' "$upstream_image")"
fixture_image_id="$(docker image inspect --format '{{.Id}}' "$fixture_image")"
load_generator_image_id="$(docker image inspect --format '{{.Id}}' "$loadgen_image")"

printf '{}\n' >"$run_dir/direct-upstream-capacity.json"
for payload_bytes in 8192 15360 16384 17408 32768 65536; do
  raw="$run_dir/direct-upstream-$payload_bytes.oha.json"
  docker run --rm --pull never --platform "$platform" --network "$network" \
    --cpuset-cpus "$loadgen_cpus" "$loadgen_image" -z "${upstream_capacity_seconds}s" \
    -c "$connections" -w --http-version 1.1 --disable-compression --no-tui --no-color \
    --output-format json "http://upstream:8081/payload/$payload_bytes" >"$raw"
  duration="$(jq -er '.summary.total | select(type == "number" and . > 0)' "$raw")" || \
    fail "direct upstream payload $payload_bytes has invalid duration"
  successful="$(jq -er '.statusCodeDistribution["200"] // 0' "$raw")"
  failures="$(jq '[.statusCodeDistribution | to_entries[]? | select(.key != "200") | .value] | add // 0' "$raw")"
  errors="$(jq '[.errorDistribution[]?] | add // 0' "$raw")"
  [ "$successful" -gt 0 ] && [ "$failures" -eq 0 ] && [ "$errors" -eq 0 ] || \
    fail "direct upstream payload $payload_bytes failed"
  direct_rps="$(awk -v count="$successful" -v duration="$duration" \
    'BEGIN {printf "%.12f", count / duration}')"
  jq --arg key "$payload_bytes" --argjson value "$direct_rps" '.[$key] = $value' \
    "$run_dir/direct-upstream-capacity.json" >"$run_dir/direct-upstream-capacity.next.json"
  mv "$run_dir/direct-upstream-capacity.next.json" "$run_dir/direct-upstream-capacity.json"
done
jq -n --arg run_id "$run_id" --arg source_commit "$source_commit" \
  --arg gateway_image_id "$gateway_image_id" --arg compiler_image_id "$compiler_image_id" \
  --arg upstream_image_id "$upstream_image_id" \
  --arg fixture_image_id "$fixture_image_id" \
  --arg load_generator_image_id "$load_generator_image_id" \
  --arg http_snapshot_sha256 "$http_snapshot_sha256" \
  --arg https_snapshot_sha256 "$https_snapshot_sha256" \
  --argjson source_dirty "$source_dirty" \
  --argjson maximum_support_capacity_percent "$maximum_support_capacity" \
  --argjson minimum_upstream_headroom_ratio "$minimum_upstream_headroom" \
  '{schema_version: 1, run_id: $run_id,
    evidence_class: "local-virtualized-response-boundary",
    publication_authorized: false,
    publication_reason: "Docker Desktop ARM64 VM; engineering evidence only",
    source_commit: $source_commit, source_dirty: $source_dirty,
    gateway_image_id: $gateway_image_id, compiler_image_id: $compiler_image_id,
    upstream_image_id: $upstream_image_id, fixture_image_id: $fixture_image_id,
    load_generator_image_id: $load_generator_image_id,
    http_snapshot_sha256: $http_snapshot_sha256,
    https_snapshot_sha256: $https_snapshot_sha256,
    maximum_support_capacity_percent: $maximum_support_capacity_percent,
    minimum_upstream_headroom_ratio: $minimum_upstream_headroom_ratio}' \
  >"$run_dir/environment.json"

verify_payload() {
  protocol="$1" payload_bytes="$2"
  docker exec "$probe" python - "$protocol" "$payload_bytes" <<'PY'
import http.client
import ssl
import sys

protocol, size_text = sys.argv[1:]
size = int(size_text)
if protocol == "https":
    context = ssl.create_default_context(cafile="/tls/ca.pem")
    connection = http.client.HTTPSConnection("api.example.test", 8443, context=context, timeout=5)
else:
    connection = http.client.HTTPConnection("gateway", 8080, timeout=5)
connection.request("GET", f"/payload/{size}", headers={"Host": "api.example.test"})
response = connection.getresponse()
body = response.read()
assert response.status == 200, response.status
assert response.getheader("content-length") == str(size), response.getheader("content-length")
assert len(body) == size and body == b"x" * size, len(body)
connection.close()
PY
}

wait_for_gateway() {
  attempt=0
  until bv_wait_gateway_ready "$gateway" "$probe" "http://gateway:9901/health/ready"; do
    attempt=$((attempt + 1)); [ "$attempt" -lt 2 ] || return 1
  done
}

jq -r '.points[] | [.order, .protocol, .payload_bytes, .repetition] | @tsv' \
  "$run_dir/plan.json" >"$run_dir/plan.tsv"
total="$(jq '.points | length' "$run_dir/plan.json")"
while IFS="$(printf '\t')" read -r order protocol payload_bytes repetition; do
  sample="$(printf '%03d-%s-%s-rep%s' "$order" "$protocol" "$payload_bytes" "$repetition")"
  gateway="bonvoyage-response-gateway-$order-$suffix"
  loadgen="bonvoyage-response-oha-$order-$suffix"
  case "$protocol" in
    http) snapshot_volume="$http_volume"; url="http://gateway:8080/payload/$payload_bytes" ;;
    https) snapshot_volume="$https_volume"; url="https://api.example.test:8443/payload/$payload_bytes" ;;
    *) fail "unknown protocol $protocol" ;;
  esac
  echo "[$order/$total] $protocol payload=$payload_bytes repetition=$repetition"
  set -- docker run --detach --pull never --platform "$platform" --name "$gateway" \
    --network "$network" --network-alias gateway --network-alias api.example.test \
    --cpuset-cpus "$gateway_cpus" --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    --cap-drop ALL --cap-add SYS_NICE --security-opt no-new-privileges:true \
    --memory 1g --memory-swap 1g --pids-limit 2048 --ulimit nofile=1048576:1048576 \
    --volume "$snapshot_volume:/snapshot:ro"
  if [ "$protocol" = https ]; then
    set -- "$@" --volume "$secret_volume:/etc/bonvoyage/secrets:ro"
  fi
  set -- "$@" "$gateway_image" --snapshot /snapshot/snapshot.pb
  if [ "$protocol" = https ]; then
    set -- "$@" --secrets-directory /etc/bonvoyage/secrets
  fi
  "$@" --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
    --smp "$gateway_cores" --memory 384M --overprovisioned >/dev/null
  wait_for_gateway || { docker logs "$gateway" >"$run_dir/results/$sample.gateway.log" 2>&1 || :;
    fail "$sample gateway readiness failed"; }
  verify_payload "$protocol" "$payload_bytes"

  if [ "$protocol" = https ]; then
    docker run --rm --pull never --platform "$platform" --network "$network" \
      --cpuset-cpus "$loadgen_cpus" --volume "$ca_dir:/tls:ro" "$loadgen_image" \
      -z "${warmup_seconds}s" -c "$connections" -w --http-version 1.1 \
      --disable-compression --cacert /tls/ca.pem --no-tui --no-color --output-format json \
      "$url" >"$run_dir/results/$sample.warmup.oha.json"
    docker run --detach --pull never --platform "$platform" --name "$loadgen" \
      --network "$network" --cpuset-cpus "$loadgen_cpus" --volume "$ca_dir:/tls:ro" \
      "$loadgen_image" -z "${measurement_seconds}s" -c "$connections" -w \
      --http-version 1.1 --disable-compression --cacert /tls/ca.pem --no-tui --no-color \
      --output-format json "$url" >/dev/null
  else
    docker run --rm --pull never --platform "$platform" --network "$network" \
      --cpuset-cpus "$loadgen_cpus" "$loadgen_image" -z "${warmup_seconds}s" \
      -c "$connections" -w --http-version 1.1 --disable-compression --no-tui --no-color \
      --output-format json "$url" >"$run_dir/results/$sample.warmup.oha.json"
    docker run --detach --pull never --platform "$platform" --name "$loadgen" \
      --network "$network" --cpuset-cpus "$loadgen_cpus" "$loadgen_image" \
      -z "${measurement_seconds}s" -c "$connections" -w --http-version 1.1 \
      --disable-compression --no-tui --no-color --output-format json "$url" >/dev/null
  fi

  stats="$run_dir/results/$sample.stats.tsv"
  printf 'epoch\trole\tcpu_percent\n' >"$stats"
  while [ "$(docker inspect --format '{{.State.Running}}' "$loadgen")" = true ]; do
    epoch="$(date -u '+%s')"
    docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}' \
      "$gateway" "$upstream" "$loadgen" 2>/dev/null | while IFS='|' read -r name cpu; do
      cpu="${cpu%%%}"
      case "$name" in "$gateway") role=gateway ;; "$upstream") role=upstream ;;
        "$loadgen") role=load_generator ;; *) continue ;; esac
      printf '%s\t%s\t%s\n' "$epoch" "$role" "$cpu"
    done >>"$stats" || :
    sleep 1
  done
  load_exit="$(docker wait "$loadgen")"
  docker logs "$loadgen" >"$run_dir/results/$sample.oha.json" 2>&1
  docker rm "$loadgen" >/dev/null
  loadgen=''
  [ "$load_exit" -eq 0 ] || fail "$sample load generator exited $load_exit"

  duration="$(jq -er '.summary.total | select(type == "number" and . > 0)' \
    "$run_dir/results/$sample.oha.json")" || fail "$sample has invalid duration"
  successful="$(jq -er '.statusCodeDistribution["200"] // 0' \
    "$run_dir/results/$sample.oha.json")"
  http_failures="$(jq '[.statusCodeDistribution | to_entries[]? | select(.key != "200") | .value] | add // 0' \
    "$run_dir/results/$sample.oha.json")"
  transport_failures="$(jq '[.errorDistribution[]?] | add // 0' \
    "$run_dir/results/$sample.oha.json")"
  [ "$successful" -gt 0 ] && [ "$http_failures" -eq 0 ] && [ "$transport_failures" -eq 0 ] || \
    fail "$sample returned failed responses"
  successful_rps="$(awk -v count="$successful" -v duration="$duration" \
    'BEGIN {printf "%.12f", count / duration}')"
  direct_upstream_rps="$(jq -er --arg key "$payload_bytes" '.[$key]' \
    "$run_dir/direct-upstream-capacity.json")"
  upstream_headroom_ratio="$(awk -v direct="$direct_upstream_rps" -v gateway="$successful_rps" \
    'BEGIN {printf "%.12f", direct/gateway}')"
  p50_ms="$(jq '.latencyPercentiles.p50 * 1000' "$run_dir/results/$sample.oha.json")"
  p95_ms="$(jq '.latencyPercentiles.p95 * 1000' "$run_dir/results/$sample.oha.json")"
  p99_ms="$(jq '.latencyPercentiles.p99 * 1000' "$run_dir/results/$sample.oha.json")"
  p999_ms="$(jq '.latencyPercentiles["p99.9"] * 1000' "$run_dir/results/$sample.oha.json")"
  role_metric() { awk -F '\t' -v role="$1" -v operation="$2" '$2 == role {
      if (operation == "mean") {sum += $3; count++} else if (!seen || $3 > maximum) {maximum=$3; seen=1}}
      END {if (operation == "mean" && count) printf "%.6f", sum/count;
        else if (operation == "maximum" && seen) printf "%.6f", maximum; else exit 1}' "$stats"; }
  gateway_mean="$(role_metric gateway mean)" || fail "$sample lacks gateway CPU samples"
  gateway_max="$(role_metric gateway maximum)"
  upstream_mean="$(role_metric upstream mean)" || fail "$sample lacks upstream CPU samples"
  upstream_max="$(role_metric upstream maximum)"
  loadgen_mean="$(role_metric load_generator mean)" || fail "$sample lacks load-generator CPU samples"
  loadgen_max="$(role_metric load_generator maximum)"
  gateway_capacity="$(awk -v cpu="$gateway_max" -v cores="$gateway_cores" 'BEGIN {printf "%.6f", cpu/cores}')"
  upstream_capacity="$(awk -v cpu="$upstream_max" -v cores="$upstream_cores" 'BEGIN {printf "%.6f", cpu/cores}')"
  loadgen_capacity="$(awk -v cpu="$loadgen_max" -v cores="$loadgen_cores" 'BEGIN {printf "%.6f", cpu/cores}')"
  restart_count="$(docker inspect --format '{{.RestartCount}}' "$gateway")"
  oom_killed="$(docker inspect --format '{{.State.OOMKilled}}' "$gateway")"
  docker logs "$gateway" >"$run_dir/results/$sample.gateway.log" 2>&1
  docker stop --timeout 30 "$gateway" >/dev/null
  exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
  docker rm "$gateway" >/dev/null
  gateway=''
  [ "$exit_code" -eq 0 ] || fail "$sample gateway exited $exit_code"
  snapshot_sha256="$http_snapshot_sha256"; [ "$protocol" != https ] || snapshot_sha256="$https_snapshot_sha256"
  plan_id="$(jq -r '.plan_id' "$run_dir/plan.json")"
  jq -n --arg plan_id "$plan_id" --arg protocol "$protocol" \
    --arg source_commit "$source_commit" --arg gateway_image_id "$gateway_image_id" \
    --arg snapshot_sha256 "$snapshot_sha256" --argjson order "$order" \
    --argjson payload_bytes "$payload_bytes" --argjson repetition "$repetition" \
    --argjson successful_responses "$successful" --argjson successful_rps "$successful_rps" \
    --argjson direct_upstream_rps "$direct_upstream_rps" \
    --argjson upstream_headroom_ratio "$upstream_headroom_ratio" \
    --argjson http_failures "$http_failures" --argjson transport_failures "$transport_failures" \
    --argjson p50 "$p50_ms" --argjson p95 "$p95_ms" --argjson p99 "$p99_ms" \
    --argjson p999 "$p999_ms" --argjson gateway_mean "$gateway_mean" \
    --argjson gateway_max "$gateway_max" --argjson upstream_mean "$upstream_mean" \
    --argjson upstream_max "$upstream_max" --argjson loadgen_mean "$loadgen_mean" \
    --argjson loadgen_max "$loadgen_max" --argjson gateway_capacity "$gateway_capacity" \
    --argjson upstream_capacity "$upstream_capacity" --argjson loadgen_capacity "$loadgen_capacity" \
    --argjson restart_count "$restart_count" --argjson oom_killed "$oom_killed" \
    --argjson exit_code "$exit_code" \
    '{schema_version: 1, plan_id: $plan_id, order: $order, protocol: $protocol,
      payload_bytes: $payload_bytes, repetition: $repetition,
      successful_responses: $successful_responses, successful_rps: $successful_rps,
      direct_upstream_rps: $direct_upstream_rps,
      upstream_headroom_ratio: $upstream_headroom_ratio,
      http_failures: $http_failures, transport_failures: $transport_failures, error_rate: 0,
      latency_ms: {p50: $p50, p95: $p95, p99: $p99, p999: $p999},
      cpu_percent: {gateway: {mean: $gateway_mean, maximum: $gateway_max},
        upstream: {mean: $upstream_mean, maximum: $upstream_max},
        load_generator: {mean: $loadgen_mean, maximum: $loadgen_max}},
      capacity_percent: {gateway: {maximum: $gateway_capacity},
        upstream: {maximum: $upstream_capacity},
        load_generator: {maximum: $loadgen_capacity}},
      identities: {source_commit: $source_commit, gateway_image_id: $gateway_image_id,
        snapshot_sha256: $snapshot_sha256},
      process: {restart_count: $restart_count, oom_killed: $oom_killed, exit_code: $exit_code},
      diagnostic: {cycles_per_request: null, instructions_per_request: null,
        writes_per_request: null, bytes_per_write: null, downstream_flush_wait_ms: null}}' \
    >"$run_dir/results/$sample.result.json"
  printf '  %.0f RPS, CPU %.1f%%, p99.9 %.3f ms\n' "$successful_rps" "$gateway_mean" "$p999_ms"
done <"$run_dir/plan.tsv"

git -C "$repo" status --short >"$run_dir/git-status-after.txt"
cmp -s "$run_dir/git-status-before.txt" "$run_dir/git-status-after.txt" || \
  fail 'source state changed during the experiment'
docker logs "$upstream" >"$run_dir/upstream.log" 2>&1
node "$script_dir/response-boundary.mjs" summarize --plan "$run_dir/plan.json" \
  --environment "$run_dir/environment.json" --results-dir "$run_dir/results" \
  --output "$run_dir/summary.json" --report "$run_dir/report.md"
(
  cd "$run_dir"
  checksum_manifest="$(mktemp "${TMPDIR:-/tmp}/bonvoyage-response-checksums.XXXXXX")"
  find . -type f ! -name checksums.sha256 | LC_ALL=C sort | while IFS= read -r file; do
    shasum -a 256 "$file"
  done >"$checksum_manifest"
  mv "$checksum_manifest" checksums.sha256
  shasum -a 256 -c checksums.sha256 >/dev/null
)
cat "$run_dir/report.md"
echo "RESULT_DIR=$run_dir"
