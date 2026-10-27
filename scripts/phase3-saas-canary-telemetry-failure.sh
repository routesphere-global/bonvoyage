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
prometheus_image="${BONVOYAGE_PROMETHEUS_IMAGE:-prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
fixture="$repo_root/tests/fixtures/phase3-saas-canary-telemetry-failure.yaml"
shards="${BONVOYAGE_SAAS_PROFILE_SHARDS:-2}"
release_requests="${BONVOYAGE_SAAS_PROFILE_RELEASE_REQUESTS:-256}"
outage_requests="${BONVOYAGE_SAAS_PROFILE_OUTAGE_REQUESTS:-128}"
slow_metric_connections="${BONVOYAGE_SAAS_PROFILE_SLOW_METRIC_CONNECTIONS:-24}"
slow_metric_hold_seconds="${BONVOYAGE_SAAS_PROFILE_SLOW_METRIC_HOLD_SECONDS:-8}"
rss_max_growth_bytes="${BONVOYAGE_SAAS_PROFILE_RSS_MAX_GROWTH_BYTES:-67108864}"
rss_max_growth_percent="${BONVOYAGE_SAAS_PROFILE_RSS_MAX_GROWTH_PERCENT:-25}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="saas-canary-telemetry-failure-$timestamp"
suffix="$$"
network="bonvoyage-saas-profile-$suffix"
volume="bonvoyage-saas-profile-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-saas-profile-gateway-$suffix"
loadgen="bonvoyage-saas-profile-loadgen-$suffix"
prometheus="bonvoyage-saas-profile-prometheus-$suffix"
tenant_a_stable="bonvoyage-saas-profile-a-stable-$suffix"
tenant_a_canary="bonvoyage-saas-profile-a-canary-$suffix"
tenant_b_stable="bonvoyage-saas-profile-b-stable-$suffix"
tenant_b_canary="bonvoyage-saas-profile-b-canary-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-saas-profile.XXXXXX")"
stage_dir="$work_dir/evidence"
secrets_dir="$work_dir/secrets"
output_root="${BONVOYAGE_SAAS_PROFILE_EVIDENCE_ROOT:-$repo_root/benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir" "$secrets_dir"

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
    capture_container "$loadgen" loadgen
    capture_container "$prometheus" prometheus
    capture_container "$tenant_a_stable" tenant-a-stable
    capture_container "$tenant_a_canary" tenant-a-canary
    capture_container "$tenant_b_stable" tenant-b-stable
    capture_container "$tenant_b_canary" tenant-b-canary
    if [ "$status" -ne 0 ]; then
      printf 'outcome=FAIL\nexit_code=%s\n' "$status" \
        >"$stage_dir/run-status.env"
      write_checksums >/dev/null 2>&1 || true
      printf 'SaaS canary profile failed; temporary evidence: %s\n' \
        "$stage_dir" >&2
      sed -n '1,240p' "$stage_dir/gateway.log" >&2 || true
      sed -n '1,160p' "$stage_dir/prometheus.log" >&2 || true
    fi
  fi
  docker rm --force "$gateway" "$loadgen" "$prometheus" \
    "$tenant_a_stable" "$tenant_a_canary" \
    "$tenant_b_stable" "$tenant_b_canary" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$secrets_dir" >/dev/null 2>&1 || {
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

for command_name in awk date docker find git grep mktemp node openssl python3 sed sort; do
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

positive_integer BONVOYAGE_SAAS_PROFILE_SHARDS "$shards"
[ "$shards" -ge 2 ] || fail "BONVOYAGE_SAAS_PROFILE_SHARDS must be at least 2"
positive_integer BONVOYAGE_SAAS_PROFILE_RELEASE_REQUESTS "$release_requests"
[ $((release_requests % 4)) -eq 0 ] \
  || fail "BONVOYAGE_SAAS_PROFILE_RELEASE_REQUESTS must contain complete 3:1 cycles"
positive_integer BONVOYAGE_SAAS_PROFILE_OUTAGE_REQUESTS "$outage_requests"
[ $((outage_requests % 4)) -eq 0 ] \
  || fail "BONVOYAGE_SAAS_PROFILE_OUTAGE_REQUESTS must contain complete 3:1 cycles"
positive_integer BONVOYAGE_SAAS_PROFILE_SLOW_METRIC_CONNECTIONS "$slow_metric_connections"
positive_integer BONVOYAGE_SAAS_PROFILE_SLOW_METRIC_HOLD_SECONDS "$slow_metric_hold_seconds"
positive_integer BONVOYAGE_SAAS_PROFILE_RSS_MAX_GROWTH_BYTES "$rss_max_growth_bytes"
nonnegative_integer BONVOYAGE_SAAS_PROFILE_RSS_MAX_GROWTH_PERCENT "$rss_max_growth_percent"
[ -f "$fixture" ] || fail "SaaS profile fixture is missing: $fixture"
[ -f "$script_dir/phase3-saas-canary-client.py" ] \
  || fail "SaaS profile client is missing"
[ -f "$script_dir/phase3-composite-hardening-upstream.py" ] \
  || fail "controlled upstream is missing"
case "$prometheus_image" in
  *@sha256:*) ;;
  *) fail "BONVOYAGE_PROMETHEUS_IMAGE must use an immutable sha256 digest" ;;
esac
[ ! -e "$output_dir" ] || fail "evidence directory already exists: $output_dir"

docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"
docker run --rm --platform "$platform" \
  --volume "$repo_root/observability/prometheus:/etc/prometheus:ro" \
  --workdir /etc/prometheus --entrypoint /bin/promtool \
  "$prometheus_image" check config /etc/prometheus/prometheus.yml \
  >"$stage_dir/promtool-config.txt" 2>&1 \
  || fail "Prometheus configuration or rule syntax validation failed"
docker run --rm --platform "$platform" \
  --volume "$repo_root/observability/prometheus:/etc/prometheus:ro" \
  --workdir /etc/prometheus/tests --entrypoint /bin/promtool \
  "$prometheus_image" test rules bonvoyage-rules.test.yml \
  >"$stage_dir/promtool-rules.txt" 2>&1 \
  || fail "Prometheus deterministic decision-rule tests failed"

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile . \
  >"$stage_dir/compiler-image-build.log" 2>&1 \
  || fail "snapshot compiler image build failed"
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream \
  >"$stage_dir/upstream-image-build.log" 2>&1 \
  || fail "controlled upstream image build failed"

dataplane_image_id="$(docker image inspect --format '{{.Id}}' "$image")" \
  || fail "dataplane image is unavailable: $image"
compiler_image_id="$(docker image inspect --format '{{.Id}}' "$compiler_image")"
upstream_image_id="$(docker image inspect --format '{{.Id}}' "$upstream_image")"
prometheus_image_id="$(docker image inspect --format '{{.Id}}' "$prometheus_image")"
docker image inspect "$dataplane_image_id" "$compiler_image_id" \
  "$upstream_image_id" "$prometheus_image_id" \
  >"$stage_dir/images.inspect.json"

tenant_a_key="$(openssl rand -hex 24)"
tenant_b_key="$(openssl rand -hex 24)"
printf '%s\n' "$tenant_a_key" >"$secrets_dir/tenant-a-api-keys.txt"
printf '%s\n' "$tenant_b_key" >"$secrets_dir/tenant-b-api-keys.txt"
chmod 600 "$secrets_dir"/*.txt

bv_stage_fixture_secrets "$secret_volume" "$secrets_dir" "$upstream_image_id" "$platform" \
  tenant-a-api-keys.txt tenant-b-api-keys.txt

docker network create --internal "$network" >/dev/null \
  || fail "could not create isolated Docker network"
docker volume create "$volume" >/dev/null \
  || fail "could not create snapshot volume"
docker run --rm --platform "$platform" --network none --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$fixture:/etc/bonvoyage/saas-profile.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" "$compiler_image_id" \
  -input /etc/bonvoyage/saas-profile.yaml \
  -output /var/lib/bonvoyage/snapshot.pb \
  >"$stage_dir/snapshot-compiler.log" 2>&1 \
  || fail "SaaS profile snapshot compilation failed"

docker run --detach --platform "$platform" --name "$loadgen" \
  --user "$(id -u):$(id -g)" \
  --network "$network" --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true --cap-drop ALL --entrypoint python \
  --volume "$script_dir/phase3-saas-canary-client.py:/saas-client.py:ro" \
  --volume "$secrets_dir:/secrets:ro" \
  "$upstream_image_id" -m http.server 18080 >/dev/null \
  || fail "could not start isolated load-generator container"

start_upstream() {
  container="$1"
  alias="$2"
  identity="$3"
  docker run --detach --platform "$platform" --name "$container" \
    --user "$(id -u):$(id -g)" \
    --network "$network" --network-alias "$alias" --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --security-opt no-new-privileges:true --cap-drop ALL --entrypoint python \
    --env "BONVOYAGE_UPSTREAM_ID=$identity" \
    --volume "$script_dir/phase3-composite-hardening-upstream.py:/controlled-upstream.py:ro" \
    "$upstream_image_id" /controlled-upstream.py >/dev/null \
    || fail "could not start controlled $identity upstream"
}

start_upstream "$tenant_a_stable" tenant-a-stable tenant-a-stable
start_upstream "$tenant_a_canary" tenant-a-canary tenant-a-canary
start_upstream "$tenant_b_stable" tenant-b-stable tenant-b-stable
start_upstream "$tenant_b_canary" tenant-b-canary tenant-b-canary

docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias bonvoyage --dns-search . --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
  "$dataplane_image_id" --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp "$shards" --memory 512M --overprovisioned \
  --logger-log-level bonvoyage-gateway=info >/dev/null \
  || fail "could not start multi-shard BonVoyage dataplane"

wait_for_url() {
  url="$1"
  label="$2"
  attempt=0
  until docker exec "$loadgen" python -c \
    'import sys, urllib.request; assert urllib.request.urlopen(sys.argv[1], timeout=1).status == 200' \
    "$url" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 40 ] || fail "$label did not become ready"
    sleep 1
  done
}

wait_for_url http://tenant-a-stable:8081/healthz "tenant A stable upstream"
wait_for_url http://tenant-a-canary:8081/healthz "tenant A canary upstream"
wait_for_url http://tenant-b-stable:8081/healthz "tenant B stable upstream"
wait_for_url http://tenant-b-canary:8081/healthz "tenant B canary upstream"
bv_wait_gateway_ready "$gateway" "$loadgen" http://bonvoyage:9901/health/ready

docker run --detach --platform "$platform" --name "$prometheus" \
  --network "$network" --network-alias prometheus --read-only \
  --tmpfs /prometheus:rw,noexec,nosuid,nodev,size=128m,mode=0777 \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$repo_root/observability/prometheus:/etc/prometheus:ro" \
  "$prometheus_image_id" \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/prometheus --storage.tsdb.retention.time=1h >/dev/null \
  || fail "could not start pinned Prometheus collector"

wait_for_prometheus() {
  attempt=0
  until docker exec "$loadgen" python -c '
import json
import urllib.parse
import urllib.request
query = urllib.parse.urlencode({"query": "up{job=\"bonvoyage\"}"})
result = json.load(urllib.request.urlopen(
    "http://prometheus:9090/api/v1/query?" + query, timeout=2
))["data"]["result"]
assert result and float(result[0]["value"][1]) == 1
' >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 50 ] || fail "Prometheus did not scrape BonVoyage"
    sleep 1
  done
}

wait_for_url http://prometheus:9090/-/ready "Prometheus collector"
wait_for_prometheus

capture_metrics() {
  destination="$1"
  docker exec "$loadgen" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1], timeout=5).read())
' http://bonvoyage:9090/metrics >"$destination"
}

measure_rss_kib() {
  docker top "$gateway" -eo pid,rss 2>/dev/null \
    | awk 'NR > 1 && $2 ~ /^[0-9]+$/ { total += $2; count += 1 }
      END { if (count == 0) exit 1; printf "%.0f\n", total }'
}

gateway_identity() {
  docker inspect --format \
    '{{.Id}}|{{.State.Pid}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.State.Running}}' \
    "$gateway"
}

run_batch() {
  output="$1"
  authority="$2"
  path="$3"
  key_file="$4"
  count="$5"
  concurrency="$6"
  profile="$7"
  path_profile="$8"
  docker exec "$loadgen" python /saas-client.py batch \
    --gateway bonvoyage --authority "$authority" --path "$path" \
    --key-file "$key_file" --count "$count" --concurrency "$concurrency" \
    --profile "$profile" --path-profile "$path_profile" \
    >"$stage_dir/$output" \
    || fail "SaaS workload failed: $output"
}

toggle_failure() {
  alias="$1"
  enabled="$2"
  docker exec "$loadgen" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(
    "http://" + sys.argv[1] + ":8081/control/failure?enabled=" + sys.argv[2],
    timeout=5,
).read())
' "$alias" "$enabled"
}

capture_stats() {
  alias="$1"
  destination="$2"
  docker exec "$loadgen" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(
    "http://" + sys.argv[1] + ":8081/stats", timeout=5
).read())
' "$alias" >"$stage_dir/$destination"
}

run_batch warmup-a.json tenant-a.saas.example.test /v1/data \
  /secrets/tenant-a-api-keys.txt 64 16 tenant_a release
run_batch warmup-b.json tenant-b.saas.example.test /v1/data \
  /secrets/tenant-b-api-keys.txt 64 16 tenant_b release
capture_metrics "$stage_dir/metrics-baseline.prom"
baseline_rss_kib="$(measure_rss_kib)" || fail "could not measure baseline RSS"
initial_identity="$(gateway_identity)"
printf 'initial=%s\n' "$initial_identity" >"$stage_dir/gateway-identities.txt"
docker exec "$loadgen" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1], timeout=5).read())
' http://bonvoyage:9901/config/active >"$stage_dir/active-snapshot.json"

docker exec "$loadgen" python /saas-client.py isolation \
  --gateway bonvoyage \
  --tenant-a-authority tenant-a.saas.example.test \
  --tenant-b-authority tenant-b.saas.example.test \
  --tenant-a-key-file /secrets/tenant-a-api-keys.txt \
  --tenant-b-key-file /secrets/tenant-b-api-keys.txt \
  >"$stage_dir/tenant-isolation.json" \
  || fail "tenant isolation matrix failed"

run_batch normal-a.json tenant-a.saas.example.test /v1/data \
  /secrets/tenant-a-api-keys.txt "$release_requests" 32 tenant_a release
run_batch normal-b.json tenant-b.saas.example.test /v1/data \
  /secrets/tenant-b-api-keys.txt "$release_requests" 32 tenant_b release
run_batch quota-a.json tenant-a.saas.example.test /v1/quota \
  /secrets/tenant-a-api-keys.txt 16 16 tenant_a quota

toggle_failure tenant-a-canary 1 >"$stage_dir/tenant-a-canary-failure-enabled.json"
run_batch degraded-a.json tenant-a.saas.example.test /v1/data \
  /secrets/tenant-a-api-keys.txt "$release_requests" 32 tenant_a release
run_batch unaffected-b.json tenant-b.saas.example.test /v1/data \
  /secrets/tenant-b-api-keys.txt "$release_requests" 32 tenant_b release
capture_stats tenant-a-stable tenant-a-stable-stats-degraded.json
capture_stats tenant-a-canary tenant-a-canary-stats-degraded.json
toggle_failure tenant-a-canary 0 >"$stage_dir/tenant-a-canary-failure-disabled.json"
sleep 3
run_batch canary-recovery-a.json tenant-a.saas.example.test /v1/data \
  /secrets/tenant-a-api-keys.txt "$release_requests" 32 tenant_a release
run_batch canary-recovery-b.json tenant-b.saas.example.test /v1/data \
  /secrets/tenant-b-api-keys.txt "$release_requests" 32 tenant_b release

run_batch overload-a.json tenant-a.saas.example.test /v1/slow \
  /secrets/tenant-a-api-keys.txt 32 32 tenant_a overload
run_batch overload-recovery-a.json tenant-a.saas.example.test /v1/data \
  /secrets/tenant-a-api-keys.txt 64 16 tenant_a release

attempt=0
until docker exec "$loadgen" python -c '
import json
import urllib.parse
import urllib.request
expressions = {
    "ready": "bonvoyage:gateway_ready:min",
    "requests": "bonvoyage:gateway_requests:rate5m",
    "success": "bonvoyage:gateway_success:ratio5m",
    "api_key_rejection": "max_over_time(bonvoyage:gateway_rejections:rate5m{reason=\"api_key_authentication\"}[5m])",
    "rate_limit_rejection": "max_over_time(bonvoyage:gateway_rejections:rate5m{reason=\"rate_limited\"}[5m])",
    "route_overload_rejection": "max_over_time(bonvoyage:gateway_rejections:rate5m{reason=\"route_overloaded\"}[5m])",
    "upstream_failure": "max_over_time(bonvoyage:gateway_resilience_events:rate5m{event=\"upstream_failure\"}[5m])",
}
output = {}
for name, expression in expressions.items():
    query = urllib.parse.urlencode({"query": expression})
    result = json.load(urllib.request.urlopen(
        "http://prometheus:9090/api/v1/query?" + query, timeout=2
    ))["data"]["result"]
    output[name] = max(
        (float(item["value"][1]) for item in result), default=0.0
    )
print(json.dumps(output, indent=2, sort_keys=True), flush=True)
if not all(value > 0 for value in output.values()):
    raise SystemExit(1)
' >"$stage_dir/prometheus-pre-outage-signals.json.tmp" 2>/dev/null; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 50 ] \
    || fail "Prometheus did not expose the pre-outage incident signals"
  sleep 1
done
mv "$stage_dir/prometheus-pre-outage-signals.json.tmp" \
  "$stage_dir/prometheus-pre-outage-signals.json"

capture_metrics "$stage_dir/metrics-before-collector-loss.prom"
printf 'collector_loss_started_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  >"$stage_dir/collector-outage-window.txt"
docker inspect "$prometheus" >"$stage_dir/prometheus-before-loss.inspect.json"
docker stop --time 5 "$prometheus" >/dev/null \
  || fail "could not stop Prometheus for the collector-loss stage"
docker inspect "$prometheus" >"$stage_dir/prometheus-during-loss.inspect.json"
run_batch collector-loss-a.json tenant-a.saas.example.test /v1/data \
  /secrets/tenant-a-api-keys.txt "$outage_requests" 32 tenant_a release
run_batch collector-loss-b.json tenant-b.saas.example.test /v1/data \
  /secrets/tenant-b-api-keys.txt "$outage_requests" 32 tenant_b release
capture_metrics "$stage_dir/metrics-during-collector-loss.prom"
printf 'during_collector_loss=%s\n' "$(gateway_identity)" \
  >>"$stage_dir/gateway-identities.txt"
docker start "$prometheus" >/dev/null \
  || fail "could not restart Prometheus after the collector-loss stage"
wait_for_url http://prometheus:9090/-/ready "restarted Prometheus collector"
wait_for_prometheus
printf 'collector_recovered_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  >>"$stage_dir/collector-outage-window.txt"
docker inspect "$prometheus" >"$stage_dir/prometheus-after-recovery.inspect.json"
printf 'after_collector_recovery=%s\n' "$(gateway_identity)" \
  >>"$stage_dir/gateway-identities.txt"

docker exec "$loadgen" python /saas-client.py slow-metrics \
  --gateway bonvoyage --connections "$slow_metric_connections" \
  --hold-seconds "$slow_metric_hold_seconds" \
  >"$stage_dir/slow-metrics-consumers.json" \
  2>"$stage_dir/slow-metrics-consumers.stderr" &
slow_metrics_pid="$!"
sleep 2
run_batch slow-metrics-a.json tenant-a.saas.example.test /v1/data \
  /secrets/tenant-a-api-keys.txt "$outage_requests" 32 tenant_a release
run_batch slow-metrics-b.json tenant-b.saas.example.test /v1/data \
  /secrets/tenant-b-api-keys.txt "$outage_requests" 32 tenant_b release
wait "$slow_metrics_pid" || fail "slow metrics-consumer stage failed"
printf 'after_slow_metrics=%s\n' "$(gateway_identity)" \
  >>"$stage_dir/gateway-identities.txt"

docker exec "$loadgen" python /saas-client.py privacy \
  --gateway bonvoyage --authority tenant-a.saas.example.test \
  >"$stage_dir/privacy-request.json" \
  || fail "privacy-canary request failed"
run_batch final-recovery-a.json tenant-a.saas.example.test /v1/data \
  /secrets/tenant-a-api-keys.txt "$release_requests" 32 tenant_a release
run_batch final-recovery-b.json tenant-b.saas.example.test /v1/data \
  /secrets/tenant-b-api-keys.txt "$release_requests" 32 tenant_b release

capture_stats tenant-a-stable tenant-a-stable-stats-final.json
capture_stats tenant-a-canary tenant-a-canary-stats-final.json
capture_stats tenant-b-stable tenant-b-stable-stats-final.json
capture_stats tenant-b-canary tenant-b-canary-stats-final.json
capture_metrics "$stage_dir/metrics-final.prom"
final_rss_kib="$(measure_rss_kib)" || fail "could not measure final RSS"
printf 'final=%s\n' "$(gateway_identity)" >>"$stage_dir/gateway-identities.txt"

attempt=0
until docker exec "$loadgen" python -c '
import json
import urllib.parse
import urllib.request
expressions = {
    "ready": "bonvoyage:gateway_ready:min",
    "requests": "bonvoyage:gateway_requests:rate5m",
    "success": "bonvoyage:gateway_success:ratio5m",
}
output = {}
for name, expression in expressions.items():
    query = urllib.parse.urlencode({"query": expression})
    result = json.load(urllib.request.urlopen(
        "http://prometheus:9090/api/v1/query?" + query, timeout=2
    ))["data"]["result"]
    output[name] = max(
        (float(item["value"][1]) for item in result), default=0.0
    )
for name, expression in {
    "rejections_present": "bonvoyage:gateway_rejections:rate5m",
    "resilience_present": "bonvoyage:gateway_resilience_events:rate5m",
}.items():
    query = urllib.parse.urlencode({"query": expression})
    result = json.load(urllib.request.urlopen(
        "http://prometheus:9090/api/v1/query?" + query, timeout=2
    ))["data"]["result"]
    output[name] = 1.0 if result else 0.0
print(json.dumps(output, indent=2, sort_keys=True), flush=True)
if not all(value > 0 for value in output.values()):
    raise SystemExit(1)
' >"$stage_dir/prometheus-recovery-signals.json.tmp" 2>/dev/null; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 50 ] \
    || fail "Prometheus decision rules did not recover with the profile signals"
  sleep 1
done
mv "$stage_dir/prometheus-recovery-signals.json.tmp" \
  "$stage_dir/prometheus-recovery-signals.json"

docker exec "$loadgen" python -c '
import json
import urllib.parse
import urllib.request

queries = {
    "gateway_5xx_ratio": "bonvoyage:gateway_5xx:ratio5m",
    "gateway_p999_microseconds": "bonvoyage:gateway_latency:p999_microseconds5m",
    "gateway_ready": "bonvoyage:gateway_ready:min",
    "gateway_rejections": "bonvoyage:gateway_rejections:rate5m",
    "gateway_request_rate": "bonvoyage:gateway_requests:rate5m",
    "gateway_resilience_events": "bonvoyage:gateway_resilience_events:rate5m",
    "gateway_shard_imbalance": "bonvoyage:gateway_shard_imbalance:ratio5m",
    "gateway_success_ratio": "bonvoyage:gateway_success:ratio5m",
    "memory_utilization": "bonvoyage:memory_utilization:ratio",
    "reactor_utilization": "bonvoyage:reactor_utilization:max",
    "snapshot_generation_mismatch": "bonvoyage:snapshot_generation:mismatch",
}
output = {}
for name, expression in queries.items():
    query = urllib.parse.urlencode({"query": expression})
    response = json.load(urllib.request.urlopen(
        "http://prometheus:9090/api/v1/query?" + query, timeout=5
    ))
    assert response["status"] == "success", (name, response)
    output[name] = [
        {
            "labels": item["metric"],
            "timestamp": float(item["value"][0]),
            "value": float(item["value"][1]),
        }
        for item in response["data"]["result"]
    ]
print(json.dumps(output, indent=2, sort_keys=True))
' >"$stage_dir/decision-series.json"
docker exec "$loadgen" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1], timeout=5).read())
' http://prometheus:9090/api/v1/rules >"$stage_dir/prometheus-rules-api.json"
docker exec "$loadgen" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1], timeout=5).read())
' http://prometheus:9090/api/v1/targets >"$stage_dir/prometheus-targets-api.json"

python3 - "$stage_dir" "$shards" "$release_requests" "$outage_requests" \
  "$slow_metric_connections" "$baseline_rss_kib" "$final_rss_kib" \
  "$rss_max_growth_bytes" "$rss_max_growth_percent" \
  >"$stage_dir/results-validation.txt" <<'PY'
import json
import re
import sys

(
    root,
    expected_shards,
    release_requests,
    outage_requests,
    slow_metric_connections,
    baseline_rss_kib,
    final_rss_kib,
    rss_max_growth_bytes,
    rss_max_growth_percent,
) = sys.argv[1:]
expected_shards = int(expected_shards)
release_requests = int(release_requests)
outage_requests = int(outage_requests)
slow_metric_connections = int(slow_metric_connections)
baseline_rss_kib = int(baseline_rss_kib)
final_rss_kib = int(final_rss_kib)
rss_max_growth_bytes = int(rss_max_growth_bytes)
rss_max_growth_percent = int(rss_max_growth_percent)


def load(name):
    with open(root + "/" + name, encoding="utf-8") as source:
        return json.load(source)


batch_names = [
    "normal-a.json",
    "normal-b.json",
    "quota-a.json",
    "degraded-a.json",
    "unaffected-b.json",
    "canary-recovery-a.json",
    "canary-recovery-b.json",
    "overload-a.json",
    "overload-recovery-a.json",
    "collector-loss-a.json",
    "collector-loss-b.json",
    "slow-metrics-a.json",
    "slow-metrics-b.json",
    "final-recovery-a.json",
    "final-recovery-b.json",
]


def require_complete(name):
    result = load(name)
    assert result["completed"] == result["requested"], (name, result)
    assert not result["errors"], (name, result)
    return result


def require_success(name):
    result = require_complete(name)
    assert result["statuses"] == {"200": result["requested"]}, (name, result)
    return result


def require_weighted(name, tenant, count):
    result = require_success(name)
    stable = int(result["upstreams"].get(f"{tenant}-stable", 0))
    canary = int(result["upstreams"].get(f"{tenant}-canary", 0))
    assert stable + canary == count, (name, result)
    assert stable == count * 3 // 4, (name, result)
    assert canary == count // 4, (name, result)
    return result


for name, tenant, count in (
    ("normal-a.json", "tenant-a", release_requests),
    ("normal-b.json", "tenant-b", release_requests),
    ("unaffected-b.json", "tenant-b", release_requests),
    ("canary-recovery-a.json", "tenant-a", release_requests),
    ("canary-recovery-b.json", "tenant-b", release_requests),
    ("collector-loss-a.json", "tenant-a", outage_requests),
    ("collector-loss-b.json", "tenant-b", outage_requests),
    ("slow-metrics-a.json", "tenant-a", outage_requests),
    ("slow-metrics-b.json", "tenant-b", outage_requests),
    ("final-recovery-a.json", "tenant-a", release_requests),
    ("final-recovery-b.json", "tenant-b", release_requests),
):
    require_weighted(name, tenant, count)

isolation = load("tenant-isolation.json")
for name, tenant in (
    ("tenant_a_valid", "tenant-a"),
    ("tenant_b_valid", "tenant-b"),
):
    assert isolation[name]["status"] == 200, isolation
    assert isolation[name]["upstream_profile"].startswith(tenant + "-"), isolation
for name in (
    "tenant_a_missing_key",
    "tenant_b_missing_key",
    "tenant_a_with_tenant_b_key",
    "tenant_b_with_tenant_a_key",
):
    assert isolation[name] == {"status": 401, "upstream_profile": ""}, isolation

degraded = require_complete("degraded-a.json")
degraded_successes = int(degraded["statuses"].get("200", 0))
degraded_failures = sum(
    int(value)
    for status, value in degraded["statuses"].items()
    if status in {"502", "503"}
)
assert set(degraded["statuses"]) <= {"200", "502", "503"}, degraded
assert degraded_successes == release_requests * 3 // 4, degraded
assert degraded_failures == release_requests // 4, degraded
assert degraded["upstreams"] == {"tenant-a-stable": degraded_successes}, degraded

quota = require_complete("quota-a.json")
quota_successes = int(quota["statuses"].get("200", 0))
quota_rejections = int(quota["statuses"].get("429", 0))
assert 1 <= quota_successes <= expected_shards, quota
assert quota_successes + quota_rejections == quota["requested"], quota
assert quota_rejections > 0, quota

overload = require_complete("overload-a.json")
overload_successes = int(overload["statuses"].get("200", 0))
overload_rejections = int(overload["statuses"].get("503", 0))
assert 2 <= overload_successes <= expected_shards * 2, overload
assert overload_successes + overload_rejections == overload["requested"], overload
assert overload_rejections > 0, overload
require_success("overload-recovery-a.json")

slow_metrics = load("slow-metrics-consumers.json")
assert slow_metrics["requested_connections"] == slow_metric_connections, slow_metrics
assert slow_metrics["established_connections"] == slow_metric_connections, slow_metrics
assert slow_metrics["bytes_read_per_connection"] == 0, slow_metrics
assert not slow_metrics["errors"], slow_metrics

privacy = load("privacy-request.json")
assert privacy == {
    "expected_local_rejection": True,
    "status": 404,
    "upstream_selected": False,
}, privacy

for name in (
    "tenant-a-stable-stats-final.json",
    "tenant-a-canary-stats-final.json",
    "tenant-b-stable-stats-final.json",
    "tenant-b-canary-stats-final.json",
):
    stats = load(name)
    assert stats["active"] == 0, (name, stats)
assert load("tenant-a-canary-stats-final.json")["forced_failures"] >= 1

with open(root + "/gateway-identities.txt", encoding="utf-8") as source:
    identities = [line.strip().split("=", 1)[1] for line in source if line.strip()]
assert len(identities) == 5, identities
assert len(set(identities)) == 1, identities
assert identities[0].endswith("|true") and "|0|" in identities[0], identities

rss_growth_kib = max(0, final_rss_kib - baseline_rss_kib)
rss_growth_bytes = rss_growth_kib * 1024
rss_growth_percent = (
    100.0 * rss_growth_kib / baseline_rss_kib if baseline_rss_kib else 0.0
)
assert (
    rss_growth_bytes <= rss_max_growth_bytes
    or rss_growth_percent <= rss_max_growth_percent
), (baseline_rss_kib, final_rss_kib, rss_growth_bytes, rss_growth_percent)

label_pattern = re.compile(r'(\w+)="((?:\\.|[^"\\])*)"')


def metric_values(path, metric_name):
    text = open(path, encoding="utf-8").read()
    values = {}
    for line in text.splitlines():
        if not line.startswith(metric_name + "{"):
            continue
        token, raw = line.split(None, 1)
        labels = dict(label_pattern.findall(token))
        assert set(labels) == {"shard"}, (metric_name, labels)
        values[int(labels["shard"])] = float(raw)
    assert set(values) == set(range(expected_shards)), (metric_name, values)
    return values


prefix = "bonvoyage_bonvoyage_gateway_"


def delta(metric):
    before = metric_values(root + "/metrics-baseline.prom", prefix + metric)
    after = metric_values(root + "/metrics-final.prom", prefix + metric)
    return int(sum(after.values()) - sum(before.values()))


batch_results = [load(name) for name in batch_names]
expected_requests = sum(result["requested"] for result in batch_results) + 7
expected_2xx = sum(int(result["statuses"].get("200", 0)) for result in batch_results) + 2
expected_4xx = quota_rejections + 5
expected_5xx = degraded_failures + overload_rejections
assert delta("requests_total") == expected_requests
assert delta("responses_2xx_total") == expected_2xx
assert delta("responses_4xx_total") == expected_4xx
assert delta("responses_5xx_total") == expected_5xx
assert delta("api_key_auth_rejections_total") == 4
assert delta("route_rate_limit_rejections_total") == quota_rejections
assert delta("route_overload_rejections_total") == overload_rejections
assert delta("route_misses_total") == 1
assert delta("upstream_failures_total") >= 1
assert delta("endpoint_circuit_opens_total") >= 1

final_metrics = open(root + "/metrics-final.prom", encoding="utf-8").read()
for line in final_metrics.splitlines():
    if not line.startswith(prefix) or line.startswith("#"):
        continue
    token = line.split(None, 1)[0]
    labels = dict(label_pattern.findall(token))
    permitted = {"shard", "le"} if token.split("{", 1)[0].endswith("_bucket") else {"shard"}
    assert set(labels) == permitted, (token, labels)

for suffix, expected in {
    "telemetry_contract_version": 3,
    "ready": 1,
    "snapshot_generation": 41,
    "configured_listeners": 1,
    "configured_routes": 4,
    "configured_clusters": 4,
    "configured_endpoints": 4,
}.items():
    values = metric_values(root + "/metrics-final.prom", prefix + suffix)
    assert all(value == expected for value in values.values()), (suffix, values)

active_snapshot = load("active-snapshot.json")
assert active_snapshot == {
    "snapshot_id": "phase3-saas-canary-telemetry-failure",
    "generation": 41,
}, active_snapshot

decisions = load("decision-series.json")
for name, values in decisions.items():
    assert values, f"decision series is empty: {name}"
assert min(item["value"] for item in decisions["gateway_ready"]) == 1
assert max(item["value"] for item in decisions["snapshot_generation_mismatch"]) == 0
assert max(item["value"] for item in decisions["gateway_request_rate"]) > 0
pre_outage_signals = load("prometheus-pre-outage-signals.json")
assert set(pre_outage_signals) == {
    "api_key_rejection",
    "rate_limit_rejection",
    "ready",
    "requests",
    "route_overload_rejection",
    "success",
    "upstream_failure",
}, pre_outage_signals
assert all(value > 0 for value in pre_outage_signals.values()), pre_outage_signals
recovery_signals = load("prometheus-recovery-signals.json")
assert set(recovery_signals) == {
    "ready",
    "rejections_present",
    "requests",
    "resilience_present",
    "success",
}, recovery_signals
assert all(value > 0 for value in recovery_signals.values()), recovery_signals

persona_summary = {
    "scope": {
        "evidence_class": "bounded_local_engineering",
        "billing_grade": False,
        "marketing_claim_authorized": False,
        "workload": "synthetic_multi_tenant_saas_canary",
    },
    "outcomes": {
        "total_profile_requests": expected_requests,
        "successful_responses": expected_2xx,
        "client_error_responses": expected_4xx,
        "gateway_error_responses": expected_5xx,
        "tenant_isolation_rejections": 4,
        "quota_rejections": quota_rejections,
        "overload_rejections": overload_rejections,
        "canary_failure_impacted_only_selected_tenant": True,
        "collector_loss_healthy_responses": outage_requests * 2,
        "slow_consumer_healthy_responses": outage_requests * 2,
        "recovery_without_gateway_restart": True,
    },
    "audiences": {
        "infrastructure_engineer": {
            "decision": "traffic remained available through collector loss and slow metrics consumers; no gateway restart was required",
            "signals": ["readiness", "tail_latency", "rejection_reason", "reactor", "memory", "shard_balance"],
        },
        "systems_expert": {
            "decision": "tenant policy, weighted selection, circuit isolation, overload bounds, and recovery matched the static snapshot contract",
            "signals": ["configured_scale", "upstream_failure", "circuit_open", "request_distribution", "rss_growth"],
        },
        "sales": {
            "decision": "the local synthetic profile demonstrates protected multi-tenant routing and bounded recovery, but does not authorize a production or performance claim",
            "signals": ["successful_volume", "service_quality", "protocol_adoption", "claim_scope"],
        },
        "business_analyst": {
            "decision": "successful demand, client-policy rejection, gateway-failure, and recovery outcomes are distinguishable without tenant-derived metric labels",
            "signals": ["response_outcomes", "policy_rejection_mix", "payload_volume", "protocol_adoption"],
        },
        "ceo": {
            "decision": "service outcome and resilience evidence is visible while billing, SLO, capacity, and marketing conclusions remain gated",
            "signals": ["successful_volume", "success_ratio", "gateway_error_ratio", "rollout_integrity"],
        },
        "cto": {
            "decision": "the share-nothing dataplane stayed alive and observable across tenant failure, overload, collector loss, and recovery with bounded labels",
            "signals": ["tail_latency", "resource_saturation", "failure_boundary", "snapshot_integrity", "privacy_contract"],
        },
    },
    "resources": {
        "baseline_rss_kib": baseline_rss_kib,
        "final_rss_kib": final_rss_kib,
        "rss_growth_bytes": rss_growth_bytes,
        "rss_growth_percent": round(rss_growth_percent, 3),
    },
}
with open(root + "/persona-decision-summary.json", "w", encoding="utf-8") as destination:
    json.dump(persona_summary, destination, indent=2, sort_keys=True)
    destination.write("\n")

print("two-tenant canary, failure isolation, overload, collector loss, slow-consumer, privacy, and recovery checks passed")
print(f"profile_requests={expected_requests} successful={expected_2xx} client_errors={expected_4xx} gateway_errors={expected_5xx}")
print(f"rss_baseline_kib={baseline_rss_kib} rss_final_kib={final_rss_kib} rss_growth_percent={rss_growth_percent:.3f}")
PY

capture_container "$gateway" gateway
capture_container "$loadgen" loadgen
capture_container "$prometheus" prometheus
capture_container "$tenant_a_stable" tenant-a-stable
capture_container "$tenant_a_canary" tenant-a-canary
capture_container "$tenant_b_stable" tenant-b-stable
capture_container "$tenant_b_canary" tenant-b-canary

for marker in \
  tenant-a.saas.example.test \
  tenant-b.saas.example.test \
  privacy-path-marker-bv-saas \
  privacy-query-marker-bv-saas \
  privacy-bearer-marker-bv-saas \
  privacy-cookie-marker-bv-saas \
  privacy-header-marker-bv-saas \
  privacy-tenant-marker-bv-saas \
  203.0.113.219; do
  if grep -F "$marker" "$stage_dir/metrics-final.prom" \
    "$stage_dir/gateway.log" "$stage_dir/decision-series.json" \
    "$stage_dir/prometheus-rules-api.json" >/dev/null 2>&1; then
    fail "forbidden request-derived value escaped into gateway telemetry"
  fi
done
for secret_value in "$tenant_a_key" "$tenant_b_key"; do
  if grep -F "$secret_value" "$stage_dir/metrics-final.prom" \
    "$stage_dir/gateway.log" "$stage_dir/decision-series.json" \
    "$stage_dir/prometheus-rules-api.json" >/dev/null 2>&1; then
    fail "an ephemeral credential escaped into gateway telemetry"
  fi
done
printf '%s\n' \
  'PASS: synthetic tenant hosts, paths, query, client IP, credentials, cookie, and header markers were absent from gateway telemetry.' \
  >"$stage_dir/privacy-validation.txt"

source_commit="$(git rev-parse HEAD)"
if [ -z "$(git status --porcelain)" ]; then source_dirty=false; else source_dirty=true; fi
cat >"$stage_dir/metadata.txt" <<EOF
captured_at_utc=$timestamp
run_id=$run_id
source_commit=$source_commit
source_dirty=$source_dirty
platform=$platform
gateway_shards=$shards
snapshot_generation=41
release_requests_per_stage=$release_requests
collector_loss_requests_per_tenant=$outage_requests
slow_metric_connections=$slow_metric_connections
slow_metric_hold_seconds=$slow_metric_hold_seconds
dataplane_image_id=$dataplane_image_id
compiler_image_id=$compiler_image_id
upstream_image_id=$upstream_image_id
prometheus_image=$prometheus_image
prometheus_image_id=$prometheus_image_id
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
billing_grade=false
EOF

python3 - "$stage_dir" >"$stage_dir/summary.txt" <<'PY'
import json
import sys

root = sys.argv[1]
with open(root + "/persona-decision-summary.json", encoding="utf-8") as source:
    summary = json.load(source)
outcomes = summary["outcomes"]
resources = summary["resources"]
print("outcome: PASS")
print("scope: bounded local Phase 3 multi-tenant SaaS canary under telemetry failure")
for name, value in outcomes.items():
    print(f"{name}: {str(value).lower() if isinstance(value, bool) else value}")
print(f"rss_baseline_kib: {resources['baseline_rss_kib']}")
print(f"rss_final_kib: {resources['final_rss_kib']}")
print(f"rss_growth_percent: {resources['rss_growth_percent']}")
print("request_derived_metric_labels: none")
print("billing_grade: false")
print("claim_limit: synthetic local functional and resilience evidence; not a performance, capacity, SLO, billing, production, or marketing qualification")
PY

cat >"$stage_dir/README.md" <<EOF
# Phase 3 SaaS canary and telemetry-failure evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This record does not authorize
performance, capacity, SLO, billing, production-readiness, competitive, customer,
or marketing claims.

One unchanged ${shards}-shard BonVoyage process served two synthetic tenants with
separate API keys and upstream pools. The profile exercised static 75/25 canary
traffic, cross-tenant credential rejection, local quota, route overload, one-
tenant canary failure, unaffected-tenant continuation, collector loss, slow
metrics consumers, privacy canaries, and recovery without a gateway restart.

The persona decision summary translates the same bounded operational evidence
for infrastructure, systems, sales, business-analysis, CEO, and CTO decisions.
It deliberately preserves claim boundaries: Prometheus is not a billing ledger,
the synthetic workload is not customer evidence, and dedicated performance,
dynamic rollout, multi-hour hardening, route-scale, and access-log or tracing
backpressure remain open.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
Makefile
observability/decision-audiences.yaml
observability/grafana/dashboards/bonvoyage-decision-console.json
observability/telemetry-contract.yaml
scripts/phase3-composite-hardening-upstream.py
scripts/phase3-saas-canary-client.py
scripts/phase3-saas-canary-telemetry-failure.sh
scripts/test-fixture-secrets.sh
tests/fixtures/phase3-saas-canary-telemetry-failure.yaml
website/scripts/validate-project.cjs
EOF
while IFS= read -r source_file; do
  if [ "$checksum_tool" = sha256sum ]; then
    sha256sum "$source_file"
  else
    shasum -a 256 "$source_file"
  fi
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"
printf 'outcome=PASS\nexit_code=0\n' >"$stage_dir/run-status.env"
write_checksums || fail "could not create SaaS profile evidence manifest"

mkdir -p "$output_root"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-saas-canary-telemetry-failure.txt.tmp"
mv "$output_root/current-saas-canary-telemetry-failure.txt.tmp" \
  "$output_root/current-saas-canary-telemetry-failure.txt"

printf 'SaaS canary telemetry-failure profile passed: %s\n' "$output_dir"
cat "$output_dir/results-validation.txt"
cat "$output_dir/summary.txt"
