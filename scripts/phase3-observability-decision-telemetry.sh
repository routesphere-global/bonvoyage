#!/bin/sh
set -eu

umask 077

script_dir="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
repo_root="$(CDPATH='' cd "$script_dir/.." && pwd)"
cd "$repo_root"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
prometheus_image="${BONVOYAGE_PROMETHEUS_IMAGE:-prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
fixture="$repo_root/tests/fixtures/phase3-observability-decision-telemetry.yaml"
shards="${BONVOYAGE_OBSERVABILITY_SHARDS:-2}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="observability-decision-$timestamp"
suffix="$$"
network="bonvoyage-observability-$suffix"
volume="bonvoyage-observability-snapshot-$suffix"
gateway="bonvoyage-observability-gateway-$suffix"
upstream="bonvoyage-observability-upstream-$suffix"
prometheus="bonvoyage-observability-prometheus-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-observability.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_OBSERVABILITY_EVIDENCE_ROOT:-$repo_root/benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"

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
    capture_container "$upstream" upstream
    capture_container "$prometheus" prometheus
    if [ "$status" -ne 0 ]; then
      printf 'outcome=FAIL\nexit_code=%s\n' "$status" \
        >"$stage_dir/run-status.env"
      write_checksums >/dev/null 2>&1 || true
      printf 'Observability decision telemetry failed; temporary evidence: %s\n' \
        "$stage_dir" >&2
      sed -n '1,240p' "$stage_dir/gateway.log" >&2 || true
      sed -n '1,160p' "$stage_dir/prometheus.log" >&2 || true
    fi
  fi
  docker rm --force "$gateway" "$upstream" "$prometheus" \
    >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  if [ "$status" -eq 0 ]; then
    rm -rf "$work_dir"
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command_name in date docker find git grep mktemp node python3 sed sort; do
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

case "$shards" in
  ''|*[!0-9]*) fail "BONVOYAGE_OBSERVABILITY_SHARDS must be an integer" ;;
esac
[ "$shards" -ge 2 ] \
  || fail "BONVOYAGE_OBSERVABILITY_SHARDS must be at least 2"
[ -f "$fixture" ] || fail "observability fixture is missing: $fixture"
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

docker network create --internal "$network" >/dev/null \
  || fail "could not create isolated Docker network"
docker volume create "$volume" >/dev/null \
  || fail "could not create snapshot volume"
docker run --rm --platform "$platform" --network none --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$fixture:/etc/bonvoyage/observability.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" "$compiler_image_id" \
  -input /etc/bonvoyage/observability.yaml \
  -output /var/lib/bonvoyage/snapshot.pb \
  >"$stage_dir/snapshot-compiler.log" 2>&1 \
  || fail "observability snapshot compilation failed"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --env BONVOYAGE_UPSTREAM_ID=decision-upstream \
  "$upstream_image_id" >/dev/null \
  || fail "could not start controlled upstream"
docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias bonvoyage --dns-search . --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$volume:/snapshot:ro" "$dataplane_image_id" \
  --snapshot /snapshot/snapshot.pb \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp "$shards" --memory 384M --overprovisioned \
  --runtime-log-transport stderr-pipe \
  --logger-log-level bonvoyage-gateway=info >/dev/null \
  || fail "could not start multi-shard BonVoyage dataplane"

wait_for_url() {
  url="$1"
  label="$2"
  attempt=0
  until docker exec "$upstream" python -c \
    'import sys, urllib.request; assert urllib.request.urlopen(sys.argv[1], timeout=1).status == 200' \
    "$url" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 40 ] || fail "$label did not become ready"
    sleep 1
  done
}

wait_for_url http://upstream:8081/healthz "controlled upstream"
wait_for_url http://bonvoyage:9901/health/ready "BonVoyage gateway"

docker exec "$upstream" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1], timeout=5).read())
' http://bonvoyage:9901/config/active >"$stage_dir/active-snapshot.json"
docker exec "$upstream" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1], timeout=5).read())
' http://bonvoyage:9090/metrics >"$stage_dir/metrics-baseline.prom"

docker run --detach --platform "$platform" --name "$prometheus" \
  --network "$network" --network-alias prometheus --read-only \
  --tmpfs /prometheus:rw,noexec,nosuid,nodev,size=128m,mode=0777 \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$repo_root/observability/prometheus:/etc/prometheus:ro" \
  "$prometheus_image_id" \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/prometheus \
  --storage.tsdb.retention.time=1h >/dev/null \
  || fail "could not start pinned Prometheus collector"
wait_for_url http://prometheus:9090/-/ready "Prometheus collector"

attempt=0
until docker exec "$upstream" python -c '
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
  [ "$attempt" -lt 40 ] || fail "Prometheus did not scrape BonVoyage"
  sleep 1
done

docker exec "$upstream" python -c '
import concurrent.futures
import json
import urllib.error
import urllib.request

gateway = "http://bonvoyage:8080"
headers = {
    "Host": "telemetry.example.test",
    "Authorization": "Bearer telemetry-secret-do-not-export",
    "Cookie": "telemetry-session-do-not-export",
    "X-Decision-Needle": "telemetry-header-do-not-export",
    "X-Forwarded-For": "203.0.113.77",
}

def request(path):
    value = urllib.request.Request(gateway + path, headers=headers)
    try:
        with urllib.request.urlopen(value, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code

def concurrent_requests(path, count, workers):
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda _: request(path), range(count)))

success = concurrent_requests("/decision/success", 64, 16)
rate = concurrent_requests("/decision/rate", 32, 32)
missing = concurrent_requests(
    "/private-needle-bv-telemetry?customer=telemetry-query-do-not-export",
    8,
    8,
)
failure = concurrent_requests("/decision/failure", 8, 4)

def distribution(values):
    return {
        str(status): values.count(status) for status in sorted(set(values))
    }

assert distribution(success) == {"200": 64}, distribution(success)
assert set(rate) <= {200, 429} and 429 in rate and 200 in rate, distribution(rate)
assert distribution(missing) == {"404": 8}, distribution(missing)
assert distribution(failure) == {"502": 8}, distribution(failure)
print(json.dumps({
    "failure": distribution(failure),
    "missing": distribution(missing),
    "rate_limit": distribution(rate),
    "success": distribution(success),
}, indent=2, sort_keys=True))
' >"$stage_dir/workload-results.json" \
  || fail "decision telemetry workload failed"

attempt=0
until docker exec "$upstream" python -c '
import json
import urllib.parse
import urllib.request
expressions = (
    ("bonvoyage:gateway_5xx:ratio5m", False),
    ("bonvoyage:gateway_latency:p999_microseconds5m", False),
    ("bonvoyage:gateway_ready:min", False),
    ("bonvoyage:gateway_rejections:rate5m{reason=\"rate_limited\"}", True),
    ("bonvoyage:gateway_requests:rate5m", True),
    ("bonvoyage:gateway_shard_imbalance:ratio5m", False),
    ("bonvoyage:gateway_connections_accepted_per_shard:rate5m", True),
    ("bonvoyage:gateway_connection_shard_imbalance:ratio5m", False),
    ("bonvoyage:gateway_success:ratio5m", False),
    ("bonvoyage:memory_utilization:ratio", False),
    ("bonvoyage:snapshot_generation:mismatch", False),
    ("bonvoyage:upstream_http1_pool_pressure:max", False),
    ("bonvoyage:upstream_http1_pool_waits:rate5m", False),
)
for expression, require_positive in expressions:
    query = urllib.parse.urlencode({"query": expression})
    result = json.load(urllib.request.urlopen(
        "http://prometheus:9090/api/v1/query?" + query, timeout=2
    ))["data"]["result"]
    assert result, expression
    if require_positive:
        assert max(float(item["value"][1]) for item in result) > 0, expression
' >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 40 ] \
    || fail "Prometheus decision recording rules did not produce live traffic series"
  sleep 1
done

docker exec "$upstream" python -c '
import json
import urllib.parse
import urllib.request

queries = {
    "gateway_5xx_ratio": "bonvoyage:gateway_5xx:ratio5m",
    "gateway_p999_microseconds": "bonvoyage:gateway_latency:p999_microseconds5m",
    "gateway_ready": "bonvoyage:gateway_ready:min",
    "gateway_rejections": "bonvoyage:gateway_rejections:rate5m",
    "gateway_request_rate": "bonvoyage:gateway_requests:rate5m",
    "gateway_shard_imbalance": "bonvoyage:gateway_shard_imbalance:ratio5m",
    "gateway_connection_rate": "bonvoyage:gateway_connections_accepted_per_shard:rate5m",
    "gateway_connection_shard_imbalance": "bonvoyage:gateway_connection_shard_imbalance:ratio5m",
    "gateway_success_ratio": "bonvoyage:gateway_success:ratio5m",
    "memory_utilization": "bonvoyage:memory_utilization:ratio",
    "snapshot_generation_mismatch": "bonvoyage:snapshot_generation:mismatch",
    "upstream_http1_pool_pressure": "bonvoyage:upstream_http1_pool_pressure:max",
    "upstream_http1_pool_wait_rate": "bonvoyage:upstream_http1_pool_waits:rate5m",
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
docker exec "$upstream" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1], timeout=5).read())
' http://prometheus:9090/api/v1/rules >"$stage_dir/prometheus-rules-api.json"
docker exec "$upstream" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1], timeout=5).read())
' http://prometheus:9090/api/v1/status/buildinfo \
  >"$stage_dir/prometheus-build-info.json"
docker exec "$upstream" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1], timeout=5).read())
' http://bonvoyage:9090/metrics >"$stage_dir/metrics-final.prom"

python3 - "$stage_dir" "$shards" >"$stage_dir/metrics-validation.txt" <<'PY'
import json
import math
import re
import sys

root, expected_shards = sys.argv[1:]
expected_shards = int(expected_shards)
expected_shard_ids = set(range(expected_shards))
prefix = "bonvoyage_bonvoyage_gateway_"

with open(root + "/metrics-final.prom", encoding="utf-8") as source:
    metrics_text = source.read()
with open(root + "/workload-results.json", encoding="utf-8") as source:
    workload = json.load(source)
with open(root + "/decision-series.json", encoding="utf-8") as source:
    decisions = json.load(source)
with open(root + "/active-snapshot.json", encoding="utf-8") as source:
    active_snapshot = json.load(source)

label_pattern = re.compile(r'(\w+)="((?:\\.|[^"\\])*)"')


def samples(metric_name):
    result = []
    for line in metrics_text.splitlines():
        if not line.startswith(metric_name):
            continue
        token, raw = line.split(None, 1)
        if token != metric_name and not token.startswith(metric_name + "{"):
            continue
        labels = dict(label_pattern.findall(token))
        result.append((labels, float(raw)))
    return result


def by_shard(metric_name):
    values = {}
    for labels, value in samples(metric_name):
        assert "shard" in labels, (metric_name, labels)
        shard = int(labels["shard"])
        values[shard] = values.get(shard, 0.0) + value
    assert set(values) == expected_shard_ids, (metric_name, values)
    return values


def total(metric_name):
    return sum(by_shard(metric_name).values())


def distribution_total(name, status):
    return int(workload[name].get(str(status), 0))


for line in metrics_text.splitlines():
    if not line.startswith(prefix) or line.startswith("#"):
        continue
    token = line.split(None, 1)[0]
    labels = dict(label_pattern.findall(token))
    metric_name = token.split("{", 1)[0]
    permitted = {"shard", "le"} if metric_name.endswith("_bucket") else {"shard"}
    assert set(labels) == permitted, (metric_name, labels)

expected_gauges = {
    "telemetry_contract_version": 3,
    "ready": 1,
    "snapshot_generation": 37,
    "configured_listeners": 1,
    "configured_routes": 3,
    "configured_clusters": 1,
    "configured_endpoints": 1,
}
for suffix, expected in expected_gauges.items():
    values = by_shard(prefix + suffix)
    assert all(value == expected for value in values.values()), (suffix, values)

assert active_snapshot == {
    "snapshot_id": "phase3-observability-decision-telemetry",
    "generation": 37,
}, active_snapshot

success_2xx = distribution_total("success", 200)
rate_2xx = distribution_total("rate_limit", 200)
rate_429 = distribution_total("rate_limit", 429)
missing_404 = distribution_total("missing", 404)
failure_502 = distribution_total("failure", 502)
expected_requests = success_2xx + rate_2xx + rate_429 + missing_404 + failure_502

requests_by_shard = by_shard(prefix + "requests_total")
assert all(value > 0 for value in requests_by_shard.values()), requests_by_shard
assert sum(requests_by_shard.values()) == expected_requests, requests_by_shard
connections_by_shard = by_shard(prefix + "downstream_connections_accepted_total")
assert all(value > 0 for value in connections_by_shard.values()), connections_by_shard
assert total(prefix + "upstream_http1_pool_waits_total") >= 0
assert total(prefix + "active_upstream_http1_requests") == 0
assert all(value > 0 for value in by_shard(
    prefix + "configured_upstream_http1_connections").values())
assert total(prefix + "responses_2xx_total") == success_2xx + rate_2xx
assert total(prefix + "responses_4xx_total") == rate_429 + missing_404
assert total(prefix + "responses_5xx_total") == failure_502
assert total(prefix + "route_misses_total") == missing_404
assert total(prefix + "route_rate_limit_rejections_total") == rate_429
assert total(prefix + "upstream_failures_total") >= failure_502

histogram_name = prefix + "request_latency_microseconds_bucket"
positive_infinity = [
    (labels, value) for labels, value in samples(histogram_name)
    if labels.get("le") == "+Inf"
]
legacy_infinity = [
    (labels, value) for labels, value in samples(histogram_name)
    if labels.get("le") == "inf"
]
assert len(positive_infinity) == expected_shards, positive_infinity
assert not legacy_infinity, legacy_infinity
assert total(prefix + "request_latency_microseconds_count") == expected_requests

for name, series in decisions.items():
    assert series, f"decision series is empty: {name}"
assert min(item["value"] for item in decisions["gateway_ready"]) == 1
assert max(item["value"] for item in decisions["snapshot_generation_mismatch"]) == 0
assert max(item["value"] for item in decisions["gateway_request_rate"]) > 0
assert max(item["value"] for item in decisions["gateway_connection_rate"]) > 0
success_ratio = max(item["value"] for item in decisions["gateway_success_ratio"])
gateway_5xx_ratio = max(item["value"] for item in decisions["gateway_5xx_ratio"])
assert 0 < success_ratio < 1, success_ratio
assert 0 < gateway_5xx_ratio < 1, gateway_5xx_ratio

request_total = sum(requests_by_shard.values())
request_share = {
    str(shard): value / request_total
    for shard, value in sorted(requests_by_shard.items())
}
summary = {
    "business": {
        "client_error_responses": rate_429 + missing_404,
        "gateway_error_responses": failure_502,
        "policy_rejections": {"rate_limited": rate_429},
        "successful_responses": success_2xx + rate_2xx,
        "total_requests": int(request_total),
        "use_for_billing": False,
    },
    "infrastructure": {
        "all_shards_ready": True,
        "configured_scale": {
            "clusters": 1,
            "endpoints": 1,
            "listeners": 1,
            "routes": 3,
        },
        "gateway_5xx_ratio_live_rule": gateway_5xx_ratio,
        "gateway_success_ratio_live_rule": success_ratio,
        "request_share_by_shard": request_share,
        "snapshot_generation": 37,
        "snapshot_generation_mismatch": 0,
    },
    "privacy": {
        "native_metric_labels": ["le", "shard"],
        "request_derived_labels_present": False,
    },
    "telemetry": {
        "contract_version": 1,
        "live_decision_series": sorted(decisions),
        "prometheus_target_scraped": True,
    },
}
with open(root + "/decision-summary.json", "w", encoding="utf-8") as destination:
    json.dump(summary, destination, indent=2, sort_keys=True)
    destination.write("\n")
print("two-shard metrics, outcomes, bounded labels, canonical histogram, and live decision series passed")
PY

capture_container "$gateway" gateway
initial_identity="$(docker inspect --format \
  '{{.Id}}|{{.State.Pid}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.State.Running}}' \
  "$gateway")"
printf 'before_shutdown=%s\n' "$initial_identity" \
  >"$stage_dir/gateway-identities.txt"
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
capture_container "$upstream" upstream
capture_container "$prometheus" prometheus

grep -F 'event=dataplane_ready' "$stage_dir/gateway.log" \
  | grep -F "shards=$shards" \
  | grep -F 'snapshot_id=phase3-observability-decision-telemetry' \
  | grep -F 'snapshot_generation=37' \
  >"$stage_dir/lifecycle-events.txt" \
  || fail "structured dataplane_ready event is incomplete"
grep -F 'event=dataplane_stopped' "$stage_dir/gateway.log" \
  | grep -F 'outcome=clean' >>"$stage_dir/lifecycle-events.txt" \
  || fail "structured dataplane_stopped event is incomplete"

for marker in \
  telemetry.example.test \
  private-needle-bv-telemetry \
  telemetry-query-do-not-export \
  telemetry-secret-do-not-export \
  telemetry-session-do-not-export \
  telemetry-header-do-not-export \
  203.0.113.77; do
  if grep -F "$marker" "$stage_dir/metrics-final.prom" \
    "$stage_dir/gateway.log" "$stage_dir/decision-series.json" \
    >/dev/null 2>&1; then
    fail "forbidden request-derived value escaped into telemetry: $marker"
  fi
done
printf '%s\n' \
  'PASS: request path, query, authority, client IP, credential, cookie, and header markers were absent from gateway telemetry.' \
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
telemetry_contract_version=3
snapshot_generation=37
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
with open(root + "/decision-summary.json", encoding="utf-8") as source:
    summary = json.load(source)
business = summary["business"]
infrastructure = summary["infrastructure"]
print("outcome: PASS")
print("scope: bounded local Phase 3 decision-telemetry qualification")
print(f"requests_observed: {business['total_requests']}")
print(f"successful_responses: {business['successful_responses']}")
print(f"client_error_responses: {business['client_error_responses']}")
print(f"gateway_error_responses: {business['gateway_error_responses']}")
print(f"rate_limit_rejections: {business['policy_rejections']['rate_limited']}")
print(f"request_share_by_shard: {infrastructure['request_share_by_shard']}")
print("all_shards_ready: true")
print("snapshot_generation_mismatch: 0")
print("prometheus_target_scraped: true")
print("recording_rules_live: true")
print("request_derived_metric_labels: none")
print("forbidden_request_values_in_gateway_telemetry: none")
print("billing_grade: false")
print("claim_limit: local functional telemetry evidence; not a performance, capacity, SLO, billing, or marketing qualification")
PY

cat >"$stage_dir/README.md" <<EOF
# Phase 3 decision telemetry evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This record does not authorize
performance, capacity, SLO, billing, competitive, customer-facing, or marketing
claims.

The ${shards}-shard BonVoyage dataplane served snapshot generation 37 while a
pinned Prometheus 3.14.0 collector scraped the native endpoint and evaluated the
checked-in recording and alert rules. The workload exercised successful proxy
responses, shard-local rate-limit rejection, route miss, and upstream failure.
The retained raw metrics, live decision series, rule API, workload outcomes,
image identities, lifecycle events, and checksums allow the result to be
reproduced and audited.

Native gateway labels were limited to shard and histogram le. Deliberate
request path, query, authority, client IP, credential, cookie, and header
markers did not appear in gateway metrics, lifecycle logs, or derived decision
series. Prometheus counters remain resettable operational telemetry and must
not be used as a billing ledger.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
.github/workflows/ci.yml
Makefile
dataplane/src/gateway.cc
dataplane/src/main.cc
observability/grafana/dashboards/bonvoyage-decision-console.json
observability/grafana/provisioning/dashboards/bonvoyage.yml
observability/grafana/provisioning/datasources/prometheus.yml
observability/logging/events.yaml
observability/prometheus/prometheus.yml
observability/prometheus/rules/bonvoyage-alerts.yml
observability/prometheus/rules/bonvoyage-recording-rules.yml
observability/prometheus/tests/bonvoyage-rules.test.yml
observability/telemetry-contract.yaml
scripts/phase3-observability-decision-telemetry.sh
tests/fixtures/phase3-observability-decision-telemetry.yaml
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
write_checksums || fail "could not create observability evidence manifest"

mkdir -p "$output_root"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-observability-decision.txt.tmp"
mv "$output_root/current-observability-decision.txt.tmp" \
  "$output_root/current-observability-decision.txt"

printf 'Observability decision telemetry passed: %s\n' "$output_dir"
cat "$output_dir/metrics-validation.txt"
cat "$output_dir/summary.txt"
