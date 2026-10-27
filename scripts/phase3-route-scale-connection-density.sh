#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
fixture_image="${BONVOYAGE_SCALE_FIXTURE_IMAGE:-bonvoyage-phase3-scale-fixture:dev}"
probe_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
case "$platform" in
  linux/amd64)
    default_oha_image="ghcr.io/hatoo/oha@sha256:9567e87f638dc28e83d99fb0f7498f702ef0a9020569d089aa1ecbd720106674"
    ;;
  linux/arm64 | linux/arm64/v8)
    default_oha_image="ghcr.io/hatoo/oha@sha256:7636e482ec11bd9a51c0fdf73ec075aad861a1eb227388c5ac6d694c986232c5"
    ;;
  *)
    if [ -z "${BONVOYAGE_OHA_IMAGE:-}" ]; then
      echo "BONVOYAGE_OHA_IMAGE is required for unsupported platform: $platform" >&2
      exit 2
    fi
    default_oha_image="$BONVOYAGE_OHA_IMAGE"
    ;;
esac
oha_image="${BONVOYAGE_OHA_IMAGE:-$default_oha_image}"

route_counts="${BONVOYAGE_ROUTE_SCALE_COUNTS:-1000 10000 100000}"
density_counts="${BONVOYAGE_CONNECTION_DENSITY_COUNTS:-1000 4000 8000}"
measurement_requests="${BONVOYAGE_SCALE_MEASUREMENT_REQUESTS:-100000}"
measurement_repetitions="${BONVOYAGE_SCALE_REPETITIONS:-3}"
measurement_concurrency="${BONVOYAGE_SCALE_CONCURRENCY:-64}"
holder_workers="${BONVOYAGE_CONNECTION_HOLDER_WORKERS:-256}"
max_connections="${BONVOYAGE_SCALE_MAX_CONNECTIONS_PER_SHARD:-20000}"
gateway_memory="${BONVOYAGE_SCALE_GATEWAY_MEMORY:-1G}"
drain_timeout_seconds="${BONVOYAGE_SCALE_DRAIN_TIMEOUT_SECONDS:-60}"
rss_settle_seconds="${BONVOYAGE_SCALE_RSS_SETTLE_SECONDS:-1}"
rss_max_growth_bytes="${BONVOYAGE_SCALE_MAX_RETAINED_RSS_BYTES:-134217728}"
rss_max_growth_percent="${BONVOYAGE_SCALE_MAX_RETAINED_RSS_PERCENT:-25}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="route-scale-connection-density-$timestamp"
suffix="$$"
network="bonvoyage-scale-$suffix"
volume="bonvoyage-scale-snapshots-$suffix"
gateway="bonvoyage-scale-gateway-$suffix"
probe="bonvoyage-scale-probe-$suffix"
holder=""
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-scale.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_ROUTE_SCALE_DENSITY_EVIDENCE_ROOT:-benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"
chmod 755 "$work_dir"

fail() {
  echo "route-scale and connection-density gate failed: $*" >&2
  exit 1
}

container_exists() {
  docker inspect "$1" >/dev/null 2>&1
}

capture_cleanup_logs() {
  if container_exists "$gateway"; then
    docker logs "$gateway" >"$stage_dir/cleanup-gateway.log" 2>&1 || true
  fi
  if [ -n "$holder" ] && container_exists "$holder"; then
    docker logs "$holder" >"$stage_dir/cleanup-holder.log" 2>&1 || true
  fi
}

cleanup() {
  status="$?"
  capture_cleanup_logs
  if [ -n "$holder" ]; then
    docker rm --force "$holder" >/dev/null 2>&1 || true
  fi
  docker rm --force "$gateway" "$probe" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  if [ "$status" -eq 0 ]; then
    rm -rf "$work_dir"
  else
    echo "temporary scale evidence: $stage_dir" >&2
  fi
  return "$status"
}
trap cleanup EXIT INT TERM

for command_name in awk date docker git grep mktemp python3 sed sleep sort uname; do
  command -v "$command_name" >/dev/null 2>&1 \
    || fail "$command_name is required"
done

case "$oha_image" in
  *@sha256:*) ;;
  *) fail "BONVOYAGE_OHA_IMAGE must use an immutable sha256 digest" ;;
esac

for numeric_value in "$measurement_requests" "$measurement_repetitions" \
  "$measurement_concurrency" "$holder_workers" "$max_connections" \
  "$drain_timeout_seconds" "$rss_settle_seconds" "$rss_max_growth_bytes" \
  "$rss_max_growth_percent"; do
  case "$numeric_value" in
    '' | *[!0-9]* | 0) fail "numeric controls must be positive integers" ;;
  esac
done

validate_count_list() {
  list="$1"
  [ -n "$list" ] || fail "count lists must not be empty"
  for count in $list; do
    case "$count" in
      '' | *[!0-9]* | 0) fail "invalid count in list: $count" ;;
    esac
  done
}
validate_count_list "$route_counts"
validate_count_list "$density_counts"

for required_route_count in 1000 10000 100000; do
  case " $route_counts " in
    *" $required_route_count "*) ;;
    *) fail "route scale list must include $required_route_count" ;;
  esac
done

maximum_density=0
for density_count in $density_counts; do
  if [ "$density_count" -gt "$maximum_density" ]; then
    maximum_density="$density_count"
  fi
done
required_connections=$((maximum_density + measurement_concurrency + 64))
[ "$max_connections" -le 60000 ] \
  || fail "scale fixture supports at most 60000 connections within its 65536 descriptor limit"
[ "$max_connections" -ge "$required_connections" ] \
  || fail "max connection limit $max_connections is below required headroom $required_connections"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

now_ms() {
  # Each invocation runs in a new process, so use a cross-process clock.
  python3 -c 'import time; print(time.time_ns() // 1_000_000)'
}

measure_rss_kib() {
  docker top "$gateway" -eo pid,rss 2>/dev/null \
    | awk '
        NR > 1 && $2 ~ /^[0-9]+$/ { total += $2; count += 1 }
        END {
          if (count == 0) exit 1
          printf "%.0f\n", total
        }
      '
}

gateway_identity() {
  docker inspect --format \
    '{{.Id}}|{{.State.Pid}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.State.Running}}' \
    "$gateway"
}

capture_metrics() {
  filename="$1"
  docker exec "$probe" python -c '
import sys
import urllib.request
with urllib.request.urlopen(sys.argv[1], timeout=10) as response:
    sys.stdout.buffer.write(response.read())
' "http://$gateway:9090/metrics" >"$stage_dir/$filename"
}

metric_total() {
  metric_name="$1"
  docker exec "$probe" python -c '
import sys
import urllib.request
with urllib.request.urlopen(sys.argv[1], timeout=10) as response:
    metrics = response.read().decode()
name = sys.argv[2]
value = sum(
    float(line.split()[-1])
    for line in metrics.splitlines()
    if line.startswith(name + "{") or line.startswith(name + " ")
)
print(int(value))
' "http://$gateway:9090/metrics" "$metric_name"
}

wait_for_ready() {
  attempt=0
  while [ "$attempt" -lt 600 ]; do
    if docker exec "$probe" python -c '
import sys
import urllib.request
with urllib.request.urlopen(sys.argv[1], timeout=1) as response:
    assert response.status == 200
' "http://$gateway:9901/health/ready" >/dev/null 2>&1; then
      return 0
    fi
    running="$(docker inspect --format '{{.State.Running}}' "$gateway" 2>/dev/null || true)"
    [ "$running" = "true" ] || fail "gateway stopped before readiness"
    attempt=$((attempt + 1))
    sleep 0.1
  done
  fail "gateway did not become ready within 60 seconds"
}

wait_for_active_connections() {
  expected="$1"
  attempts=$((drain_timeout_seconds * 10))
  attempt=0
  while [ "$attempt" -lt "$attempts" ]; do
    observed="$(metric_total bonvoyage_bonvoyage_gateway_active_connections 2>/dev/null || true)"
    if [ "$observed" = "$expected" ]; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  fail "active downstream connections did not reach $expected; last observed ${observed:-unknown}"
}

start_gateway() {
  snapshot_name="$1"
  startup_started="$(now_ms)"
  docker run --detach --platform "$platform" --name "$gateway" \
    --network "$network" --network-alias gateway \
    --ulimit nofile=65536:65536 \
    --volume "$volume:/snapshots:ro" "$image" \
    --snapshot "/snapshots/$snapshot_name" \
    --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
    --smp 1 --memory "$gateway_memory" --overprovisioned >/dev/null
  wait_for_ready
  startup_finished="$(now_ms)"
  startup_elapsed_ms=$((startup_finished - startup_started))
}

stop_gateway() {
  label="$1"
  docker logs "$gateway" >"$stage_dir/gateway-$label.log" 2>&1
  docker inspect "$gateway" >"$stage_dir/gateway-$label.before-stop.inspect.json"
  docker stop --time 15 "$gateway" >/dev/null
  docker inspect "$gateway" >"$stage_dir/gateway-$label.after-stop.inspect.json"
  gateway_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
  [ "$gateway_exit_code" -eq 0 ] || fail "$label gateway exit code was $gateway_exit_code"
  docker rm "$gateway" >/dev/null
}

run_oha() {
  output_name="$1"
  request_path="$2"
  docker run --rm --platform "$platform" --network "$network" --read-only \
    --security-opt no-new-privileges:true --cap-drop ALL "$oha_image" \
    -n "$measurement_requests" -c "$measurement_concurrency" \
    --no-tui --output-format json --http-version 1.1 \
    --disable-compression --host scale.example.test \
    "http://gateway:8080$request_path" >"$stage_dir/$output_name"
}

validate_oha() {
  filename="$1"
  python3 -c '
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
expected = int(sys.argv[2])
distribution = result.get("statusCodeDistribution", {})
errors = result.get("errorDistribution", {})
assert result["summary"]["successRate"] == 1, result["summary"]
assert int(distribution.get("200", 0)) == expected, distribution
assert set(distribution) == {"200"}, distribution
assert not errors, errors
assert float(result["summary"]["requestsPerSec"]) > 0, result["summary"]
' "$stage_dir/$filename" "$measurement_requests"
}

run_oha_series() {
  prefix="$1"
  request_path="$2"
  repetition=1
  while [ "$repetition" -le "$measurement_repetitions" ]; do
    filename="$prefix-rep$repetition.oha.json"
    run_oha "$filename" "$request_path"
    validate_oha "$filename" || fail "$filename did not meet the success contract"
    repetition=$((repetition + 1))
  done
}

validate_route_positions() {
  route_count="$1"
  docker exec "$probe" python -c '
import json
import sys
import urllib.error
import urllib.request

count = int(sys.argv[1])
base = "http://gateway:8080"
indices = [0, count // 2, count - 1]
results = []
for index in indices:
    identity = f"r{index:06d}"
    request = urllib.request.Request(
        f"{base}/r/{index:06d}",
        headers={"Host": "scale.example.test"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read().decode()
    assert response.status == 200, response.status
    assert body == identity + "\n", (identity, body)
    results.append({"index": index, "status": response.status, "body": body})

miss = urllib.request.Request(
    f"{base}/r/{count:06d}",
    headers={"Host": "scale.example.test"},
)
try:
    urllib.request.urlopen(miss, timeout=10)
except urllib.error.HTTPError as error:
    miss_body = json.loads(error.read().decode())
    assert error.code == 404, error.code
    assert miss_body["error"]["code"] == "route_not_found", miss_body
    results.append({"index": count, "status": error.code, "code": "route_not_found"})
else:
    raise AssertionError("route miss unexpectedly succeeded")

print(json.dumps({"route_count": count, "results": results}, indent=2))
' "$route_count" >"$stage_dir/route-$route_count.functional.json"
}

wait_for_holder_ready() {
  attempt=0
  while [ "$attempt" -lt 1800 ]; do
    if docker exec "$probe" python -c '
import urllib.request
with urllib.request.urlopen("http://holder:8090/health/ready", timeout=1) as response:
    assert response.status == 200
' >/dev/null 2>&1; then
      return 0
    fi
    running="$(docker inspect --format '{{.State.Running}}' "$holder" 2>/dev/null || true)"
    [ "$running" = "true" ] || fail "connection holder stopped before readiness"
    attempt=$((attempt + 1))
    sleep 0.1
  done
  fail "connection holder did not become ready within 180 seconds"
}

capture_holder_summary() {
  filename="$1"
  docker exec "$probe" python -c '
import sys
import urllib.request
with urllib.request.urlopen("http://holder:8090/summary", timeout=10) as response:
    sys.stdout.buffer.write(response.read())
' >"$stage_dir/$filename"
}

release_holder() {
  docker exec "$probe" python -c '
import urllib.request
request = urllib.request.Request("http://holder:8090/release", method="POST")
with urllib.request.urlopen(request, timeout=30) as response:
    assert response.status == 200
' >/dev/null
}

if [ -n "${BONVOYAGE_LOCKED_DATAPLANE_IMAGE_ID:-}" ]; then
  BONVOYAGE_DATAPLANE_IMAGE="$image" \
    "$script_dir/require-locked-dataplane-image.sh"
else
  docker buildx build --platform "$platform" --load --tag "$image" \
    --file deploy/docker/bonvoyage/Dockerfile .
fi
docker buildx build --platform "$platform" --load --tag "$fixture_image" \
  --file tests/fixtures/phase3-scale/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$probe_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
if ! docker image inspect "$oha_image" >/dev/null 2>&1; then
  docker pull --platform "$platform" "$oha_image"
fi

docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
docker run --detach --platform "$platform" --name "$probe" \
  --network "$network" --network-alias probe "$probe_image" >/dev/null

docker info >"$stage_dir/docker-info.txt"
docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker image inspect "$fixture_image" >"$stage_dir/fixture-image.inspect.json"
docker image inspect "$oha_image" >"$stage_dir/oha-image.inspect.json"

printf 'route_count,snapshot_bytes,generation_ms,startup_ms,rss_kib,configured_routes,graceful_exit\n' \
  >"$stage_dir/route-lifecycle.csv"

for route_count in $route_counts; do
  generation_started="$(now_ms)"
  docker run --rm --platform "$platform" --user 0:0 \
    --volume "$volume:/output" "$fixture_image" snapshot \
    -routes "$route_count" \
    -max-connections "$max_connections" \
    -output "/output/snapshot-$route_count.pb" \
    >"$stage_dir/snapshot-$route_count.json"
  generation_finished="$(now_ms)"
  generation_elapsed_ms=$((generation_finished - generation_started))
  snapshot_bytes="$(python3 -c '
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["bytes"])
' "$stage_dir/snapshot-$route_count.json")"

  start_gateway "snapshot-$route_count.pb"
  validate_route_positions "$route_count" \
    || fail "$route_count route positional validation failed"
  configured_routes="$(metric_total bonvoyage_bonvoyage_gateway_configured_routes)"
  [ "$configured_routes" -eq "$route_count" ] \
    || fail "configured route gauge $configured_routes did not equal $route_count"
  wait_for_active_connections 0
  sleep "$rss_settle_seconds"
  route_rss_kib="$(measure_rss_kib)" \
    || fail "could not measure RSS for $route_count routes"
  capture_metrics "metrics-route-$route_count.prom"
  middle_index=$((route_count / 2))
  middle_path="$(printf '/r/%06d' "$middle_index")"
  run_oha_series "route-$route_count" "$middle_path"
  wait_for_active_connections 0
  stop_gateway "route-$route_count"
  printf '%s,%s,%s,%s,%s,%s,%s\n' \
    "$route_count" "$snapshot_bytes" "$generation_elapsed_ms" \
    "$startup_elapsed_ms" "$route_rss_kib" "$configured_routes" \
    "$gateway_exit_code" >>"$stage_dir/route-lifecycle.csv"
done

start_gateway "snapshot-1000.pb"
run_oha_series density-baseline /r/000500
wait_for_active_connections 0
sleep "$rss_settle_seconds"
density_baseline_rss_kib="$(measure_rss_kib)" \
  || fail "could not measure density baseline RSS"
density_initial_identity="$(gateway_identity)" \
  || fail "could not capture density gateway identity"
printf 'initial=%s\n' "$density_initial_identity" \
  >"$stage_dir/density-gateway-identities.txt"
capture_metrics metrics-density-baseline.prom

printf 'target,opened,open_duration_ms,rss_before_kib,rss_at_density_kib,rss_delta_kib,bytes_per_connection,active_before_load,active_after_load,active_after_release,rejection_delta,rss_after_release_kib\n' \
  >"$stage_dir/density-lifecycle.csv"

for density_count in $density_counts; do
  rss_before_kib="$(measure_rss_kib)" \
    || fail "could not measure RSS before $density_count connections"
  rejections_before="$(metric_total bonvoyage_bonvoyage_gateway_downstream_connection_rejections_total)"
  holder="bonvoyage-scale-holder-$density_count-$suffix"
  docker run --detach --platform "$platform" --name "$holder" \
    --network "$network" --network-alias holder --read-only \
    --security-opt no-new-privileges:true --cap-drop ALL \
    --pids-limit 1024 --ulimit nofile=1048576:1048576 \
    "$fixture_image" hold --address gateway:8080 \
    --host scale.example.test --path /r/000000 \
    --connections "$density_count" \
    --workers "$holder_workers" >/dev/null
  wait_for_holder_ready
  capture_holder_summary "holder-$density_count.ready.json"
  opened="$(python3 -c '
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["opened"])
' "$stage_dir/holder-$density_count.ready.json")"
  open_duration_ms="$(python3 -c '
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["open_duration_ms"])
' "$stage_dir/holder-$density_count.ready.json")"
  [ "$opened" -eq "$density_count" ] \
    || fail "holder opened $opened of $density_count connections"
  wait_for_active_connections "$density_count"
  active_before_load="$(metric_total bonvoyage_bonvoyage_gateway_active_connections)"
  rss_at_density_kib="$(measure_rss_kib)" \
    || fail "could not measure RSS at $density_count connections"
  capture_metrics "metrics-density-$density_count-active.prom"
  run_oha_series "density-$density_count" /r/000500
  wait_for_active_connections "$density_count"
  active_after_load="$(metric_total bonvoyage_bonvoyage_gateway_active_connections)"
  release_holder
  wait_for_active_connections 0
  active_after_release="$(metric_total bonvoyage_bonvoyage_gateway_active_connections)"
  capture_holder_summary "holder-$density_count.released.json"
  capture_metrics "metrics-density-$density_count-released.prom"
  docker logs "$holder" >"$stage_dir/holder-$density_count.log" 2>&1
  docker inspect "$holder" >"$stage_dir/holder-$density_count.inspect.json"
  docker stop --time 10 "$holder" >/dev/null
  holder_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$holder")"
  [ "$holder_exit_code" -eq 0 ] \
    || fail "$density_count connection holder exit code was $holder_exit_code"
  docker rm "$holder" >/dev/null
  holder=""
  rejections_after="$(metric_total bonvoyage_bonvoyage_gateway_downstream_connection_rejections_total)"
  rejection_delta=$((rejections_after - rejections_before))
  [ "$rejection_delta" -eq 0 ] \
    || fail "$density_count connection case recorded $rejection_delta admission rejections"
  sleep "$rss_settle_seconds"
  rss_after_release_kib="$(measure_rss_kib)" \
    || fail "could not measure RSS after releasing $density_count connections"
  rss_delta_kib=$((rss_at_density_kib - rss_before_kib))
  if [ "$rss_delta_kib" -lt 0 ]; then
    rss_delta_kib=0
  fi
  bytes_per_connection=$((rss_delta_kib * 1024 / density_count))
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$density_count" "$opened" "$open_duration_ms" "$rss_before_kib" \
    "$rss_at_density_kib" "$rss_delta_kib" "$bytes_per_connection" \
    "$active_before_load" "$active_after_load" "$active_after_release" \
    "$rejection_delta" "$rss_after_release_kib" \
    >>"$stage_dir/density-lifecycle.csv"
done

run_oha_series density-recovery /r/000500
wait_for_active_connections 0
density_final_identity="$(gateway_identity)" \
  || fail "density gateway stopped before recovery identity check"
printf 'final=%s\n' "$density_final_identity" \
  >>"$stage_dir/density-gateway-identities.txt"
[ "$density_initial_identity" = "$density_final_identity" ] \
  || fail "density gateway process identity changed"
sleep "$rss_settle_seconds"
density_final_rss_kib="$(measure_rss_kib)" \
  || fail "could not measure final density RSS"
density_final_growth_kib=$((density_final_rss_kib - density_baseline_rss_kib))
if [ "$density_final_growth_kib" -lt 0 ]; then
  density_final_growth_kib=0
fi
rss_absolute_limit_kib=$(((rss_max_growth_bytes + 1023) / 1024))
rss_percent_limit_kib=$(((density_baseline_rss_kib * rss_max_growth_percent + 99) / 100))
rss_allowed_growth_kib="$rss_absolute_limit_kib"
if [ "$rss_percent_limit_kib" -gt "$rss_allowed_growth_kib" ]; then
  rss_allowed_growth_kib="$rss_percent_limit_kib"
fi
[ "$density_final_growth_kib" -le "$rss_allowed_growth_kib" ] \
  || fail "retained RSS growth ${density_final_growth_kib} KiB exceeded ${rss_allowed_growth_kib} KiB"
capture_metrics metrics-density-final.prom
cat >"$stage_dir/density-final.txt" <<EOF
baseline_rss_kib=$density_baseline_rss_kib
final_rss_kib=$density_final_rss_kib
retained_growth_kib=$density_final_growth_kib
allowed_growth_kib=$rss_allowed_growth_kib
process_identity_unchanged=true
EOF
stop_gateway density

python3 - "$stage_dir" "$run_id" "$measurement_requests" \
  "$measurement_repetitions" "$measurement_concurrency" "$platform" \
  >"$stage_dir/summary.json" <<'PY'
import csv
import glob
import json
import os
import statistics
import sys

root, run_id, requests, repetitions, concurrency, platform = sys.argv[1:]

def read_csv(name):
    with open(os.path.join(root, name), newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source))

def summarize_oha(prefix):
    paths = sorted(glob.glob(os.path.join(root, prefix + "-rep*.oha.json")))
    samples = []
    for path in paths:
        with open(path, encoding="utf-8") as source:
            result = json.load(source)
        samples.append({
            "requests_per_second": float(result["summary"]["requestsPerSec"]),
            "p99_ms": float(result["latencyPercentiles"]["p99"]) * 1000,
            "p999_ms": float(result["latencyPercentiles"]["p99.9"]) * 1000,
            "success_rate": float(result["summary"]["successRate"]),
        })
    assert len(samples) == int(repetitions), (prefix, len(samples), repetitions)
    return {
        "samples": samples,
        "median_requests_per_second": statistics.median(item["requests_per_second"] for item in samples),
        "median_p99_ms": statistics.median(item["p99_ms"] for item in samples),
        "median_p999_ms": statistics.median(item["p999_ms"] for item in samples),
        "minimum_success_rate": min(item["success_rate"] for item in samples),
    }

route_rows = read_csv("route-lifecycle.csv")
routes = {}
for row in route_rows:
    count = row["route_count"]
    routes[count] = {
        "snapshot_bytes": int(row["snapshot_bytes"]),
        "generation_ms": int(row["generation_ms"]),
        "startup_ms": int(row["startup_ms"]),
        "rss_kib": int(row["rss_kib"]),
        "configured_routes": int(row["configured_routes"]),
        "graceful_exit": int(row["graceful_exit"]) == 0,
        "lookup": summarize_oha("route-" + count),
    }

density_rows = read_csv("density-lifecycle.csv")
density = {}
for row in density_rows:
    count = row["target"]
    density[count] = {
        key: int(value)
        for key, value in row.items()
        if key != "target"
    }
    density[count]["active_lookup"] = summarize_oha("density-" + count)

with open(os.path.join(root, "density-final.txt"), encoding="utf-8") as source:
    final = dict(line.rstrip().split("=", 1) for line in source if "=" in line)

baseline = summarize_oha("density-baseline")
recovery = summarize_oha("density-recovery")
for item in density.values():
    item["active_to_baseline_rps_ratio"] = (
        item["active_lookup"]["median_requests_per_second"]
        / baseline["median_requests_per_second"]
    )

summary = {
    "schema_version": 1,
    "run_id": run_id,
    "result": "PASS",
    "classification": "local engineering evidence",
    "publishable": False,
    "marketing_use_authorized": False,
    "controls": {
        "platform": platform,
        "gateway_shards": 1,
        "protocol": "cleartext HTTP/1.1",
        "action": "fixed response",
        "requests_per_repetition": int(requests),
        "repetitions": int(repetitions),
        "logical_concurrency": int(concurrency),
    },
    "route_scale": routes,
    "connection_density": {
        "baseline": baseline,
        "cases": density,
        "recovery": recovery,
        "baseline_rss_kib": int(final["baseline_rss_kib"]),
        "final_rss_kib": int(final["final_rss_kib"]),
        "retained_growth_kib": int(final["retained_growth_kib"]),
        "allowed_growth_kib": int(final["allowed_growth_kib"]),
        "process_identity_unchanged": final["process_identity_unchanged"] == "true",
    },
    "qualified_boundary": [
        "deterministic Protobuf snapshot generation",
        "one-shard immutable snapshot preparation and exact-path indexes",
        "first, middle, last, and miss route correctness",
        "configured-route telemetry",
        "bounded idle HTTP/1.1 connections with concurrent active requests",
        "exact connection accounting, zero admission rejection, drain, recovery, and graceful exit",
    ],
    "limitations": [
        "Local Docker Desktop scheduling and shared-host effects are uncontrolled.",
        "The load generator and gateway share one local Docker engine.",
        "The test-only generator exercises the Protobuf runtime contract, not the 1 MiB human-authored YAML input path.",
        "This bounded sweep does not establish a multi-hour memory slope or a production connection ceiling.",
        "Dedicated separated-role 10K, 50K, and 100K connection qualification remains pending.",
        "No performance, capacity, customer, or marketing claim is authorized by this evidence.",
    ],
}
print(json.dumps(summary, indent=2, sort_keys=True))
PY

python3 - "$stage_dir/summary.json" >"$stage_dir/summary.txt" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    summary = json.load(source)
print("LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE")
print("Route scale:")
for count, result in sorted(summary["route_scale"].items(), key=lambda item: int(item[0])):
    lookup = result["lookup"]
    print(
        f"  {int(count):,} routes: snapshot {result['snapshot_bytes']:,} bytes; "
        f"generation {result['generation_ms']} ms; startup {result['startup_ms']} ms; "
        f"RSS {result['rss_kib'] / 1024:.2f} MiB; "
        f"median {lookup['median_requests_per_second']:.1f} RPS; "
        f"p99 {lookup['median_p99_ms']:.3f} ms; p99.9 {lookup['median_p999_ms']:.3f} ms"
    )
print("Connection density:")
baseline = summary["connection_density"]["baseline"]
print(f"  baseline active lookup: {baseline['median_requests_per_second']:.1f} RPS")
for count, result in sorted(summary["connection_density"]["cases"].items(), key=lambda item: int(item[0])):
    lookup = result["active_lookup"]
    print(
        f"  {int(count):,} held: {result['bytes_per_connection']:,} observed RSS bytes/connection; "
        f"{lookup['median_requests_per_second']:.1f} active RPS; "
        f"ratio {result['active_to_baseline_rps_ratio']:.3f}; "
        f"p99.9 {lookup['median_p999_ms']:.3f} ms; rejections {result['rejection_delta']}"
    )
connection = summary["connection_density"]
print(
    f"  final retained RSS growth: {connection['retained_growth_kib']} KiB "
    f"(allowed {connection['allowed_growth_kib']} KiB); process unchanged"
)
PY

source_commit="$(git rev-parse HEAD)"
source_dirty="$(if [ -z "$(git status --porcelain)" ]; then printf false; else printf true; fi)"
runtime_image_id="$(docker image inspect "$image" --format '{{.Id}}')"
fixture_image_id="$(docker image inspect "$fixture_image" --format '{{.Id}}')"
oha_image_id="$(docker image inspect "$oha_image" --format '{{.Id}}')"
cat >"$stage_dir/metadata.txt" <<EOF
captured_at_utc=$timestamp
run_id=$run_id
source_commit=$source_commit
source_dirty=$source_dirty
host=$(uname -s) $(uname -r) $(uname -m)
platform=$platform
runtime_image=$image
runtime_image_id=$runtime_image_id
fixture_image=$fixture_image
fixture_image_id=$fixture_image_id
oha_image=$oha_image
oha_image_id=$oha_image_id
route_counts=$route_counts
density_counts=$density_counts
measurement_requests=$measurement_requests
measurement_repetitions=$measurement_repetitions
measurement_concurrency=$measurement_concurrency
max_connections_per_shard=$max_connections
gateway_memory=$gateway_memory
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<'EOF'
# Phase 3 route-scale and connection-density evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, competitive, customer-facing, billing, capacity, or production-readiness claims.

The route matrix generates deterministic immutable Protobuf snapshots at 1K, 10K, and 100K exact routes. Every snapshot is prepared by one live BonVoyage shard, reports the expected configured-route gauge, returns route-specific bodies for first/middle/last positions, rejects a miss, serves a repeated fixed-response lookup workload, and exits cleanly.

The density matrix holds verified HTTP/1.1 keep-alive connections idle while a separate client continues active fixed-response requests. It records exact active-connection accounting, admission rejection deltas, process identity, RSS before/during/after each level, observed RSS bytes per connection, active lookup latency and throughput, complete drain, recovery, and final retained RSS.

The test-only generator deliberately exercises the runtime Protobuf contract. It does not weaken or qualify the original 1 MiB human-authored YAML input bound. The bounded local sweep does not establish a production connection ceiling, multi-hour memory slope, or dedicated-host performance result.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
.dockerignore
Makefile
api/proto/bonvoyage/v1/config.proto
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/gateway.cc
dataplane/src/runtime_snapshot.cc
deploy/docker/bonvoyage/Dockerfile
deploy/docker/upstream/Dockerfile
scripts/phase3-route-scale-connection-density.sh
tests/fixtures/phase3-scale/Dockerfile
tests/fixtures/phase3-scale/go.mod
tests/fixtures/phase3-scale/go.sum
tests/fixtures/phase3-scale/main.go
tests/fixtures/phase3-scale/main_test.go
EOF
while IFS= read -r source_file; do
  hash_file "$source_file"
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"

test ! -e "$output_dir"
mkdir -p "$output_dir"
cp -R "$stage_dir"/. "$output_dir"/
checksum_manifest="$work_dir/checksums.sha256"
(
  cd "$output_dir"
  find . -type f ! -name checksums.sha256 -print | LC_ALL=C sort | \
    while IFS= read -r evidence_file; do
      hash_file "$evidence_file"
    done >"$checksum_manifest"
)
mv "$checksum_manifest" "$output_dir/checksums.sha256"
printf '%s\n' "$run_id" >"$output_root/current-route-scale-connection-density.txt.tmp"
mv "$output_root/current-route-scale-connection-density.txt.tmp" \
  "$output_root/current-route-scale-connection-density.txt"

trap - EXIT INT TERM
cleanup
printf '%s\n' "route-scale and connection-density gate passed: $output_dir"
cat "$output_dir/summary.txt"
