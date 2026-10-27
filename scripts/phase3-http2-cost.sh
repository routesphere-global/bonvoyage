#!/bin/sh
set -eu

umask 077

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

dataplane_image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
platform="${BONVOYAGE_BUILD_PLATFORM:-}"
fixture="$repo_root/tests/fixtures/phase3-http2-cost.yaml"

warmup_seconds="${BONVOYAGE_HTTP2_COST_WARMUP_SECONDS:-5}"
measurement_seconds="${BONVOYAGE_HTTP2_COST_MEASUREMENT_SECONDS:-10}"
repetitions="${BONVOYAGE_HTTP2_COST_REPETITIONS:-3}"
cooldown_seconds="${BONVOYAGE_HTTP2_COST_COOLDOWN_SECONDS:-1}"
logical_concurrency="${BONVOYAGE_HTTP2_COST_CONCURRENCY:-32}"
http2_connections="${BONVOYAGE_HTTP2_COST_HTTP2_CONNECTIONS:-8}"
http2_parallel="${BONVOYAGE_HTTP2_COST_HTTP2_PARALLEL:-4}"
payload_bytes="${BONVOYAGE_HTTP2_COST_PAYLOAD_BYTES:-256}"
minimum_resource_samples="${BONVOYAGE_HTTP2_COST_MIN_RESOURCE_SAMPLES:-3}"
maximum_error_rate="${BONVOYAGE_HTTP2_COST_MAX_ERROR_RATE:-0.001}"

started_at="$(date -u +%Y%m%dT%H%M%SZ)"
suffix="$$"
run_id="phase3-http2-cost-$started_at-$suffix"
network="bonvoyage-http2-cost-$suffix"
volume="bonvoyage-http2-cost-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-http2-cost-gateway-$suffix"
upstream="bonvoyage-http2-cost-upstream-$suffix"
loadgen=""
dataplane_run_image="bonvoyage-phase3-cost-dataplane:$suffix"
compiler_run_image="bonvoyage-phase3-cost-compiler:$suffix"
upstream_run_image="bonvoyage-phase3-cost-upstream:$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-http2-cost.XXXXXX")"
evidence_root="${BONVOYAGE_HTTP2_COST_EVIDENCE_ROOT:-${TMPDIR:-/tmp}/bonvoyage-http2-cost-evidence}"
evidence_dir="${BONVOYAGE_HTTP2_COST_EVIDENCE_DIR:-$evidence_root/$run_id}"

checksum_tool=""
dataplane_image_id=""
compiler_image_id=""
upstream_image_id=""
oha_image_id=""
evidence_ready=0

fail() {
  message="$1"
  printf 'phase3-http2-cost: %s\n' "$message" >&2
  if [ "$evidence_ready" -eq 1 ]; then
    printf '%s\n' "$message" >"$evidence_dir/failure.txt"
  fi
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 \
    || fail "required command is unavailable: $1"
}

require_positive_integer() {
  name="$1"
  value="$2"
  case "$value" in
    ''|*[!0-9]*) fail "$name must be a positive integer, got '$value'" ;;
  esac
  [ "$value" -gt 0 ] || fail "$name must be greater than zero"
}

require_nonnegative_integer() {
  name="$1"
  value="$2"
  case "$value" in
    ''|*[!0-9]*) fail "$name must be a nonnegative integer, got '$value'" ;;
  esac
}

require_rate() {
  name="$1"
  value="$2"
  awk -v value="$value" 'BEGIN {
    if (value !~ /^[0-9]+([.][0-9]+)?$/ || value < 0 || value > 1) exit 1
  }' || fail "$name must be a number between zero and one, got '$value'"
}

checksum_value() {
  path="$1"
  if [ "$checksum_tool" = "sha256sum" ]; then
    sha256sum "$path" | awk '{print $1}'
  else
    shasum -a 256 "$path" | awk '{print $1}'
  fi
}

write_checksums() {
  (
    cd "$evidence_dir" || exit 1
    find . -type f \
      ! -name 'checksums.sha256' \
      ! -name 'checksums.sha256.tmp' -print \
      | LC_ALL=C sort \
      | while IFS= read -r path; do
          path="${path#./}"
          if [ "$checksum_tool" = "sha256sum" ]; then
            sha256sum "$path"
          else
            shasum -a 256 "$path"
          fi
        done >checksums.sha256.tmp
    mv checksums.sha256.tmp checksums.sha256
    if [ "$checksum_tool" = "sha256sum" ]; then
      sha256sum --check checksums.sha256 >/dev/null
    else
      shasum -a 256 --check checksums.sha256 >/dev/null
    fi
  )
}

capture_container() {
  name="$1"
  label="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker inspect "$name" >"$evidence_dir/$label.inspect.json" 2>&1 || true
    docker logs "$name" >"$evidence_dir/$label.log" 2>&1 || true
  fi
}

cleanup() {
  status="$?"
  trap - EXIT INT TERM
  set +e

  if [ -n "$loadgen" ]; then
    capture_container "$loadgen" interrupted-load-generator
  fi

  if docker inspect "$gateway" >/dev/null 2>&1; then
    running="$(docker inspect --format '{{.State.Running}}' "$gateway" 2>/dev/null)"
    if [ "$running" = "true" ]; then
      docker stop --signal TERM --time 15 "$gateway" >/dev/null 2>&1
    fi
  fi

  if [ "$evidence_ready" -eq 1 ]; then
    capture_container "$gateway" gateway
    capture_container "$upstream" upstream
    if [ "$status" -eq 0 ]; then
      printf 'outcome=PASS\nexit_code=0\nevidence_class=local-engineering\npublishable=false\n' \
        >"$evidence_dir/run-status.env"
    else
      printf 'outcome=FAIL\nexit_code=%s\nevidence_class=local-engineering\npublishable=false\n' \
        "$status" >"$evidence_dir/run-status.env"
    fi

    if ! write_checksums; then
      printf 'phase3-http2-cost: failed to create or verify evidence checksums\n' >&2
      status=1
      printf 'outcome=FAIL\nexit_code=1\nevidence_class=local-engineering\npublishable=false\n' \
        >"$evidence_dir/run-status.env"
      write_checksums >/dev/null 2>&1 || true
    fi
  fi

  docker rm --force "$loadgen" "$gateway" "$upstream" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$work_dir/secrets" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  docker image rm \
    "$dataplane_run_image" "$compiler_run_image" "$upstream_run_image" \
    >/dev/null 2>&1 || true
  rm -rf "$work_dir"

  if [ "$status" -eq 0 ]; then
    printf 'BonVoyage local TLS protocol-cost qualification passed\n'
  else
    printf 'BonVoyage local TLS protocol-cost qualification failed\n' >&2
  fi
  if [ "$evidence_ready" -eq 1 ]; then
    printf 'Evidence retained at %s\n' "$evidence_dir"
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

memory_to_bytes() {
  memory_value="$1"
  case "$memory_value" in
    *KiB) memory_number="${memory_value%KiB}"; memory_multiplier=1024 ;;
    *MiB) memory_number="${memory_value%MiB}"; memory_multiplier=1048576 ;;
    *GiB) memory_number="${memory_value%GiB}"; memory_multiplier=1073741824 ;;
    *kB) memory_number="${memory_value%kB}"; memory_multiplier=1000 ;;
    *MB) memory_number="${memory_value%MB}"; memory_multiplier=1000000 ;;
    *GB) memory_number="${memory_value%GB}"; memory_multiplier=1000000000 ;;
    *B) memory_number="${memory_value%B}"; memory_multiplier=1 ;;
    *) return 1 ;;
  esac
  awk -v number="$memory_number" -v multiplier="$memory_multiplier" \
    'BEGIN { printf "%.0f", number * multiplier }'
}

measure_gateway_rss_kib() {
  docker top "$gateway" -eo pid,rss 2>/dev/null \
    | awk '
        NR > 1 && $2 ~ /^[0-9]+$/ { total += $2; count += 1 }
        END {
          if (count == 0) exit 1
          printf "%.0f\n", total
        }
      '
}

run_python() {
  docker run --rm --platform "$platform" --network none --read-only \
    --user "$(id -u):$(id -g)" \
    --security-opt no-new-privileges:true --cap-drop ALL \
    --volume "$evidence_dir:/evidence:ro" \
    --entrypoint python "$upstream_run_image" "$@"
}

run_python_write() {
  docker run --rm --platform "$platform" --network none --read-only \
    --user "$(id -u):$(id -g)" \
    --security-opt no-new-privileges:true --cap-drop ALL \
    --volume "$evidence_dir:/evidence:rw" \
    --entrypoint python "$upstream_run_image" "$@"
}

validate_oha_output() {
  relative_path="$1"
  allowed_error_rate="$2"
  run_python -c '
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
summary = result.get("summary", {})
success_rate = float(summary.get("successRate", -1))
requests_per_second = float(summary.get("requestsPerSec", 0))
percentiles = result.get("latencyPercentiles", {})
assert requests_per_second > 0, summary
assert success_rate >= 1 - float(sys.argv[2]), summary
assert percentiles.get("p99") is not None, percentiles
assert percentiles.get("p99.9") is not None, percentiles
assert sum(int(value) for value in result.get("statusCodeDistribution", {}).values()) > 0
' "/evidence/$relative_path" "$allowed_error_rate"
}

capture_metrics() {
  output_name="$1"
  docker exec "$upstream" python -c '
import sys
import urllib.request

body = urllib.request.urlopen(sys.argv[1], timeout=5).read()
sys.stdout.buffer.write(body)
' "http://$gateway:9090/metrics" >"$evidence_dir/$output_name"
}

run_oha_foreground() {
  protocol="$1"
  duration="$2"
  output_name="$3"
  stderr_name="$4"

  if [ "$protocol" = "http1" ]; then
    port=8443
    version=1.1
    connections="$logical_concurrency"
    parallel=1
  else
    port=9443
    version=2
    connections="$http2_connections"
    parallel="$http2_parallel"
  fi

  docker run --rm --platform "$platform" --network "$network" --read-only \
    --user "$(id -u):$(id -g)" \
    --security-opt no-new-privileges:true --cap-drop ALL \
    --volume "$work_dir/client:/tls:ro" "$oha_image_id" \
    -z "${duration}s" -c "$connections" -p "$parallel" \
    --wait-ongoing-requests-after-deadline \
    --no-tui --no-color --output-format json \
    --http-version "$version" --disable-compression \
    --connect-timeout 5s -t 10s --cacert /tls/ca.pem \
    "https://api.example.test:$port/payload/$payload_bytes" \
    >"$evidence_dir/$output_name" 2>"$evidence_dir/$stderr_name"
}

write_result() {
  protocol="$1"
  repetition="$2"
  raw_name="$3"
  stats_name="$4"
  metrics_before_name="$5"
  metrics_after_name="$6"
  result_name="$7"
  loadgen_name="$8"

  run_python -c '
import csv
import json
import statistics
import sys

raw_path, stats_path, metrics_before_path, metrics_after_path = sys.argv[1:5]
protocol, repetition = sys.argv[5:7]
gateway_name, upstream_name, loadgen_name = sys.argv[7:10]
minimum_samples = int(sys.argv[10])
maximum_error_rate = float(sys.argv[11])
logical_concurrency = int(sys.argv[12])
http2_connections = int(sys.argv[13])
http2_parallel = int(sys.argv[14])
measurement_seconds = int(sys.argv[15])
payload_bytes = int(sys.argv[16])

with open(raw_path, encoding="utf-8") as source:
    raw = json.load(source)
with open(stats_path, newline="", encoding="utf-8") as source:
    rows = list(csv.DictReader(source, delimiter="\t"))

def metric_sum(path, name):
    values = []
    with open(path, encoding="utf-8") as source:
        for line in source:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            if len(fields) < 2:
                continue
            metric_name = fields[0].split("{", 1)[0]
            if metric_name == name:
                values.append(float(fields[1]))
    if not values:
        raise AssertionError(f"required allocator metric is absent: {name}")
    return sum(values)

allocator_metric_names = {
    "malloc_operations": "bonvoyage_memory_malloc_operations",
    "free_operations": "bonvoyage_memory_free_operations",
    "cross_cpu_free_operations": "bonvoyage_memory_cross_cpu_free_operations",
    "malloc_failed": "bonvoyage_memory_malloc_failed",
    "oversized_allocs": "bonvoyage_memory_oversized_allocs",
    "reclaims_operations": "bonvoyage_memory_reclaims_operations",
    "malloc_live_objects": "bonvoyage_memory_malloc_live_objects",
    "allocated_memory": "bonvoyage_memory_allocated_memory",
}
allocator_before = {
    key: metric_sum(metrics_before_path, name)
    for key, name in allocator_metric_names.items()
}
allocator_after = {
    key: metric_sum(metrics_after_path, name)
    for key, name in allocator_metric_names.items()
}
allocator_deltas = {
    key: allocator_after[key] - allocator_before[key]
    for key in allocator_metric_names
}
for name in (
    "malloc_operations",
    "free_operations",
    "cross_cpu_free_operations",
    "malloc_failed",
    "oversized_allocs",
    "reclaims_operations",
):
    if allocator_deltas[name] < 0:
        raise AssertionError(f"allocator counter reset during measurement: {name}")

def selected(name):
    return [row for row in rows if row["container"] == name]

gateway_rows = selected(gateway_name)
upstream_rows = selected(upstream_name)
loadgen_rows = selected(loadgen_name)
rss_values = [int(row["gateway_rss_kib"]) for row in gateway_rows
              if row["gateway_rss_kib"]]
sample_counts = {
    "gateway": len(gateway_rows),
    "gateway_rss": len(rss_values),
    "upstream": len(upstream_rows),
    "load_generator": len(loadgen_rows),
}
for role, count in sample_counts.items():
    if count < minimum_samples:
        raise AssertionError(
            f"{role} supplied {count} samples, expected at least {minimum_samples}"
        )

def mean_cpu(values):
    return statistics.fmean(float(row["cpu_percent"]) for row in values)

summary = raw["summary"]
success_rate = float(summary["successRate"])
request_rate = float(summary["requestsPerSec"])
error_rate = 1.0 - success_rate
percentiles = raw["latencyPercentiles"]
status_distribution = raw.get("statusCodeDistribution", {})
total_responses = sum(int(value) for value in status_distribution.values())
successful_responses = int(status_distribution.get("200", 0))
valid = (
    request_rate > 0
    and total_responses > 0
    and successful_responses > 0
    and error_rate <= maximum_error_rate
    and percentiles.get("p99") is not None
    and percentiles.get("p99.9") is not None
    and allocator_deltas["malloc_failed"] == 0
    and allocator_deltas["cross_cpu_free_operations"] == 0
)

allocator = {
    "source": "Seastar shard allocator metrics exposed by the live dataplane",
    "normalization": "successful HTTP 200 responses",
    "successful_responses": successful_responses,
    "malloc_operations_delta": int(allocator_deltas["malloc_operations"]),
    "free_operations_delta": int(allocator_deltas["free_operations"]),
    "malloc_operations_per_successful_response": (
        allocator_deltas["malloc_operations"] / successful_responses
    ),
    "free_operations_per_successful_response": (
        allocator_deltas["free_operations"] / successful_responses
    ),
    "live_objects_delta": int(allocator_deltas["malloc_live_objects"]),
    "allocated_memory_delta_bytes": int(allocator_deltas["allocated_memory"]),
    "failed_allocations_delta": int(allocator_deltas["malloc_failed"]),
    "oversized_allocations_delta": int(allocator_deltas["oversized_allocs"]),
    "reclaim_operations_delta": int(allocator_deltas["reclaims_operations"]),
    "cross_shard_free_operations_delta": int(
        allocator_deltas["cross_cpu_free_operations"]
    ),
}

result = {
    "schema_version": 1,
    "evidence": {
        "class": "local-engineering",
        "publishable": False,
        "marketing_use_authorized": False,
    },
    "protocol": "http/1.1" if protocol == "http1" else "http/2",
    "repetition": int(repetition),
    "valid": valid,
    "workload": {
        "duration_seconds": measurement_seconds,
        "payload_bytes": payload_bytes,
        "logical_concurrency": logical_concurrency,
        "client_connections": (
            logical_concurrency if protocol == "http1" else http2_connections
        ),
        "parallel_streams_per_connection": (
            1 if protocol == "http1" else http2_parallel
        ),
    },
    "metrics": {
        "successful_rps": request_rate * success_rate,
        "error_rate": error_rate,
        "latency_ms": {
            "p99": float(percentiles["p99"]) * 1000,
            "p999": float(percentiles["p99.9"]) * 1000,
        },
        "gateway_cpu_percent": mean_cpu(gateway_rows),
        "gateway_max_rss_bytes": max(rss_values) * 1024,
        "gateway_max_container_memory_bytes": max(
            int(row["container_memory_bytes"]) for row in gateway_rows
        ),
        "upstream_cpu_percent": mean_cpu(upstream_rows),
        "load_generator_cpu_percent": mean_cpu(loadgen_rows),
        "responses": total_responses,
        "allocator": allocator,
    },
    "resource_samples": sample_counts,
    "status_code_distribution": status_distribution,
    "error_distribution": raw.get("errorDistribution", {}),
    "raw_artifacts": [
        raw_path.removeprefix("/evidence/"),
        stats_path.removeprefix("/evidence/"),
        metrics_before_path.removeprefix("/evidence/"),
        metrics_after_path.removeprefix("/evidence/"),
    ],
}
json.dump(result, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
' "/evidence/$raw_name" "/evidence/$stats_name" \
    "/evidence/$metrics_before_name" "/evidence/$metrics_after_name" \
    "$protocol" "$repetition" "$gateway" "$upstream" "$loadgen_name" \
    "$minimum_resource_samples" "$maximum_error_rate" \
    "$logical_concurrency" "$http2_connections" "$http2_parallel" \
    "$measurement_seconds" "$payload_bytes" >"$evidence_dir/$result_name"

  run_python -c '
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
assert result["valid"], result
metrics = result["metrics"]
latency = metrics["latency_ms"]
print(
    "{:.1f} successful RPS, CPU {:.2f}%, RSS {} bytes, "
    "p99 {:.3f} ms, p99.9 {:.3f} ms, {:.3f} mallocs/response".format(
        metrics["successful_rps"],
        metrics["gateway_cpu_percent"],
        metrics["gateway_max_rss_bytes"],
        latency["p99"],
        latency["p999"],
        metrics["allocator"]["malloc_operations_per_successful_response"],
    )
)
' "/evidence/$result_name"
}

run_measurement() {
  protocol="$1"
  repetition="$2"
  base="$protocol-rep$repetition"
  raw_name="$base.oha.json"
  stderr_name="$base.oha.stderr.txt"
  stats_name="$base.resources.tsv"
  metrics_before_name="$base.metrics-before.prom"
  metrics_after_name="$base.metrics-after.prom"
  result_name="$base.result.json"
  sample_file="$work_dir/docker-stats.sample"
  loadgen="bonvoyage-http2-cost-$protocol-r$repetition-$suffix"

  if [ "$protocol" = "http1" ]; then
    port=8443
    version=1.1
    connections="$logical_concurrency"
    parallel=1
  else
    port=9443
    version=2
    connections="$http2_connections"
    parallel="$http2_parallel"
  fi

  printf 'timestamp_utc\tcontainer\tcpu_percent\tcontainer_memory_bytes\tgateway_rss_kib\n' \
    >"$evidence_dir/$stats_name"
  capture_metrics "$metrics_before_name"

  docker run --detach --name "$loadgen" --platform "$platform" \
    --user "$(id -u):$(id -g)" \
    --network "$network" --read-only \
    --security-opt no-new-privileges:true --cap-drop ALL \
    --volume "$work_dir/client:/tls:ro" "$oha_image_id" \
    -z "${measurement_seconds}s" -c "$connections" -p "$parallel" \
    --wait-ongoing-requests-after-deadline \
    --no-tui --no-color --output-format json \
    --http-version "$version" --disable-compression \
    --connect-timeout 5s -t 10s --cacert /tls/ca.pem \
    "https://api.example.test:$port/payload/$payload_bytes" >/dev/null \
    || fail "could not start $protocol repetition $repetition"

  while [ "$(docker inspect --format '{{.State.Running}}' "$loadgen")" = "true" ]; do
    sample_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    gateway_rss_kib="$(measure_gateway_rss_kib)" \
      || fail "could not capture gateway RSS during $base"
    docker stats --no-stream \
      --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}' \
      "$gateway" "$upstream" "$loadgen" >"$sample_file" 2>/dev/null || true
    if [ "$(docker inspect --format '{{.State.Running}}' "$loadgen")" != "true" ]; then
      continue
    fi
    while IFS='|' read -r sample_name sample_cpu sample_memory; do
      [ -n "$sample_name" ] || continue
      sample_cpu="${sample_cpu%%%}"
      sample_memory="${sample_memory%% / *}"
      sample_memory_bytes="$(memory_to_bytes "$sample_memory")" || continue
      sample_rss=""
      if [ "$sample_name" = "$gateway" ]; then
        sample_rss="$gateway_rss_kib"
      fi
      printf '%s\t%s\t%s\t%s\t%s\n' \
        "$sample_time" "$sample_name" "$sample_cpu" \
        "$sample_memory_bytes" "$sample_rss" \
        >>"$evidence_dir/$stats_name"
    done <"$sample_file"
  done

  loadgen_status="$(docker inspect --format '{{.State.ExitCode}}' "$loadgen")"
  docker logs "$loadgen" >"$evidence_dir/$raw_name" \
    2>"$evidence_dir/$stderr_name"
  docker inspect "$loadgen" >"$evidence_dir/$base.load-generator.inspect.json"
  docker rm "$loadgen" >/dev/null
  loadgen=""
  [ "$loadgen_status" -eq 0 ] \
    || fail "$protocol repetition $repetition exited with status $loadgen_status"

  validate_oha_output "$raw_name" "$maximum_error_rate" \
    || fail "$protocol repetition $repetition returned invalid oha output"
  capture_metrics "$metrics_after_name"
  result_line="$(write_result "$protocol" "$repetition" "$raw_name" \
    "$stats_name" "$metrics_before_name" "$metrics_after_name" \
    "$result_name" "bonvoyage-http2-cost-$protocol-r$repetition-$suffix")" \
    || fail "$protocol repetition $repetition could not be summarized"
  printf '  %s repetition %s: %s\n' "$protocol" "$repetition" "$result_line"

  if [ "$cooldown_seconds" -gt 0 ]; then
    sleep "$cooldown_seconds"
  fi
}

write_summary() {
  run_python_write -c '
import glob
import json
import os
import statistics
import sys

os.umask(0o077)

run_id = sys.argv[1]
expected_repetitions = int(sys.argv[2])
warmup_seconds = int(sys.argv[3])
measurement_seconds = int(sys.argv[4])
logical_concurrency = int(sys.argv[5])
http2_connections = int(sys.argv[6])
http2_parallel = int(sys.argv[7])
payload_bytes = int(sys.argv[8])

def load(protocol):
    paths = sorted(glob.glob(f"/evidence/{protocol}-rep*.result.json"))
    if len(paths) != expected_repetitions:
        raise AssertionError((protocol, len(paths), expected_repetitions))
    values = []
    for path in paths:
        with open(path, encoding="utf-8") as source:
            value = json.load(source)
        if not value["valid"]:
            raise AssertionError(value)
        values.append(value)
    return values

def median(values):
    return statistics.median(values)

def summarize(values):
    rates = [value["metrics"]["successful_rps"] for value in values]
    cpus = [value["metrics"]["gateway_cpu_percent"] for value in values]
    allocators = [value["metrics"]["allocator"] for value in values]
    middle_rate = median(rates)
    return {
        "repetitions": len(values),
        "median_successful_rps": middle_rate,
        "maximum_rps_deviation_from_median_percent": max(
            abs(value - middle_rate) / middle_rate * 100 for value in rates
        ),
        "mean_gateway_cpu_percent": statistics.fmean(cpus),
        "median_cpu_percent_per_1000_successful_rps": median([
            value["metrics"]["gateway_cpu_percent"]
            / (value["metrics"]["successful_rps"] / 1000)
            for value in values
        ]),
        "maximum_gateway_rss_bytes": max(
            value["metrics"]["gateway_max_rss_bytes"] for value in values
        ),
        "median_p99_ms": median([
            value["metrics"]["latency_ms"]["p99"] for value in values
        ]),
        "median_p999_ms": median([
            value["metrics"]["latency_ms"]["p999"] for value in values
        ]),
        "maximum_error_rate": max(
            value["metrics"]["error_rate"] for value in values
        ),
        "maximum_upstream_cpu_percent": max(
            value["metrics"]["upstream_cpu_percent"] for value in values
        ),
        "maximum_load_generator_cpu_percent": max(
            value["metrics"]["load_generator_cpu_percent"] for value in values
        ),
        "allocator": {
            "median_malloc_operations_per_successful_response": median([
                value["malloc_operations_per_successful_response"]
                for value in allocators
            ]),
            "maximum_malloc_operations_per_successful_response": max(
                value["malloc_operations_per_successful_response"]
                for value in allocators
            ),
            "median_free_operations_per_successful_response": median([
                value["free_operations_per_successful_response"]
                for value in allocators
            ]),
            "maximum_absolute_live_objects_delta": max(
                abs(value["live_objects_delta"]) for value in allocators
            ),
            "maximum_absolute_allocated_memory_delta_bytes": max(
                abs(value["allocated_memory_delta_bytes"])
                for value in allocators
            ),
            "total_failed_allocations": sum(
                value["failed_allocations_delta"] for value in allocators
            ),
            "total_oversized_allocations": sum(
                value["oversized_allocations_delta"] for value in allocators
            ),
            "total_reclaim_operations": sum(
                value["reclaim_operations_delta"] for value in allocators
            ),
            "total_cross_shard_free_operations": sum(
                value["cross_shard_free_operations_delta"]
                for value in allocators
            ),
        },
    }

http1 = summarize(load("http1"))
http2 = summarize(load("http2"))
summary = {
    "schema_version": 1,
    "run_id": run_id,
    "evidence": {
        "class": "local-engineering",
        "publishable": False,
        "marketing_use_authorized": False,
        "claim": "Local protocol-cost observation only",
    },
    "controls": {
        "gateway_shards": 1,
        "gateway_docker_cpu_limit": 1,
        "same_gateway_process": True,
        "same_tls_certificate_and_hostname": True,
        "same_route_and_controlled_upstream": True,
        "warmup_seconds_per_protocol": warmup_seconds,
        "measurement_seconds_per_repetition": measurement_seconds,
        "logical_concurrency": logical_concurrency,
        "http1_connections": logical_concurrency,
        "http2_connections": http2_connections,
        "http2_parallel_streams_per_connection": http2_parallel,
        "payload_bytes": payload_bytes,
        "order": "alternating by repetition",
    },
    "protocols": {"http1": http1, "http2": http2},
    "observed_comparison": {
        "http2_to_http1_successful_rps_ratio": (
            http2["median_successful_rps"] / http1["median_successful_rps"]
        ),
        "http2_to_http1_mean_gateway_cpu_ratio": (
            http2["mean_gateway_cpu_percent"] / http1["mean_gateway_cpu_percent"]
        ),
        "http2_to_http1_cpu_cost_per_1000_rps_ratio": (
            http2["median_cpu_percent_per_1000_successful_rps"]
            / http1["median_cpu_percent_per_1000_successful_rps"]
        ),
        "http2_to_http1_p99_ratio": (
            http2["median_p99_ms"] / http1["median_p99_ms"]
        ),
        "http2_to_http1_p999_ratio": (
            http2["median_p999_ms"] / http1["median_p999_ms"]
        ),
        "http2_to_http1_malloc_operations_per_response_ratio": (
            http2["allocator"][
                "median_malloc_operations_per_successful_response"
            ]
            / http1["allocator"][
                "median_malloc_operations_per_successful_response"
            ]
        ),
        "http2_minus_http1_malloc_operations_per_response": (
            http2["allocator"][
                "median_malloc_operations_per_successful_response"
            ]
            - http1["allocator"][
                "median_malloc_operations_per_successful_response"
            ]
        ),
    },
    "limitations": [
        "Local Docker scheduling and shared-host noise are not controlled.",
        "The load generator and controlled upstream share the local Docker runtime.",
        "The HTTP/2 topology uses equal logical concurrency with multiplexed streams.",
        "Allocator deltas cover the complete live gateway path, including protocol and connection lifecycle; they are not a libnghttp2-only microbenchmark.",
        "One metrics scrape occurs at each measurement boundary; its fixed allocator cost is not subtracted and is amortized over all successful responses.",
        "These observations cannot support marketing, customer, or competitive claims.",
    ],
}
with open("/evidence/summary.json", "w", encoding="utf-8") as output:
    json.dump(summary, output, indent=2, sort_keys=True)
    output.write("\n")
' "$run_id" "$repetitions" "$warmup_seconds" "$measurement_seconds" \
    "$logical_concurrency" "$http2_connections" "$http2_parallel" \
    "$payload_bytes"

  run_python -c '
import json
import sys

with open("/evidence/summary.json", encoding="utf-8") as source:
    summary = json.load(source)
print("protocol,median_successful_rps,mean_gateway_cpu_percent,maximum_gateway_rss_bytes,median_p99_ms,median_p999_ms,median_malloc_operations_per_successful_response,maximum_absolute_live_objects_delta,maximum_error_rate")
for protocol in ("http1", "http2"):
    value = summary["protocols"][protocol]
    print(
        "{},{:.6f},{:.6f},{},{:.6f},{:.6f},{:.9f},{},{:.9f}".format(
            protocol,
            value["median_successful_rps"],
            value["mean_gateway_cpu_percent"],
            value["maximum_gateway_rss_bytes"],
            value["median_p99_ms"],
            value["median_p999_ms"],
            value["allocator"][
                "median_malloc_operations_per_successful_response"
            ],
            value["allocator"]["maximum_absolute_live_objects_delta"],
            value["maximum_error_rate"],
        )
    )
' >"$evidence_dir/summary.csv"

  run_python -c '
import json

with open("/evidence/summary.json", encoding="utf-8") as source:
    summary = json.load(source)
print("LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE")
for protocol in ("http1", "http2"):
    value = summary["protocols"][protocol]
    print(
        "{}: median {:.1f} successful RPS; mean gateway CPU {:.2f}%; "
        "max RSS {} bytes; median p99 {:.3f} ms; median p99.9 {:.3f} ms; "
        "median {:.3f} mallocs/successful response; max absolute live-object delta {}".format(
            protocol,
            value["median_successful_rps"],
            value["mean_gateway_cpu_percent"],
            value["maximum_gateway_rss_bytes"],
            value["median_p99_ms"],
            value["median_p999_ms"],
            value["allocator"][
                "median_malloc_operations_per_successful_response"
            ],
            value["allocator"]["maximum_absolute_live_objects_delta"],
        )
    )
comparison = summary["observed_comparison"]
print(
    "Observed HTTP/2 to HTTP/1 ratios: "
    "RPS {:.3f}; CPU {:.3f}; CPU cost/1000 RPS {:.3f}; "
    "p99 {:.3f}; p99.9 {:.3f}; mallocs/response {:.3f} ({:+.3f})".format(
        comparison["http2_to_http1_successful_rps_ratio"],
        comparison["http2_to_http1_mean_gateway_cpu_ratio"],
        comparison["http2_to_http1_cpu_cost_per_1000_rps_ratio"],
        comparison["http2_to_http1_p99_ratio"],
        comparison["http2_to_http1_p999_ratio"],
        comparison["http2_to_http1_malloc_operations_per_response_ratio"],
        comparison["http2_minus_http1_malloc_operations_per_response"],
    )
)
' >"$evidence_dir/summary.txt"

  {
    printf '# BonVoyage Local TLS Protocol-Cost Evidence\n\n'
    printf '**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** Do not use these results for marketing, customer-facing, or competitive claims.\n\n'
    printf 'This run compares downstream TLS HTTP/1.1 and HTTP/2 on one BonVoyage process constrained to one Docker CPU and one Seastar shard. Both listeners use the same certificate, hostname, virtual host, route, controlled upstream, and payload. Protocol order alternates between repetitions. Live Seastar allocator counters are sampled immediately before and after every measurement and normalized by successful HTTP 200 responses.\n\n'
    printf '```text\n'
    cat "$evidence_dir/summary.txt"
    printf '```\n\n'
    printf '%s\n' "The complete machine-readable result is in \`summary.json\`; raw oha output, resource samples, metrics, image identities, source inputs, and checksums are retained alongside it. Shared-host and local Docker effects make this evidence suitable for engineering decisions only."
  } >"$evidence_dir/README.md"
}

for command_name in \
  awk cat chmod cp date docker find git grep id mktemp mv openssl rm sleep sort uname; do
  require_command "$command_name"
done
if command -v sha256sum >/dev/null 2>&1; then
  checksum_tool="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  checksum_tool="shasum"
else
  fail "either sha256sum or shasum is required"
fi

require_positive_integer BONVOYAGE_HTTP2_COST_WARMUP_SECONDS "$warmup_seconds"
require_positive_integer BONVOYAGE_HTTP2_COST_MEASUREMENT_SECONDS "$measurement_seconds"
require_positive_integer BONVOYAGE_HTTP2_COST_REPETITIONS "$repetitions"
require_nonnegative_integer BONVOYAGE_HTTP2_COST_COOLDOWN_SECONDS "$cooldown_seconds"
require_positive_integer BONVOYAGE_HTTP2_COST_CONCURRENCY "$logical_concurrency"
require_positive_integer BONVOYAGE_HTTP2_COST_HTTP2_CONNECTIONS "$http2_connections"
require_positive_integer BONVOYAGE_HTTP2_COST_HTTP2_PARALLEL "$http2_parallel"
require_positive_integer BONVOYAGE_HTTP2_COST_PAYLOAD_BYTES "$payload_bytes"
require_positive_integer BONVOYAGE_HTTP2_COST_MIN_RESOURCE_SAMPLES "$minimum_resource_samples"
require_rate BONVOYAGE_HTTP2_COST_MAX_ERROR_RATE "$maximum_error_rate"

[ "$repetitions" -ge 2 ] \
  || fail "BONVOYAGE_HTTP2_COST_REPETITIONS must be at least two"
[ "$payload_bytes" -le 1048576 ] \
  || fail "BONVOYAGE_HTTP2_COST_PAYLOAD_BYTES must not exceed 1048576"
[ $((http2_connections * http2_parallel)) -eq "$logical_concurrency" ] \
  || fail "HTTP/2 connections multiplied by parallel streams must equal logical concurrency"
[ -f "$fixture" ] || fail "fixture is missing: $fixture"
case "$oha_image" in
  *@sha256:*) ;;
  *) fail "BONVOYAGE_OHA_IMAGE must use an immutable sha256 digest" ;;
esac

if [ -e "$evidence_dir" ]; then
  fail "evidence directory already exists: $evidence_dir"
fi
mkdir -p "$evidence_dir" || fail "could not create evidence directory"
evidence_dir="$(CDPATH='' cd -- "$evidence_dir" && pwd)"
evidence_ready=1
mkdir -p "$work_dir/client" "$work_dir/secrets"

docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"
dataplane_image_id="$(docker image inspect --format '{{.Id}}' "$dataplane_image")" \
  || fail "dataplane image is unavailable: $dataplane_image"
compiler_image_id="$(docker image inspect --format '{{.Id}}' "$compiler_image")" \
  || fail "snapshot compiler image is unavailable: $compiler_image"
upstream_image_id="$(docker image inspect --format '{{.Id}}' "$upstream_image")" \
  || fail "controlled upstream image is unavailable: $upstream_image"
oha_image_id="$(docker image inspect --format '{{.Id}}' "$oha_image")" \
  || fail "pinned oha image is unavailable: $oha_image"

# Run-private tags keep the captured image identities reachable even when a
# concurrent local build replaces one of the mutable development tags.
docker image tag "$dataplane_image_id" "$dataplane_run_image" \
  || fail "could not lock the dataplane image for this run"
docker image tag "$compiler_image_id" "$compiler_run_image" \
  || fail "could not lock the compiler image for this run"
docker image tag "$upstream_image_id" "$upstream_run_image" \
  || fail "could not lock the upstream image for this run"

if [ -z "$platform" ]; then
  platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$dataplane_image_id")"
fi
for image_id in "$dataplane_image_id" "$compiler_image_id" "$upstream_image_id" "$oha_image_id"; do
  image_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image_id")"
  [ "$image_platform" = "$platform" ] \
    || fail "image $image_id is $image_platform but the requested platform is $platform"
done

printf '%s\n' \
  'LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE' \
  'This output is not authorized for marketing, customer-facing, or competitive claims.' \
  'Use a controlled native Linux host and the publishable benchmark gate for external claims.' \
  >"$evidence_dir/NOTICE.txt"
printf '%s\n' \
  '{' \
  '  "evidence_class": "local-engineering",' \
  '  "publishable": false,' \
  '  "marketing_use_authorized": false,' \
  '  "purpose": "downstream TLS HTTP/1.1 versus HTTP/2 protocol and allocation-cost observation"' \
  '}' >"$evidence_dir/classification.json"

cp "$fixture" "$evidence_dir/phase3-http2-cost.yaml"
cp "$script_dir/phase3-http2-cost.sh" "$evidence_dir/harness.sh"
cp "$script_dir/test-fixture-secrets.sh" "$evidence_dir/test-fixture-secrets.sh"
docker image inspect \
  "$dataplane_image_id" "$compiler_image_id" "$upstream_image_id" "$oha_image_id" \
  >"$evidence_dir/images.inspect.json"
docker run --rm --platform "$platform" --network none "$oha_image_id" --version \
  >"$evidence_dir/oha-version.txt" 2>&1 \
  || fail "could not execute the pinned oha client"

{
  printf 'run_id=%s\n' "$run_id"
  printf 'started_at_utc=%s\n' "$started_at"
  printf 'evidence_class=local-engineering\n'
  printf 'publishable=false\n'
  printf 'marketing_use_authorized=false\n'
  printf 'git_commit=%s\n' "$(git rev-parse HEAD)"
  printf 'git_status_begin\n'
  git status --short
  printf 'git_status_end\n'
  printf 'platform=%s\n' "$platform"
  printf 'fixture_sha256=%s\n' "$(checksum_value "$fixture")"
  printf 'fixture_helper_sha256=%s\n' "$(checksum_value "$script_dir/test-fixture-secrets.sh")"
  printf 'harness_sha256=%s\n' "$(checksum_value "$script_dir/phase3-http2-cost.sh")"
  printf 'dataplane_image_ref=%s\n' "$dataplane_image"
  printf 'dataplane_image_id=%s\n' "$dataplane_image_id"
  printf 'compiler_image_ref=%s\n' "$compiler_image"
  printf 'compiler_image_id=%s\n' "$compiler_image_id"
  printf 'upstream_image_ref=%s\n' "$upstream_image"
  printf 'upstream_image_id=%s\n' "$upstream_image_id"
  printf 'oha_image_ref=%s\n' "$oha_image"
  printf 'oha_image_id=%s\n' "$oha_image_id"
  printf 'gateway_shards=1\n'
  printf 'gateway_docker_cpu_limit=1\n'
  printf 'warmup_seconds=%s\n' "$warmup_seconds"
  printf 'measurement_seconds=%s\n' "$measurement_seconds"
  printf 'repetitions=%s\n' "$repetitions"
  printf 'cooldown_seconds=%s\n' "$cooldown_seconds"
  printf 'logical_concurrency=%s\n' "$logical_concurrency"
  printf 'http1_connections=%s\n' "$logical_concurrency"
  printf 'http2_connections=%s\n' "$http2_connections"
  printf 'http2_parallel_streams=%s\n' "$http2_parallel"
  printf 'payload_bytes=%s\n' "$payload_bytes"
  printf 'maximum_error_rate=%s\n' "$maximum_error_rate"
  printf 'allocator_metric_source=live Seastar shard allocator counters\n'
  printf 'host=%s\n' "$(uname -a)"
  docker version
} >"$evidence_dir/environment.txt" 2>&1
docker info >"$evidence_dir/docker-info.txt" 2>&1

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage HTTP2 Cost CA" \
  -keyout "$work_dir/ca-key.pem" -out "$work_dir/client/ca.pem" \
  >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=api.example.test" \
  -keyout "$work_dir/secrets/server-key.pem" -out "$work_dir/server.csr" \
  >/dev/null 2>&1
printf '%s\n' \
  'subjectAltName=DNS:api.example.test' \
  'extendedKeyUsage=serverAuth' \
  'keyUsage=digitalSignature,keyEncipherment' >"$work_dir/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work_dir/server.csr" \
  -CA "$work_dir/client/ca.pem" -CAkey "$work_dir/ca-key.pem" \
  -CAcreateserial -extfile "$work_dir/server-ext.cnf" \
  -out "$work_dir/secrets/server-chain.pem" >/dev/null 2>&1
chmod 600 "$work_dir/ca-key.pem" "$work_dir/secrets/server-key.pem"

bv_stage_fixture_secrets "$secret_volume" "$work_dir/secrets" "$upstream_image_id" "$platform" \
  server-chain.pem server-key.pem
cp "$work_dir/client/ca.pem" "$evidence_dir/ephemeral-ca.pem"
cp "$work_dir/secrets/server-chain.pem" "$evidence_dir/ephemeral-server-chain.pem"
openssl x509 -in "$work_dir/secrets/server-chain.pem" -noout \
  -fingerprint -sha256 -serial -dates -subject -issuer \
  >"$evidence_dir/ephemeral-certificate.txt"

docker network create --internal "$network" >/dev/null \
  || fail "could not create the isolated Docker network"
docker volume create "$volume" >/dev/null \
  || fail "could not create the snapshot volume"

docker run --rm --platform "$platform" --network none --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$fixture:/etc/bonvoyage/http2-cost.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_run_image" -input /etc/bonvoyage/http2-cost.yaml \
  -output /var/lib/bonvoyage/snapshot.pb \
  >"$evidence_dir/snapshot-compiler.log" 2>&1 \
  || fail "snapshot compilation failed"
docker run --rm --platform "$platform" --network none --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$volume:/snapshot:ro" --entrypoint python "$upstream_run_image" \
  -c 'import sys; sys.stdout.buffer.write(open("/snapshot/snapshot.pb", "rb").read())' \
  >"$evidence_dir/snapshot.pb" \
  || fail "could not retain the compiled snapshot"

docker run --detach --platform "$platform" --name "$upstream" \
  --user "$(id -u):$(id -g)" \
  --network "$network" --network-alias upstream --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$work_dir/client:/tls:ro" "$upstream_run_image" >/dev/null \
  || fail "could not start the controlled upstream"
attempt=0
until docker exec "$upstream" python -c \
  'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:8081/healthz", timeout=1).status == 200' \
  >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 30 ] || fail "controlled upstream did not become healthy"
  sleep 1
done

docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test --dns-search . --read-only \
  --cpus 1 --memory 512m \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
  "$dataplane_run_image" --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 256M --overprovisioned \
  --logger-log-level bonvoyage-gateway=info >/dev/null \
  || fail "could not start the one-core BonVoyage dataplane"
bv_wait_gateway_ready "$gateway" "$upstream" "http://$gateway:9901/health/ready"

docker inspect --format \
  'container={{.Name}} nano_cpus={{.HostConfig.NanoCpus}} cpu_quota={{.HostConfig.CpuQuota}} cpu_period={{.HostConfig.CpuPeriod}}' \
  "$gateway" >"$evidence_dir/gateway-cpu-verification.txt"
grep -Eq 'nano_cpus=1000000000|cpu_quota=100000' \
  "$evidence_dir/gateway-cpu-verification.txt" \
  || fail "Docker did not retain the one-CPU gateway limit"

docker exec "$upstream" python -c '
import socket
import ssl

context = ssl.create_default_context(cafile="/tls/ca.pem")
for port, offered, expected in (
    (8443, ["http/1.1"], "http/1.1"),
    (9443, ["h2"], "h2"),
):
    context.set_alpn_protocols(offered)
    with socket.create_connection(("api.example.test", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="api.example.test") as secure:
            selected = secure.selected_alpn_protocol()
            assert selected == expected, (port, selected, expected)
            subject = secure.getpeercert().get("subject")
            print(f"port={port} expected={expected} selected={selected} peer={subject}")
' >"$evidence_dir/alpn-verification.txt" \
  || fail "TLS identity and ALPN verification failed"

capture_metrics metrics-before.prom
printf 'Warming HTTP/1.1 for %ss...\n' "$warmup_seconds"
run_oha_foreground http1 "$warmup_seconds" \
  http1-warmup.oha.json http1-warmup.oha.stderr.txt \
  || fail "HTTP/1.1 warm-up failed"
validate_oha_output http1-warmup.oha.json 0 \
  || fail "HTTP/1.1 warm-up did not complete without errors"

printf 'Warming HTTP/2 for %ss...\n' "$warmup_seconds"
run_oha_foreground http2 "$warmup_seconds" \
  http2-warmup.oha.json http2-warmup.oha.stderr.txt \
  || fail "HTTP/2 warm-up failed"
validate_oha_output http2-warmup.oha.json 0 \
  || fail "HTTP/2 warm-up did not complete without errors"
if [ "$cooldown_seconds" -gt 0 ]; then
  sleep "$cooldown_seconds"
fi

repetition=1
while [ "$repetition" -le "$repetitions" ]; do
  if [ $((repetition % 2)) -eq 1 ]; then
    order="http1 http2"
  else
    order="http2 http1"
  fi
  printf 'Repetition %s/%s, order: %s\n' "$repetition" "$repetitions" "$order"
  for protocol in $order; do
    run_measurement "$protocol" "$repetition"
  done
  repetition=$((repetition + 1))
done

capture_metrics metrics-after.prom
write_summary
cat "$evidence_dir/summary.txt"
