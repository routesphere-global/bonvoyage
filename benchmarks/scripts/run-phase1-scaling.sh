#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
cd "$repo_root"

workload_id="http1-keepalive-phase1-scaling"
dataplane_image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:phase1-benchmark}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-benchmark-upstream:phase1}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
gateway_one_cpus="${BONVOYAGE_GATEWAY_ONE_CPUS:-2}"
gateway_two_cpus="${BONVOYAGE_GATEWAY_TWO_CPUS:-2,3}"
load_generator_cpus="${BONVOYAGE_LOAD_GENERATOR_CPUS:-4-7}"
upstream_cpus="${BONVOYAGE_UPSTREAM_CPUS:-8-11}"
irq_cpus="${BONVOYAGE_IRQ_CPUS:-not-isolated-local-qualification}"
one_concurrency="${BONVOYAGE_ONE_CORE_CONCURRENCY:-64}"
two_concurrency="${BONVOYAGE_TWO_CORE_CONCURRENCY:-128}"
warmup_seconds="${BONVOYAGE_BENCH_WARMUP_SECONDS:-30}"
measurement_seconds="${BONVOYAGE_BENCH_MEASUREMENT_SECONDS:-30}"
repetitions="${BONVOYAGE_BENCH_REPETITIONS:-5}"
cooldown_seconds="${BONVOYAGE_BENCH_COOLDOWN_SECONDS:-3}"
upstream_capacity_seconds="${BONVOYAGE_UPSTREAM_CAPACITY_SECONDS:-10}"
latency_ceiling_ms="${BONVOYAGE_LATENCY_CEILING_MS:-4.0}"
minimum_scaling_ratio="${BONVOYAGE_MINIMUM_SCALING_RATIO:-1.8}"
maximum_error_rate="${BONVOYAGE_MAXIMUM_ERROR_RATE:-0.001}"
maximum_variation_percent="${BONVOYAGE_MAXIMUM_VARIATION_PERCENT:-5.0}"
minimum_headroom_ratio="${BONVOYAGE_MINIMUM_HEADROOM_RATIO:-1.2}"
maximum_support_role_capacity_percent="${BONVOYAGE_MAXIMUM_SUPPORT_ROLE_CAPACITY_PERCENT:-80.0}"
minimum_resource_samples="${BONVOYAGE_MINIMUM_RESOURCE_SAMPLES:-3}"
require_local_gate="${BONVOYAGE_REQUIRE_LOCAL_GATE:-1}"
skip_build="${BONVOYAGE_SKIP_BUILD:-0}"
publishable_request="${BONVOYAGE_PUBLISHABLE:-0}"
qualification_attestation="${BONVOYAGE_QUALIFICATION_ATTESTATION:-}"
network_mode="${BONVOYAGE_NETWORK_MODE:-loopback}"
network_nic="${BONVOYAGE_NETWORK_NIC:-lo}"
network_speed_mbps="${BONVOYAGE_NETWORK_SPEED_MBPS:-100000}"
network_mtu="${BONVOYAGE_NETWORK_MTU:-65536}"

fail() {
  echo "phase1-scaling: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command '$1' is unavailable"
}

require_positive_integer() {
  case "$2" in
    ''|*[!0-9]*) fail "$1 must be a positive integer" ;;
  esac
  [ "$2" -gt 0 ] || fail "$1 must be a positive integer"
}

expand_cpu_set() {
  printf '%s\n' "$1" | awk -F, '
    {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^[0-9]+$/) {
          print $i
        } else if (split($i, range, "-") == 2 &&
                   range[1] ~ /^[0-9]+$/ && range[2] ~ /^[0-9]+$/ &&
                   range[1] <= range[2]) {
          for (cpu = range[1]; cpu <= range[2]; cpu++) {
            print cpu
          }
        } else {
          exit 2
        }
      }
    }
  '
}

assert_disjoint() {
  disjoint_file="$(mktemp)"
  for disjoint_assignment in "$@"; do
    disjoint_label="${disjoint_assignment%%=*}"
    disjoint_set="${disjoint_assignment#*=}"
    disjoint_expanded="$(expand_cpu_set "$disjoint_set")" || {
      rm -f "$disjoint_file"
      fail "invalid CPU set '$disjoint_set' for $disjoint_label"
    }
    printf '%s\n' "$disjoint_expanded" | awk -v label="$disjoint_label" \
      '{ print $1 " " label }' >>"$disjoint_file"
  done

  disjoint_conflict="$(sort -n "$disjoint_file" | awk '
    seen[$1] { print "CPU " $1 " is shared by " owner[$1] " and " $2; exit }
    { seen[$1] = 1; owner[$1] = $2 }
  ')"
  rm -f "$disjoint_file"
  [ -z "$disjoint_conflict" ] || fail "$disjoint_conflict"
}

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

container_process_rss_bytes() {
  [ "$(uname -s)" = "Linux" ] || return 1
  process_rss_pids="$(docker top "$1" -eo pid 2>/dev/null | \
    awk 'NR > 1 && $1 ~ /^[0-9]+$/ {print $1}')"
  [ -n "$process_rss_pids" ] || return 1

  process_rss_total_kib=0
  process_rss_found=0
  for process_rss_pid in $process_rss_pids; do
    process_rss_kib="$(awk '/^VmRSS:/ {print $2; found = 1}
      END {if (!found) exit 1}' "/proc/$process_rss_pid/status" \
      2>/dev/null)" || continue
    process_rss_total_kib=$((process_rss_total_kib + process_rss_kib))
    process_rss_found=$((process_rss_found + 1))
  done
  [ "$process_rss_found" -gt 0 ] || return 1
  printf '%s\n' "$((process_rss_total_kib * 1024))"
}

wait_for_url() {
  wait_url="$1"
  wait_name="$2"
  wait_attempt=0
  until fetch_url "$wait_url" >/dev/null 2>&1; do
    wait_attempt=$((wait_attempt + 1))
    if [ "$wait_attempt" -ge 30 ]; then
      echo "$wait_name did not become ready at $wait_url" >&2
      return 1
    fi
    sleep 1
  done
}

fetch_url() {
  docker run --rm \
    --network host \
    --cpuset-cpus "$load_generator_cpus" \
    --entrypoint /usr/bin/wget \
    "$upstream_image" \
    -q -O - "$1"
}

[ -r "$script_dir/phase1-accounting.jq" ] || \
  fail "missing phase1-accounting.jq; deploy the complete benchmark source checkout"

for command_name in awk date docker go grep jq shasum; do
  require_command "$command_name"
done

require_positive_integer "BONVOYAGE_ONE_CORE_CONCURRENCY" "$one_concurrency"
require_positive_integer "BONVOYAGE_TWO_CORE_CONCURRENCY" "$two_concurrency"
require_positive_integer "BONVOYAGE_BENCH_WARMUP_SECONDS" "$warmup_seconds"
require_positive_integer "BONVOYAGE_BENCH_MEASUREMENT_SECONDS" "$measurement_seconds"
require_positive_integer "BONVOYAGE_BENCH_REPETITIONS" "$repetitions"
require_positive_integer "BONVOYAGE_UPSTREAM_CAPACITY_SECONDS" "$upstream_capacity_seconds"
require_positive_integer "BONVOYAGE_MINIMUM_RESOURCE_SAMPLES" "$minimum_resource_samples"

gateway_one_cpu_count="$(expand_cpu_set "$gateway_one_cpus" | wc -l | tr -d ' ')"
gateway_two_cpu_count="$(expand_cpu_set "$gateway_two_cpus" | wc -l | tr -d ' ')"
load_generator_cpu_count="$(expand_cpu_set "$load_generator_cpus" | wc -l | tr -d ' ')"
upstream_cpu_count="$(expand_cpu_set "$upstream_cpus" | wc -l | tr -d ' ')"
[ "$gateway_one_cpu_count" -eq 1 ] || \
  fail "the one-core CPU set must contain exactly one CPU"
[ "$gateway_two_cpu_count" -eq 2 ] || \
  fail "the two-core CPU set must contain exactly two CPUs"
assert_disjoint \
  "gateway=$gateway_one_cpus" \
  "load-generator=$load_generator_cpus" \
  "upstream=$upstream_cpus"
assert_disjoint \
  "gateway=$gateway_two_cpus" \
  "load-generator=$load_generator_cpus" \
  "upstream=$upstream_cpus"

docker_server_arch="$(docker info --format '{{.Architecture}}')"
docker_cpus="$(docker info --format '{{.NCPU}}')"
case "$docker_server_arch" in
  x86_64|amd64) platform="linux/amd64"; manifest_arch="x86_64" ;;
  aarch64|arm64) platform="linux/arm64"; manifest_arch="aarch64" ;;
  *) fail "unsupported Docker server architecture '$docker_server_arch'" ;;
esac

highest_cpu="$({
  expand_cpu_set "$gateway_two_cpus"
  expand_cpu_set "$load_generator_cpus"
  expand_cpu_set "$upstream_cpus"
} | sort -n | tail -n 1)"
[ "$highest_cpu" -lt "$docker_cpus" ] || \
  fail "CPU $highest_cpu is outside the Docker server's $docker_cpus logical CPUs"

git_commit="${BONVOYAGE_GIT_COMMIT:-$(git rev-parse HEAD 2>/dev/null || true)}"
printf '%s\n' "$git_commit" | grep -Eq '^[0-9a-f]{40}$' || \
  fail "a 40-character Git commit is required"
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git_dirty=true
elif [ -n "$(git status --porcelain 2>/dev/null || true)" ]; then
  git_dirty=true
else
  git_dirty=false
fi

captured_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
run_stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
run_id="phase1-scaling-$run_stamp"
raw_relative="benchmarks/results/raw/$run_id"
report_relative="benchmarks/results/reports/$run_id.md"
raw_dir="$repo_root/$raw_relative"
report_path="$repo_root/$report_relative"
mkdir -p "$raw_dir" "$(dirname "$report_path")"

suffix="$$-$run_stamp"
upstream_name="bonvoyage-p1-upstream-$suffix"
gateway_name=""
loadgen_name=""
extract_name=""

cleanup() {
  set +e
  [ -z "$loadgen_name" ] || docker rm --force "$loadgen_name" >/dev/null 2>&1
  [ -z "$gateway_name" ] || docker rm --force "$gateway_name" >/dev/null 2>&1
  [ -z "$upstream_name" ] || docker rm --force "$upstream_name" >/dev/null 2>&1
  [ -z "$extract_name" ] || docker rm --force "$extract_name" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

if [ "$skip_build" != "1" ]; then
  echo "Building native $platform benchmark images..."
  docker buildx build \
    --platform "$platform" \
    --load \
    --build-arg "BUILD_JOBS=${BONVOYAGE_BUILD_JOBS:-2}" \
    --target runtime \
    --tag "$dataplane_image" \
    --file deploy/docker/bonvoyage/Dockerfile \
    .
  docker buildx build \
    --platform "$platform" \
    --load \
    --tag "$upstream_image" \
    benchmarks/products/upstream
fi

snapshot_path="$raw_dir/snapshot.pb"
(
  cd control-plane
  go run ./cmd/bonvoyage-control-plane \
    -input ../benchmarks/products/bonvoyage/host-network.yaml \
    -output "$snapshot_path"
)
snapshot_sha256="$(shasum -a 256 "$snapshot_path" | awk '{print $1}')"

dataplane_image_id="$(docker image inspect --format '{{.Id}}' "$dataplane_image")"
dataplane_version="$(docker image inspect \
  --format '{{index .Config.Labels "org.opencontainers.image.version"}}' \
  "$dataplane_image")"
case "$dataplane_image_id" in sha256:[0-9a-f]*) ;; *) fail "invalid dataplane image ID" ;; esac

extract_name="bonvoyage-p1-extract-$suffix"
docker create --name "$extract_name" "$dataplane_image" --version >/dev/null
docker cp "$extract_name:/usr/local/bin/bonvoyage-dataplane" \
  "$raw_dir/.bonvoyage-dataplane" >/dev/null
dataplane_executable_sha256="$(shasum -a 256 "$raw_dir/.bonvoyage-dataplane" | awk '{print $1}')"
docker rm "$extract_name" >/dev/null
extract_name=""
rm -f "$raw_dir/.bonvoyage-dataplane"

docker run --detach \
  --name "$upstream_name" \
  --network host \
  --cpuset-cpus "$upstream_cpus" \
  --memory 512m \
  --memory-swap 512m \
  --ulimit nofile=1048576:1048576 \
  "$upstream_image" >/dev/null
if ! wait_for_url "http://127.0.0.1:8081/healthz" "controlled upstream"; then
  docker logs "$upstream_name" >&2 || true
  fail "controlled upstream startup failed"
fi

fetch_url http://127.0.0.1:8081/payload/256 \
  >"$raw_dir/controlled-upstream.payload"
[ "$(wc -c <"$raw_dir/controlled-upstream.payload" | tr -d ' ')" -eq 256 ] || \
  fail "controlled upstream returned the wrong payload size"
[ "$(shasum -a 256 "$raw_dir/controlled-upstream.payload" | awk '{print $1}')" = \
  "85e62acd750c4eb56b7b6a1d66dca5bfaac5f062608a1a893410d0288936c09a" ] || \
  fail "controlled upstream returned the wrong payload digest"

echo "Measuring direct upstream and load-generator headroom..."
docker run --rm \
  --network host \
  --cpuset-cpus "$load_generator_cpus" \
  "$oha_image" \
  -z "${upstream_capacity_seconds}s" \
  -c "$two_concurrency" \
  --no-tui \
  --output-format json \
  http://127.0.0.1:8081/payload/256 \
  >"$raw_dir/upstream-capacity.oha.json"
jq --argjson concurrency "$two_concurrency" \
  --argjson expected_duration "$upstream_capacity_seconds" \
  -f "$script_dir/phase1-accounting.jq" \
  "$raw_dir/upstream-capacity.oha.json" \
  >"$raw_dir/upstream-capacity.accounting.json" || \
  fail "direct upstream capacity accounting failed"
jq -e '.successful_rps > 0 and .error_rate == 0' \
  "$raw_dir/upstream-capacity.accounting.json" >/dev/null || \
  fail "direct upstream capacity preflight failed"
upstream_capacity_rps="$(jq -r '.successful_rps' \
  "$raw_dir/upstream-capacity.accounting.json")"

docker_os="$(docker info --format '{{.OperatingSystem}}')"
docker_kernel="$(docker info --format '{{.KernelVersion}}')"
docker_memory="$(docker info --format '{{.MemTotal}}')"
docker_engine_version="$(docker version --format '{{.Server.Version}}')"
cpu_model="$(docker run --rm --entrypoint /bin/sh "$upstream_image" -c \
  'awk -F: '\''/model name|Hardware|Processor/ { sub(/^[[:space:]]+/, "", $2); if ($2 != "") { print $2; exit } }'\'' /proc/cpuinfo')"
[ -n "$cpu_model" ] || cpu_model="unavailable in container runtime"

evidence_class="local-functional"
publication_authorized=false
publication_reason="local or virtualized evidence is not a publishable performance claim"
if [ "$publishable_request" = "1" ]; then
  [ "$(uname -s)" = "Linux" ] || \
    fail "publishable mode requires a native Linux host"
  [ "$git_dirty" = "false" ] || \
    fail "publishable mode requires a clean Git tree"
  [ "$irq_cpus" != "not-isolated-local-qualification" ] || \
    fail "publishable mode requires an explicit IRQ CPU allocation"
  [ "$qualification_attestation" = "fairness-contract-reviewed" ] || \
    fail "publishable mode requires BONVOYAGE_QUALIFICATION_ATTESTATION=fairness-contract-reviewed"
  evidence_class="native-qualification"
  publication_authorized=true
  publication_reason="operator attested the native Linux host against the benchmark fairness contract"
fi

environment_path="$raw_dir/phase1-scaling.environment.json"
jq -n \
  --arg captured_at "$captured_at" \
  --arg commit "$git_commit" \
  --argjson dirty "$git_dirty" \
  --arg os "$docker_os" \
  --arg kernel "$docker_kernel" \
  --arg architecture "$manifest_arch" \
  --arg cpu_model "$cpu_model" \
  --argjson logical_cpus "$docker_cpus" \
  --argjson memory_bytes "$docker_memory" \
  --arg mode "$network_mode" \
  --arg nic "$network_nic" \
  --argjson link_speed_mbps "$network_speed_mbps" \
  --argjson mtu "$network_mtu" \
  --arg engine_version "$docker_engine_version" \
  --arg load_generator "$load_generator_cpus" \
  --arg gateway "1 core: $gateway_one_cpus; 2 cores: $gateway_two_cpus" \
  --arg upstream "$upstream_cpus" \
  --arg irq "$irq_cpus" \
  '{
    schema_version: 1,
    captured_at: $captured_at,
    git: {commit: $commit, dirty: $dirty},
    host: {
      os: $os,
      kernel: $kernel,
      architecture: $architecture,
      cpu_model: $cpu_model,
      logical_cpus: $logical_cpus,
      memory_bytes: $memory_bytes
    },
    network: {
      mode: $mode,
      nic: $nic,
      link_speed_mbps: $link_speed_mbps,
      mtu: $mtu
    },
    runtime: {container_engine: "docker", engine_version: $engine_version},
    cpu_allocation: {
      load_generator: $load_generator,
      gateway: $gateway,
      upstream: $upstream,
      irq: $irq
    }
  }' >"$environment_path"
environment_sha256="$(shasum -a 256 "$environment_path" | awk '{print $1}')"

run_measurement() {
  measurement_cores="$1"
  measurement_concurrency="$2"
  measurement_repetition="$3"
  measurement_started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  measurement_base="bonvoyage-${measurement_cores}core-rep${measurement_repetition}"
  measurement_raw="$raw_dir/$measurement_base.oha.json"
  measurement_accounting="$raw_dir/$measurement_base.accounting.json"
  measurement_stats="$raw_dir/$measurement_base.stats.tsv"
  measurement_roles="$raw_dir/$measurement_base.roles.json"
  measurement_result="$raw_dir/$measurement_base.result.json"
  measurement_sample="$raw_dir/.docker-stats.sample"
  : >"$measurement_stats"

  loadgen_name="bonvoyage-p1-oha-${measurement_cores}c-r${measurement_repetition}-$suffix"
  docker run --detach \
    --name "$loadgen_name" \
    --network host \
    --cpuset-cpus "$load_generator_cpus" \
    "$oha_image" \
    -z "${measurement_seconds}s" \
    -c "$measurement_concurrency" \
    --no-tui \
    --output-format json \
    http://127.0.0.1:8080/payload/256 >/dev/null

  while [ "$(docker inspect --format '{{.State.Running}}' "$loadgen_name")" = "true" ]; do
    sample_time="$(date -u '+%s')"
    gateway_process_rss="$(container_process_rss_bytes "$gateway_name")" || \
      gateway_process_rss=""
    docker stats --no-stream \
      --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}' \
      "$gateway_name" "$upstream_name" "$loadgen_name" \
      >"$measurement_sample" 2>/dev/null || true
    if [ "$(docker inspect --format '{{.State.Running}}' "$loadgen_name")" != "true" ]; then
      continue
    fi
    while IFS='|' read -r sample_name sample_cpu sample_memory; do
        sample_cpu="${sample_cpu%%%}"
        sample_memory="${sample_memory%% / *}"
        sample_memory_bytes="$(memory_to_bytes "$sample_memory")" || continue
        sample_process_rss=""
        if [ "$sample_name" = "$gateway_name" ]; then
          sample_process_rss="$gateway_process_rss"
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' \
          "$sample_time" "$sample_name" "$sample_cpu" \
          "$sample_memory_bytes" "$sample_process_rss"
    done <"$measurement_sample" >>"$measurement_stats"
  done
  rm -f "$measurement_sample"

  measurement_exit="$(docker inspect --format '{{.State.ExitCode}}' "$loadgen_name")"
  docker logs "$loadgen_name" >"$measurement_raw"
  docker rm "$loadgen_name" >/dev/null
  loadgen_name=""
  [ "$measurement_exit" -eq 0 ] || fail "$measurement_base load generator exited $measurement_exit"
  jq --argjson concurrency "$measurement_concurrency" \
    --argjson expected_duration "$measurement_seconds" \
    -f "$script_dir/phase1-accounting.jq" "$measurement_raw" \
    >"$measurement_accounting" || fail "$measurement_base produced invalid oha accounting"

  gateway_sample_count="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name {count++} END {print count + 0}' "$measurement_stats")"
  upstream_sample_count="$(awk -F '\t' -v name="$upstream_name" '
    $2 == name {count++} END {print count + 0}' "$measurement_stats")"
  measurement_loadgen_name="bonvoyage-p1-oha-${measurement_cores}c-r${measurement_repetition}-$suffix"
  loadgen_sample_count="$(awk -F '\t' -v name="$measurement_loadgen_name" '
    $2 == name {count++} END {print count + 0}' "$measurement_stats")"
  gateway_rss_sample_count="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name && $5 > 0 {count++} END {print count + 0}' \
    "$measurement_stats")"
  for resource_sample in \
    "gateway=$gateway_sample_count" \
    "upstream=$upstream_sample_count" \
    "load-generator=$loadgen_sample_count" \
    "gateway-process-rss=$gateway_rss_sample_count"; do
    [ "${resource_sample#*=}" -ge "$minimum_resource_samples" ] || \
      fail "$measurement_base ${resource_sample%%=*} supplied fewer than $minimum_resource_samples samples"
  done

  gateway_cpu="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name { sum += $3; count++ }
    END { if (count == 0) exit 1; printf "%.6f", sum / count }
  ' "$measurement_stats")" || fail "$measurement_base has no gateway CPU samples"
  gateway_container_memory="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name && $4 > maximum { maximum = $4 }
    END { printf "%.0f", maximum }
  ' "$measurement_stats")"
  gateway_rss="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name && $5 > maximum { maximum = $5 }
    END { printf "%.0f", maximum }
  ' "$measurement_stats")"
  upstream_cpu="$(awk -F '\t' -v name="$upstream_name" '
    $2 == name { sum += $3; count++ }
    END { if (count == 0) exit 1; printf "%.6f", sum / count }
  ' "$measurement_stats")" || fail "$measurement_base has no upstream CPU samples"
  loadgen_cpu="$(awk -F '\t' -v name="$measurement_loadgen_name" '
    $2 == name { sum += $3; count++ }
    END { if (count == 0) exit 1; printf "%.6f", sum / count }
  ' "$measurement_stats")" || fail "$measurement_base has no load-generator CPU samples"

  successful_rps="$(jq -r '.successful_rps' "$measurement_accounting")"
  error_rate="$(jq -r '.error_rate' "$measurement_accounting")"
  p50_ms="$(jq -r '.latencyPercentiles.p50 * 1000' "$measurement_raw")"
  p95_ms="$(jq -r '.latencyPercentiles.p95 * 1000' "$measurement_raw")"
  p99_ms="$(jq -r '.latencyPercentiles.p99 * 1000' "$measurement_raw")"
  p999_ms="$(jq -r '.latencyPercentiles["p99.9"] * 1000' "$measurement_raw")"

  jq -n \
    --arg run_id "$run_id" \
    --argjson cores "$measurement_cores" \
    --argjson repetition "$measurement_repetition" \
    --argjson upstream_cpu "$upstream_cpu" \
    --argjson loadgen_cpu "$loadgen_cpu" \
    --argjson gateway_samples "$gateway_sample_count" \
    --argjson gateway_rss_samples "$gateway_rss_sample_count" \
    --argjson upstream_samples "$upstream_sample_count" \
    --argjson loadgen_samples "$loadgen_sample_count" \
    --argjson upstream_cpu_count "$upstream_cpu_count" \
    --argjson loadgen_cpu_count "$load_generator_cpu_count" \
    '{
      run_id: $run_id,
      gateway_cores: $cores,
      repetition: $repetition,
      resource_samples: {
        gateway: $gateway_samples,
        gateway_process_rss: $gateway_rss_samples,
        upstream: $upstream_samples,
        load_generator: $loadgen_samples
      },
      upstream_cpu_percent: $upstream_cpu,
      upstream_capacity_percent: ($upstream_cpu / $upstream_cpu_count),
      load_generator_cpu_percent: $loadgen_cpu,
      load_generator_capacity_percent: ($loadgen_cpu / $loadgen_cpu_count)
    }' >"$measurement_roles"

  jq -n \
    --arg run_id "$run_id" \
    --arg workload_id "$workload_id" \
    --arg environment_sha256 "$environment_sha256" \
    --arg version "$dataplane_version" \
    --arg image_digest "$dataplane_image_id" \
    --arg config_sha256 "$snapshot_sha256" \
    --arg started_at "$measurement_started_at" \
    --argjson cores "$measurement_cores" \
    --argjson repetition "$measurement_repetition" \
    --argjson successful_rps "$successful_rps" \
    --argjson error_rate "$error_rate" \
    --argjson p50 "$p50_ms" \
    --argjson p95 "$p95_ms" \
    --argjson p99 "$p99_ms" \
    --argjson p999 "$p999_ms" \
    --argjson gateway_cpu "$gateway_cpu" \
    --argjson gateway_container_memory "$gateway_container_memory" \
    --argjson gateway_rss "$gateway_rss" \
    --argjson connections "$measurement_concurrency" \
    --arg raw_oha "$raw_relative/$measurement_base.oha.json" \
    --arg raw_accounting "$raw_relative/$measurement_base.accounting.json" \
    --arg raw_stats "$raw_relative/$measurement_base.stats.tsv" \
    --arg raw_roles "$raw_relative/$measurement_base.roles.json" \
    '{
      schema_version: 1,
      fixture: false,
      run_id: $run_id,
      workload_id: $workload_id,
      environment_sha256: $environment_sha256,
      product: {
        name: "bonvoyage",
        version: $version,
        image_digest: $image_digest,
        config_sha256: $config_sha256
      },
      execution: {
        started_at: $started_at,
        gateway_cores: $cores,
        repetition: $repetition,
        offered_rps: 0
      },
      metrics: {
        successful_rps: $successful_rps,
        error_rate: $error_rate,
        latency_ms: {p50: $p50, p95: $p95, p99: $p99, p999: $p999},
        gateway_cpu_percent: $gateway_cpu,
        gateway_container_memory_usage_bytes: $gateway_container_memory,
        gateway_rss_bytes: $gateway_rss,
        connections: $connections
      },
      raw_artifacts: [$raw_oha, $raw_stats, $raw_roles, $raw_accounting]
    }' >"$measurement_result"

  echo "  repetition $measurement_repetition: $(printf '%.0f' "$successful_rps") RPS, p99.9 $(printf '%.3f' "$p999_ms") ms"
  sleep "$cooldown_seconds"
}

run_core_count() {
  core_count="$1"
  core_cpuset="$2"
  core_concurrency="$3"
  gateway_name="bonvoyage-p1-gateway-${core_count}c-$suffix"

  echo "Running $core_count-core profile on CPUs $core_cpuset..."
  docker run --detach \
    --name "$gateway_name" \
    --network host \
    --cpuset-cpus "$core_cpuset" \
    --memory 512m \
    --memory-swap 512m \
    --volume "$snapshot_path:/etc/bonvoyage/snapshot.pb:ro" \
    "$dataplane_image" \
    --snapshot /etc/bonvoyage/snapshot.pb \
    --admin-address 127.0.0.1 \
    --metrics-address 127.0.0.1 \
    --smp "$core_count" \
    --memory 384M >/dev/null
  if ! wait_for_url "http://127.0.0.1:9901/health/ready" "BonVoyage"; then
    docker logs "$gateway_name" >&2 || true
    fail "$core_count-core gateway startup failed"
  fi

  fetch_url http://127.0.0.1:8080/payload/256 \
    >"$raw_dir/gateway-${core_count}core.payload"
  [ "$(shasum -a 256 "$raw_dir/gateway-${core_count}core.payload" | awk '{print $1}')" = \
    "85e62acd750c4eb56b7b6a1d66dca5bfaac5f062608a1a893410d0288936c09a" ] || \
    fail "$core_count-core gateway returned the wrong payload"

  loadgen_name="bonvoyage-p1-warmup-${core_count}c-$suffix"
  docker run --rm \
    --name "$loadgen_name" \
    --network host \
    --cpuset-cpus "$load_generator_cpus" \
    "$oha_image" \
    -z "${warmup_seconds}s" \
    -c "$core_concurrency" \
    --no-tui \
    --output-format json \
    http://127.0.0.1:8080/payload/256 \
    >"$raw_dir/bonvoyage-${core_count}core-warmup.oha.json"
  loadgen_name=""

  repetition=1
  while [ "$repetition" -le "$repetitions" ]; do
    run_measurement "$core_count" "$core_concurrency" "$repetition"
    repetition=$((repetition + 1))
  done

  fetch_url http://127.0.0.1:9090/metrics \
    >"$raw_dir/bonvoyage-${core_count}core.metrics.prom"
  docker stop --timeout 30 "$gateway_name" >/dev/null
  docker logs "$gateway_name" >"$raw_dir/bonvoyage-${core_count}core.gateway.log" 2>&1
  gateway_exit="$(docker inspect --format '{{.State.ExitCode}}' "$gateway_name")"
  docker rm "$gateway_name" >/dev/null
  gateway_name=""
  [ "$gateway_exit" -eq 0 ] || fail "$core_count-core gateway exited $gateway_exit"
}

run_core_count 1 "$gateway_one_cpus" "$one_concurrency"
run_core_count 2 "$gateway_two_cpus" "$two_concurrency"

docker logs "$upstream_name" >"$raw_dir/upstream.log" 2>&1
jq -s '.' "$raw_dir"/*.roles.json >"$raw_dir/role-utilization.json"

summary_path="$raw_dir/summary.json"
jq -s \
  --arg run_id "$run_id" \
  --arg workload_id "$workload_id" \
  --arg evidence_class "$evidence_class" \
  --arg publication_reason "$publication_reason" \
  --arg environment_sha256 "$environment_sha256" \
  --arg executable_sha256 "$dataplane_executable_sha256" \
  --argjson publication_authorized "$publication_authorized" \
  --argjson latency_ceiling_ms "$latency_ceiling_ms" \
  --argjson minimum_scaling_ratio "$minimum_scaling_ratio" \
  --argjson maximum_error_rate "$maximum_error_rate" \
  --argjson maximum_variation_percent "$maximum_variation_percent" \
  --argjson minimum_headroom_ratio "$minimum_headroom_ratio" \
  --argjson maximum_support_role_capacity_percent "$maximum_support_role_capacity_percent" \
  --argjson upstream_capacity_rps "$upstream_capacity_rps" \
  --slurpfile role_documents "$raw_dir/role-utilization.json" '
  def median:
    sort as $values |
    ($values | length) as $length |
    if ($length % 2) == 1 then
      $values[($length / 2 | floor)]
    else
      (($values[$length / 2 - 1] + $values[$length / 2]) / 2)
    end;
  def absolute: if . < 0 then 0 - . else . end;
  def maximum_deviation($values):
    ($values | median) as $middle |
    if $middle > 0 then
      [$values[] | (((. - $middle) | absolute) / $middle * 100)] | max
    else null end;
  def core_summary($core_count):
    [.[] | select(.execution.gateway_cores == $core_count)] as $runs |
    [$runs[].metrics.successful_rps] as $rates |
    {
      repetitions: ($runs | length),
      median_successful_rps: ($rates | median),
      rps_per_core: (($rates | median) / $core_count),
      maximum_rate_deviation_percent: maximum_deviation($rates),
      maximum_error_rate: ([$runs[].metrics.error_rate] | max),
      median_p99_ms: ([$runs[].metrics.latency_ms.p99] | median),
      median_p999_ms: ([$runs[].metrics.latency_ms.p999] | median),
      maximum_p999_ms: ([$runs[].metrics.latency_ms.p999] | max),
      mean_gateway_cpu_percent: ([$runs[].metrics.gateway_cpu_percent] | add / length),
      maximum_gateway_rss_bytes: ([$runs[].metrics.gateway_rss_bytes] | max)
    };
  . as $results |
  core_summary(1) as $one |
  core_summary(2) as $two |
  (if $one.median_successful_rps > 0 then
    $two.median_successful_rps / $one.median_successful_rps else 0 end) as $scaling |
  (if $two.median_successful_rps > 0 then
    $upstream_capacity_rps / $two.median_successful_rps else 0 end) as $headroom |
  (($scaling >= $minimum_scaling_ratio) and
   ($one.maximum_p999_ms <= $latency_ceiling_ms) and
   ($two.maximum_p999_ms <= $latency_ceiling_ms) and
   ($one.maximum_error_rate <= $maximum_error_rate) and
   ($two.maximum_error_rate <= $maximum_error_rate) and
   ($one.maximum_rate_deviation_percent != null and
    $one.maximum_rate_deviation_percent <= $maximum_variation_percent) and
   ($two.maximum_rate_deviation_percent != null and
    $two.maximum_rate_deviation_percent <= $maximum_variation_percent) and
   ($headroom >= $minimum_headroom_ratio) and
   (([$role_documents[0][].load_generator_capacity_percent] | max) <=
     $maximum_support_role_capacity_percent) and
   (([$role_documents[0][].upstream_capacity_percent] | max) <=
     $maximum_support_role_capacity_percent)) as $local_pass |
  {
    schema_version: 1,
    run_id: $run_id,
    workload_id: $workload_id,
    evidence_class: $evidence_class,
    environment_sha256: $environment_sha256,
    executable_sha256: $executable_sha256,
    one_core: $one,
    two_core: $two,
    direct_upstream_rps: $upstream_capacity_rps,
    load_generator_maximum_cpu_percent:
      ([$role_documents[0][].load_generator_cpu_percent] | max),
    load_generator_maximum_capacity_percent:
      ([$role_documents[0][].load_generator_capacity_percent] | max),
    upstream_maximum_cpu_percent:
      ([$role_documents[0][].upstream_cpu_percent] | max),
    upstream_maximum_capacity_percent:
      ([$role_documents[0][].upstream_capacity_percent] | max),
    gates: {
      scaling_ratio: $scaling,
      minimum_scaling_ratio: $minimum_scaling_ratio,
      scaling_pass: ($scaling >= $minimum_scaling_ratio),
      latency_ceiling_ms: $latency_ceiling_ms,
      matched_latency_pass:
        (($one.maximum_p999_ms <= $latency_ceiling_ms) and
         ($two.maximum_p999_ms <= $latency_ceiling_ms)),
      maximum_error_rate: $maximum_error_rate,
      errors_pass:
        (($one.maximum_error_rate <= $maximum_error_rate) and
         ($two.maximum_error_rate <= $maximum_error_rate)),
      maximum_variation_percent: $maximum_variation_percent,
      repeatability_pass:
        (($one.maximum_rate_deviation_percent != null and
          $one.maximum_rate_deviation_percent <= $maximum_variation_percent) and
         ($two.maximum_rate_deviation_percent != null and
          $two.maximum_rate_deviation_percent <= $maximum_variation_percent)),
      upstream_headroom_ratio: $headroom,
      minimum_headroom_ratio: $minimum_headroom_ratio,
      upstream_headroom_pass: ($headroom >= $minimum_headroom_ratio),
      maximum_support_role_capacity_percent: $maximum_support_role_capacity_percent,
      support_roles_pass:
        ((([$role_documents[0][].load_generator_capacity_percent] | max) <=
          $maximum_support_role_capacity_percent) and
         (([$role_documents[0][].upstream_capacity_percent] | max) <=
          $maximum_support_role_capacity_percent)),
      local_qualification_pass: $local_pass,
      publication_authorized: ($publication_authorized and $local_pass),
      phase1_exit_pass: ($publication_authorized and $local_pass),
      publication_reason: $publication_reason
    }
  }' "$raw_dir"/*.result.json >"$summary_path"

one_rps="$(jq -r '.one_core.median_successful_rps' "$summary_path")"
two_rps="$(jq -r '.two_core.median_successful_rps' "$summary_path")"
scaling_ratio="$(jq -r '.gates.scaling_ratio' "$summary_path")"
one_p999="$(jq -r '.one_core.median_p999_ms' "$summary_path")"
two_p999="$(jq -r '.two_core.median_p999_ms' "$summary_path")"
one_cpu="$(jq -r '.one_core.mean_gateway_cpu_percent' "$summary_path")"
two_cpu="$(jq -r '.two_core.mean_gateway_cpu_percent' "$summary_path")"
one_rss="$(jq -r '.one_core.maximum_gateway_rss_bytes' "$summary_path")"
two_rss="$(jq -r '.two_core.maximum_gateway_rss_bytes' "$summary_path")"
local_gate_pass="$(jq -r '.gates.local_qualification_pass' "$summary_path")"
phase_exit_pass="$(jq -r '.gates.phase1_exit_pass' "$summary_path")"

{
  printf '# Phase 1 Scaling Evidence: %s\n\n' "$run_id"
  printf -- "- Evidence class: \`%s\`\n" "$evidence_class"
  printf -- "- Workload: \`%s\`\n" "$workload_id"
  printf -- "- Environment: \`%s\`\n" "$raw_relative/phase1-scaling.environment.json"
  printf -- "- Raw summary: \`%s\`\n" "$raw_relative/summary.json"
  printf -- "- Executable SHA-256: \`%s\`\n\n" "$dataplane_executable_sha256"
  printf '| Profile | Median successful RPS | Mean gateway CPU | Max RSS bytes | Median p99.9 |\n'
  printf '| --- | ---: | ---: | ---: | ---: |\n'
  printf '| 1 core | %.2f | %.2f%% | %.0f | %.3f ms |\n' \
    "$one_rps" "$one_cpu" "$one_rss" "$one_p999"
  printf '| 2 cores | %.2f | %.2f%% | %.0f | %.3f ms |\n\n' \
    "$two_rps" "$two_cpu" "$two_rss" "$two_p999"
  printf -- "- Two-core throughput ratio: \`%.4fx\` (required \`%.2fx\`)\n" \
    "$scaling_ratio" "$minimum_scaling_ratio"
  printf -- "- Direct upstream capacity: \`%.2f RPS\`\n" "$upstream_capacity_rps"
  jq -s -r '
    "- Measured HTTP failures: \(map(.http_failures) | add)",
    "- Measured transport failures: \(map(.transport_failures) | add)",
    "- Bounded deadline-end cancellations (excluded from measured error rate): \(map(.deadline_end_cancellations) | add)"
    ' "$raw_dir"/bonvoyage-*core-rep*.accounting.json
  printf -- "- Local qualification gate: \`%s\`\n" "$local_gate_pass"
  printf -- "- Canonical Phase 1 exit gate: \`%s\`\n\n" "$phase_exit_pass"
  printf '%s\n' "$publication_reason"
  printf '%s\n' 'The canonical exit gate remains false until the same workload passes in publishable mode on the dedicated native Linux topology.'
} >"$report_path"

if [ -d website/node_modules/ajv ]; then
  (cd website && npm run validate:project >/dev/null)
else
  echo "website dependencies are absent; run 'make benchmark-contracts' to validate result schemas"
fi

echo "Phase 1 scaling report: $report_relative"
echo "Local qualification gate: $local_gate_pass"
echo "Canonical Phase 1 exit gate: $phase_exit_pass"

if [ "$require_local_gate" = "1" ] && [ "$local_gate_pass" != "true" ]; then
  exit 2
fi
