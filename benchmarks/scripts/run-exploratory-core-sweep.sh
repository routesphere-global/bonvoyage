#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
cd "$repo_root"

product_lock="benchmarks/products/lock.json"
dataplane_image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:phase2-benchmark}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-benchmark-upstream:phase2}"
gateway_cores="${BONVOYAGE_CORE_SWEEP_GATEWAY_CORES:-8}"
gateway_cpus="${BONVOYAGE_CORE_SWEEP_GATEWAY_CPUS:-4-11}"
load_generator_cpus="${BONVOYAGE_CORE_SWEEP_LOAD_GENERATOR_CPUS:-12-21}"
upstream_cpus="${BONVOYAGE_CORE_SWEEP_UPSTREAM_CPUS:-22-31}"
reserved_cpus="${BONVOYAGE_CORE_SWEEP_RESERVED_CPUS:-0-3}"
connections="${BONVOYAGE_CORE_SWEEP_CONNECTIONS:-64 128 256}"
products="${BONVOYAGE_CORE_SWEEP_PRODUCTS:-nginx bonvoyage}"
warmup_seconds="${BONVOYAGE_BENCH_WARMUP_SECONDS:-20}"
measurement_seconds="${BONVOYAGE_BENCH_MEASUREMENT_SECONDS:-20}"
repetitions="${BONVOYAGE_BENCH_REPETITIONS:-3}"
cooldown_seconds="${BONVOYAGE_BENCH_COOLDOWN_SECONDS:-3}"
upstream_capacity_seconds="${BONVOYAGE_UPSTREAM_CAPACITY_SECONDS:-20}"
latency_ceiling_ms="${BONVOYAGE_LATENCY_CEILING_MS:-4.0}"
maximum_error_rate="${BONVOYAGE_MAXIMUM_ERROR_RATE:-0.001}"
maximum_variation_percent="${BONVOYAGE_MAXIMUM_VARIATION_PERCENT:-5.0}"
maximum_support_capacity_percent="${BONVOYAGE_MAXIMUM_SUPPORT_ROLE_CAPACITY_PERCENT:-80.0}"
minimum_headroom_ratio="${BONVOYAGE_MINIMUM_HEADROOM_RATIO:-1.2}"
minimum_resource_samples="${BONVOYAGE_MINIMUM_RESOURCE_SAMPLES:-3}"
skip_build="${BONVOYAGE_SKIP_BUILD:-0}"
skip_pull="${BONVOYAGE_PHASE2_SKIP_PULL:-0}"

fail() {
  echo "core-sweep: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command '$1' is unavailable"
}

require_positive_integer() {
  case "$2" in ''|*[!0-9]*) fail "$1 must be a positive integer" ;; esac
  [ "$2" -gt 0 ] || fail "$1 must be a positive integer"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
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
          for (cpu = range[1]; cpu <= range[2]; cpu++) print cpu
        } else {
          exit 2
        }
      }
    }
  '
}

assert_disjoint() {
  assignments_file="$(mktemp)"
  for assignment in "$@"; do
    label="${assignment%%=*}"
    cpu_set="${assignment#*=}"
    expanded="$(expand_cpu_set "$cpu_set")" || {
      rm -f "$assignments_file"
      fail "invalid CPU set '$cpu_set' for $label"
    }
    printf '%s\n' "$expanded" | awk -v label="$label" \
      '{print $1 " " label}' >>"$assignments_file"
  done
  conflict="$(sort -n "$assignments_file" | awk '
    seen[$1] {print "CPU " $1 " is shared by " owner[$1] " and " $2; exit}
    {seen[$1] = 1; owner[$1] = $2}
  ')"
  rm -f "$assignments_file"
  [ -z "$conflict" ] || fail "$conflict"
}

memory_to_bytes() {
  memory_value="$1"
  case "$memory_value" in
    *KiB) number="${memory_value%KiB}"; multiplier=1024 ;;
    *MiB) number="${memory_value%MiB}"; multiplier=1048576 ;;
    *GiB) number="${memory_value%GiB}"; multiplier=1073741824 ;;
    *kB) number="${memory_value%kB}"; multiplier=1000 ;;
    *MB) number="${memory_value%MB}"; multiplier=1000000 ;;
    *GB) number="${memory_value%GB}"; multiplier=1000000000 ;;
    *B) number="${memory_value%B}"; multiplier=1 ;;
    *) return 1 ;;
  esac
  awk -v number="$number" -v multiplier="$multiplier" \
    'BEGIN {printf "%.0f", number * multiplier}'
}

fetch_url() {
  docker run --rm --network host \
    --cpuset-cpus "$load_generator_cpus" \
    --entrypoint /usr/bin/wget "$upstream_image" -q -O - "$1"
}

wait_for_url() {
  wait_url="$1"
  wait_name="$2"
  wait_attempt=0
  until fetch_url "$wait_url" >/dev/null 2>&1; do
    wait_attempt=$((wait_attempt + 1))
    [ "$wait_attempt" -lt 30 ] || return 1
    sleep 1
  done
  echo "  $wait_name ready"
}

for command_name in awk cat cp date docker git go grep jq mktemp sed sort tr wc; do
  require_command "$command_name"
done
if ! command -v sha256sum >/dev/null 2>&1; then
  require_command shasum
fi

require_positive_integer "gateway cores" "$gateway_cores"
require_positive_integer "warm-up seconds" "$warmup_seconds"
require_positive_integer "measurement seconds" "$measurement_seconds"
require_positive_integer "repetitions" "$repetitions"
require_positive_integer "upstream capacity seconds" "$upstream_capacity_seconds"
require_positive_integer "minimum resource samples" "$minimum_resource_samples"
[ "$repetitions" -ge 3 ] || fail "the exploratory sweep requires at least three repetitions"

gateway_cpu_count="$(expand_cpu_set "$gateway_cpus" | wc -l | tr -d ' ')"
load_generator_cpu_count="$(expand_cpu_set "$load_generator_cpus" | wc -l | tr -d ' ')"
upstream_cpu_count="$(expand_cpu_set "$upstream_cpus" | wc -l | tr -d ' ')"
reserved_cpu_count="$(expand_cpu_set "$reserved_cpus" | wc -l | tr -d ' ')"
[ "$gateway_cpu_count" -eq "$gateway_cores" ] || \
  fail "gateway CPU set contains $gateway_cpu_count CPUs, expected $gateway_cores"
assert_disjoint \
  "reserved=$reserved_cpus" \
  "gateway=$gateway_cpus" \
  "load-generator=$load_generator_cpus" \
  "upstream=$upstream_cpus"

docker_arch="$(docker info --format '{{.Architecture}}')"
docker_cpus="$(docker info --format '{{.NCPU}}')"
case "$docker_arch" in
  x86_64|amd64) platform="linux/amd64"; manifest_key="linux_amd64" ;;
  aarch64|arm64) platform="linux/arm64"; manifest_key="linux_arm64" ;;
  *) fail "unsupported Docker architecture '$docker_arch'" ;;
esac
highest_cpu="$({
  expand_cpu_set "$reserved_cpus"
  expand_cpu_set "$gateway_cpus"
  expand_cpu_set "$load_generator_cpus"
  expand_cpu_set "$upstream_cpus"
} | sort -n | tail -n 1)"
[ "$highest_cpu" -lt "$docker_cpus" ] || \
  fail "CPU $highest_cpu is outside Docker's $docker_cpus logical CPUs"
aio_max_nr="$(cat /proc/sys/fs/aio-max-nr 2>/dev/null || printf '0')"
minimum_aio_max_nr=$((gateway_cores * 11026))
[ "$aio_max_nr" -ge "$minimum_aio_max_nr" ] || \
  fail "fs.aio-max-nr=$aio_max_nr is below the $minimum_aio_max_nr required for $gateway_cores Seastar shards"

seen_products=""
for product in $products; do
  case "$product" in bonvoyage|nginx) ;; *) fail "unsupported product '$product'" ;; esac
  case " $seen_products " in *" $product "*) fail "duplicate product '$product'" ;; esac
  seen_products="$seen_products $product"
done
case " $seen_products " in *" bonvoyage "*) ;; *) fail "BonVoyage is required" ;; esac
case " $seen_products " in *" nginx "*) ;; *) fail "NGINX is required" ;; esac

connection_json="$(printf '%s\n' "$connections" | tr ' ' '\n' | \
  sed '/^$/d' | jq -s 'map(tonumber)')"
[ "$(printf '%s' "$connection_json" | jq 'length')" -gt 0 ] || \
  fail "at least one connection count is required"
if ! printf '%s' "$connection_json" | jq -e \
  'all(.[]; type == "number" and . > 0 and floor == .)' >/dev/null; then
  fail "connection counts must be positive integers"
fi

loadgen_repository="$(jq -r '.load_generator.repository' "$product_lock")"
loadgen_manifest="$(jq -r --arg key "$manifest_key" \
  '.load_generator.manifests[$key]' "$product_lock")"
loadgen_image="$loadgen_repository@$loadgen_manifest"
nginx_repository="$(jq -r '.products[] | select(.name == "nginx") | .repository' \
  "$product_lock")"
nginx_manifest="$(jq -r --arg key "$manifest_key" \
  '.products[] | select(.name == "nginx") | .manifests[$key]' "$product_lock")"
nginx_image="$nginx_repository@$nginx_manifest"

captured_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
run_stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
run_id="exploratory-core-sweep-$run_stamp"
run_relative="benchmarks/results/exploratory/$run_id"
run_dir="$repo_root/$run_relative"
mkdir -p "$run_dir"

suffix="$$-$run_stamp"
upstream_name="bonvoyage-core-sweep-upstream-$suffix"
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
  docker buildx build --platform "$platform" --load \
    --build-arg "BUILD_JOBS=${BONVOYAGE_BUILD_JOBS:-2}" \
    --target runtime --tag "$dataplane_image" \
    --file deploy/docker/bonvoyage/Dockerfile .
  docker buildx build --platform "$platform" --load \
    --tag "$upstream_image" benchmarks/products/upstream
fi
if [ "$skip_pull" != "1" ]; then
  docker pull "$loadgen_image" >/dev/null
  docker pull "$nginx_image" >/dev/null
fi

snapshot_path="$run_dir/snapshot.pb"
(
  cd control-plane
  go run ./cmd/bonvoyage-control-plane \
    -input ../benchmarks/products/bonvoyage/host-network.yaml \
    -output "$snapshot_path"
)
snapshot_sha256="$(sha256_file "$snapshot_path")"
dataplane_image_id="$(docker image inspect --format '{{.Id}}' "$dataplane_image")"
dataplane_version="$(docker image inspect \
  --format '{{index .Config.Labels "org.opencontainers.image.version"}}' \
  "$dataplane_image")"
nginx_version="$(jq -r '.products[] | select(.name == "nginx") | .version' \
  "$product_lock")"
nginx_config_sha256="$(sha256_file benchmarks/products/nginx/nginx.conf)"

cp "$0" "$run_dir/run-exploratory-core-sweep.sh"
cp "$product_lock" "$run_dir/product-lock.json"
cp benchmarks/products/nginx/nginx.conf "$run_dir/nginx.conf"
cp benchmarks/products/bonvoyage/host-network.yaml "$run_dir/bonvoyage.yaml"
sed "s/^worker_processes auto;/worker_processes $upstream_cpu_count;/" \
  benchmarks/products/upstream/nginx.conf >"$run_dir/upstream.nginx.conf"
grep -Fx "worker_processes $upstream_cpu_count;" \
  "$run_dir/upstream.nginx.conf" >/dev/null || \
  fail "controlled upstream worker count was not rendered"
git status --short >"$run_dir/git-status.txt"
git rev-parse HEAD >"$run_dir/git-commit.txt"
docker info >"$run_dir/docker-info.txt"
uname -a >"$run_dir/uname.txt"
if command -v lscpu >/dev/null 2>&1; then
  lscpu --extended >"$run_dir/lscpu.txt"
fi
cp /proc/sys/fs/aio-max-nr "$run_dir/aio-max-nr.txt"
cp /proc/sys/kernel/perf_event_paranoid "$run_dir/perf-event-paranoid.txt"

echo "Starting controlled upstream on CPUs $upstream_cpus..."
docker run --detach --name "$upstream_name" --network host \
  --cpuset-cpus "$upstream_cpus" \
  --memory 2g --memory-swap 2g --pids-limit 4096 \
  --ulimit nofile=1048576:1048576 \
  --volume "$run_dir/upstream.nginx.conf:/etc/nginx/nginx.conf:ro" \
  --entrypoint /usr/sbin/nginx "$upstream_image" \
  -c /etc/nginx/nginx.conf -g 'daemon off;' >/dev/null
if ! wait_for_url http://127.0.0.1:8081/healthz "controlled upstream"; then
  docker logs "$upstream_name" >&2 || true
  fail "controlled upstream did not become ready"
fi

largest_connection="$(printf '%s' "$connection_json" | jq 'max')"
echo "Measuring direct upstream capacity..."
docker run --rm --network host --cpuset-cpus "$load_generator_cpus" \
  "$loadgen_image" -z "${upstream_capacity_seconds}s" \
  -c "$largest_connection" -w --http-version 1.1 \
  --disable-compression -H 'accept: application/octet-stream' \
  --no-tui --output-format json \
  http://127.0.0.1:8081/payload/256 >"$run_dir/upstream-capacity.oha.json"
if ! jq -e '
  ([.statusCodeDistribution[]?] | add // 0) > 0 and
  ([.statusCodeDistribution | to_entries[]? |
    select(.key != "200") | .value] | add // 0) == 0 and
  ([.errorDistribution[]?] | add // 0) == 0
' "$run_dir/upstream-capacity.oha.json" >/dev/null; then
  fail "direct upstream capacity preflight failed"
fi
upstream_capacity_rps="$(jq -r \
  '(.statusCodeDistribution["200"] // 0) / .summary.total' \
  "$run_dir/upstream-capacity.oha.json")"
printf '  direct upstream: %.0f RPS\n' "$upstream_capacity_rps"

start_gateway() {
  start_product="$1"
  gateway_name="bonvoyage-core-sweep-$start_product-$suffix"
  case "$start_product" in
    bonvoyage)
      docker run --detach --name "$gateway_name" --network host \
        --cpuset-cpus "$gateway_cpus" --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
        --cap-drop ALL --cap-add SYS_NICE --security-opt no-new-privileges \
        --memory 4g --memory-swap 4g --pids-limit 4096 \
        --ulimit nofile=1048576:1048576 \
        --volume "$snapshot_path:/etc/bonvoyage/snapshot.pb:ro" \
        "$dataplane_image" \
        --snapshot /etc/bonvoyage/snapshot.pb \
        --admin-address 127.0.0.1 --metrics-address 127.0.0.1 \
        --smp "$gateway_cores" --memory 1536M >/dev/null
      readiness_path=/health/ready
      ;;
    nginx)
      docker run --detach --name "$gateway_name" --network host \
        --cpuset-cpus "$gateway_cpus" --user 65532:65532 --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
        --cap-drop ALL --cap-add SYS_NICE --security-opt no-new-privileges \
        --memory 4g --memory-swap 4g --pids-limit 4096 \
        --ulimit nofile=1048576:1048576 \
        --volume "$repo_root/benchmarks/products/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" \
        --entrypoint /usr/sbin/nginx "$nginx_image" \
        -c /etc/nginx/nginx.conf \
        -g "daemon off; worker_processes $gateway_cores;" >/dev/null
      readiness_path=/health/ready
      ;;
  esac
  if ! wait_for_url "http://127.0.0.1:9901$readiness_path" "$start_product"; then
    docker logs "$gateway_name" >&2 || true
    fail "$start_product did not become ready"
  fi
  if [ "$start_product" = "nginx" ]; then
    docker top "$gateway_name" -eo pid,ppid,comm,args \
      >"$run_dir/nginx-processes-verification.txt"
    docker inspect --format '{{.HostConfig.CpusetCpus}}' "$gateway_name" \
      >"$run_dir/nginx-cpuset-verification.txt"
    nginx_worker_count="$(awk '/nginx: worker process/ {count++}
      END {print count + 0}' "$run_dir/nginx-processes-verification.txt")"
    [ "$nginx_worker_count" -eq "$gateway_cores" ] || \
      fail "NGINX started $nginx_worker_count workers; expected $gateway_cores"
  fi
  fetch_url http://127.0.0.1:8080/payload/256 \
    >"$run_dir/$start_product.payload"
  [ "$(sha256_file "$run_dir/$start_product.payload")" = \
    "85e62acd750c4eb56b7b6a1d66dca5bfaac5f062608a1a893410d0288936c09a" ] || \
    fail "$start_product returned the wrong payload"
}

stop_gateway() {
  stop_product="$1"
  [ "$(docker inspect --format '{{.State.OOMKilled}}' "$gateway_name")" = "false" ] || \
    fail "$stop_product gateway encountered an out-of-memory event"
  docker stop --timeout 30 "$gateway_name" >/dev/null
  docker logs "$gateway_name" >"$run_dir/$stop_product.gateway.log" 2>&1
  gateway_exit="$(docker inspect --format '{{.State.ExitCode}}' "$gateway_name")"
  docker rm "$gateway_name" >/dev/null
  gateway_name=""
  [ "$gateway_exit" -eq 0 ] || fail "$stop_product gateway exited $gateway_exit"
}

run_measurement() {
  measurement_product="$1"
  measurement_connections="$2"
  measurement_repetition="$3"
  measurement_base="$measurement_product-c${measurement_connections}-rep${measurement_repetition}"
  measurement_raw="$run_dir/$measurement_base.oha.json"
  measurement_stats="$run_dir/$measurement_base.stats.tsv"
  measurement_sample="$run_dir/.$measurement_base.stats.sample"
  : >"$measurement_stats"

  loadgen_name="bonvoyage-core-sweep-oha-$measurement_base-$suffix"
  docker run --detach --name "$loadgen_name" --network host \
    --cpuset-cpus "$load_generator_cpus" "$loadgen_image" \
    -z "${measurement_seconds}s" -c "$measurement_connections" -w \
    --http-version 1.1 --disable-compression \
    -H 'accept: application/octet-stream' --no-tui \
    --output-format json http://127.0.0.1:8080/payload/256 >/dev/null

  while [ "$(docker inspect --format '{{.State.Running}}' "$loadgen_name")" = "true" ]; do
    sample_time="$(date -u '+%s')"
    docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}' \
      "$gateway_name" "$upstream_name" "$loadgen_name" \
      >"$measurement_sample" 2>/dev/null || true
    if [ "$(docker inspect --format '{{.State.Running}}' "$loadgen_name")" != "true" ]; then
      continue
    fi
    while IFS='|' read -r sample_name sample_cpu sample_memory; do
      sample_cpu="${sample_cpu%%%}"
      sample_memory="${sample_memory%% / *}"
      sample_memory_bytes="$(memory_to_bytes "$sample_memory")" || continue
      printf '%s\t%s\t%s\t%s\n' \
        "$sample_time" "$sample_name" "$sample_cpu" "$sample_memory_bytes"
    done <"$measurement_sample" >>"$measurement_stats"
  done
  rm -f "$measurement_sample"

  measurement_exit="$(docker wait "$loadgen_name")"
  docker logs "$loadgen_name" >"$measurement_raw" 2>&1
  docker rm "$loadgen_name" >/dev/null
  loadgen_name=""
  [ "$measurement_exit" -eq 0 ] || \
    fail "$measurement_base load generator exited $measurement_exit"
  jq -e '.summary.requestsPerSec > 0' "$measurement_raw" >/dev/null || \
    fail "$measurement_base produced invalid oha output"

  actual_duration="$(jq -r '.summary.total' "$measurement_raw")"
  successful_requests="$(jq -r '.statusCodeDistribution["200"] // 0' \
    "$measurement_raw")"
  completed_requests="$(jq -r '
    ([.statusCodeDistribution[]?] | add // 0) +
    ([.errorDistribution[]?] | add // 0)
  ' "$measurement_raw")"
  successful_rps="$(awk -v successful="$successful_requests" \
    -v duration="$actual_duration" \
    'BEGIN {printf "%.12f", successful / duration}')"
  error_rate="$(awk -v successful="$successful_requests" \
    -v completed="$completed_requests" \
    'BEGIN {if (completed <= 0) print 1; else printf "%.12f", 1 - successful / completed}')"
  p50_ms="$(jq -r '.latencyPercentiles.p50 * 1000' "$measurement_raw")"
  p99_ms="$(jq -r '.latencyPercentiles.p99 * 1000' "$measurement_raw")"
  p999_ms="$(jq -r '.latencyPercentiles["p99.9"] * 1000' "$measurement_raw")"

  gateway_sample_count="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name {count++} END {print count + 0}' "$measurement_stats")"
  upstream_sample_count="$(awk -F '\t' -v name="$upstream_name" '
    $2 == name {count++} END {print count + 0}' "$measurement_stats")"
  measured_loadgen="bonvoyage-core-sweep-oha-$measurement_base-$suffix"
  loadgen_sample_count="$(awk -F '\t' -v name="$measured_loadgen" '
    $2 == name {count++} END {print count + 0}' "$measurement_stats")"
  for resource_sample in \
    "gateway=$gateway_sample_count" \
    "upstream=$upstream_sample_count" \
    "load-generator=$loadgen_sample_count"; do
    [ "${resource_sample#*=}" -ge "$minimum_resource_samples" ] || \
      fail "$measurement_base ${resource_sample%%=*} supplied fewer than $minimum_resource_samples samples"
  done

  gateway_cpu="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name {sum += $3; count++}
    END {printf "%.6f", sum / count}
  ' "$measurement_stats")"
  gateway_memory_usage="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name && $4 > maximum {maximum = $4}
    END {printf "%.0f", maximum + 0}
  ' "$measurement_stats")"
  upstream_cpu="$(awk -F '\t' -v name="$upstream_name" '
    $2 == name {sum += $3; count++}
    END {printf "%.6f", sum / count}
  ' "$measurement_stats")"
  loadgen_cpu="$(awk -F '\t' -v name="$measured_loadgen" '
    $2 == name {sum += $3; count++}
    END {printf "%.6f", sum / count}
  ' "$measurement_stats")"
  upstream_capacity="$(awk -v cpu="$upstream_cpu" -v count="$upstream_cpu_count" \
    'BEGIN {printf "%.6f", cpu / count}')"
  loadgen_capacity="$(awk -v cpu="$loadgen_cpu" -v count="$load_generator_cpu_count" \
    'BEGIN {printf "%.6f", cpu / count}')"
  gateway_capacity="$(awk -v cpu="$gateway_cpu" -v count="$gateway_cpu_count" \
    'BEGIN {printf "%.6f", cpu / count}')"

  if [ "$measurement_product" = "bonvoyage" ]; then
    version="$dataplane_version"
    image_digest="$dataplane_image_id"
    config_sha256="$snapshot_sha256"
  else
    version="$nginx_version"
    image_digest="$nginx_manifest"
    config_sha256="$nginx_config_sha256"
  fi

  jq -n \
    --arg run_id "$run_id" \
    --arg product "$measurement_product" \
    --arg version "$version" \
    --arg image_digest "$image_digest" \
    --arg config_sha256 "$config_sha256" \
    --argjson gateway_cores "$gateway_cores" \
    --argjson connections "$measurement_connections" \
    --argjson repetition "$measurement_repetition" \
    --argjson successful_rps "$successful_rps" \
    --argjson error_rate "$error_rate" \
    --argjson p50_ms "$p50_ms" \
    --argjson p99_ms "$p99_ms" \
    --argjson p999_ms "$p999_ms" \
    --argjson gateway_cpu "$gateway_cpu" \
    --argjson gateway_capacity "$gateway_capacity" \
    --argjson gateway_memory_usage "$gateway_memory_usage" \
    --argjson upstream_cpu "$upstream_cpu" \
    --argjson upstream_capacity "$upstream_capacity" \
    --argjson loadgen_cpu "$loadgen_cpu" \
    --argjson loadgen_capacity "$loadgen_capacity" \
    --argjson gateway_samples "$gateway_sample_count" \
    --argjson upstream_samples "$upstream_sample_count" \
    --argjson loadgen_samples "$loadgen_sample_count" \
    '{
      schema_version: 1,
      evidence_class: "local-functional-exploratory",
      run_id: $run_id,
      product: {
        name: $product,
        version: $version,
        image_digest: $image_digest,
        config_sha256: $config_sha256
      },
      gateway_cores: $gateway_cores,
      connections: $connections,
      repetition: $repetition,
      successful_rps: $successful_rps,
      error_rate: $error_rate,
      latency_ms: {p50: $p50_ms, p99: $p99_ms, p999: $p999_ms},
      gateway: {
        cpu_percent: $gateway_cpu,
        capacity_percent: $gateway_capacity,
        maximum_container_memory_usage_bytes: $gateway_memory_usage
      },
      upstream: {cpu_percent: $upstream_cpu, capacity_percent: $upstream_capacity},
      load_generator: {cpu_percent: $loadgen_cpu, capacity_percent: $loadgen_capacity},
      resource_samples: {
        gateway: $gateway_samples,
        upstream: $upstream_samples,
        load_generator: $loadgen_samples
      },
      raw_artifacts: [
        ($run_id + "/" + $product + "-c" + ($connections | tostring) +
          "-rep" + ($repetition | tostring) + ".oha.json"),
        ($run_id + "/" + $product + "-c" + ($connections | tostring) +
          "-rep" + ($repetition | tostring) + ".stats.tsv")
      ]
    }' >"$run_dir/$measurement_base.result.json"

  printf '    c=%s rep=%s: %.0f RPS, p99.9 %.3f ms, errors %.4f%%\n' \
    "$measurement_connections" "$measurement_repetition" \
    "$successful_rps" "$p999_ms" "$(awk -v rate="$error_rate" 'BEGIN {print rate * 100}')"
  sleep "$cooldown_seconds"
}

for product in $products; do
  echo "Testing $product on $gateway_cores gateway cores..."
  start_gateway "$product"
  docker run --rm --network host --cpuset-cpus "$load_generator_cpus" \
    "$loadgen_image" -z "${warmup_seconds}s" -c "$largest_connection" -w \
    --http-version 1.1 --disable-compression \
    -H 'accept: application/octet-stream' --no-tui --output-format json \
    http://127.0.0.1:8080/payload/256 >"$run_dir/$product.warmup.oha.json"
  for connection_count in $connections; do
    repetition=1
    while [ "$repetition" -le "$repetitions" ]; do
      run_measurement "$product" "$connection_count" "$repetition"
      repetition=$((repetition + 1))
    done
  done
  stop_gateway "$product"
done

docker logs "$upstream_name" >"$run_dir/upstream.log" 2>&1
[ "$(docker inspect --format '{{.State.OOMKilled}}' "$upstream_name")" = "false" ] || \
  fail "controlled upstream encountered an out-of-memory event"
docker stop --timeout 30 "$upstream_name" >/dev/null
upstream_exit="$(docker inspect --format '{{.State.ExitCode}}' "$upstream_name")"
docker rm "$upstream_name" >/dev/null
upstream_name=""
[ "$upstream_exit" -eq 0 ] || fail "controlled upstream exited $upstream_exit"

summary_path="$run_dir/summary.json"
jq -s \
  --arg run_id "$run_id" \
  --arg captured_at "$captured_at" \
  --argjson gateway_cores "$gateway_cores" \
  --arg gateway_cpus "$gateway_cpus" \
  --arg load_generator_cpus "$load_generator_cpus" \
  --arg upstream_cpus "$upstream_cpus" \
  --arg reserved_cpus "$reserved_cpus" \
  --argjson reserved_cpu_count "$reserved_cpu_count" \
  --argjson aio_max_nr "$aio_max_nr" \
  --argjson minimum_aio_max_nr "$minimum_aio_max_nr" \
  --argjson connection_counts "$connection_json" \
  --argjson upstream_capacity_rps "$upstream_capacity_rps" \
  --argjson latency_ceiling_ms "$latency_ceiling_ms" \
  --argjson maximum_error_rate "$maximum_error_rate" \
  --argjson maximum_variation_percent "$maximum_variation_percent" \
  --argjson maximum_support_capacity_percent "$maximum_support_capacity_percent" \
  --argjson minimum_headroom_ratio "$minimum_headroom_ratio" '
  def median:
    sort as $values | ($values | length) as $length |
    if $length % 2 == 1 then $values[($length / 2 | floor)]
    else ($values[$length / 2 - 1] + $values[$length / 2]) / 2 end;
  def abs: if . < 0 then -. else . end;
  def deviation($values):
    ($values | median) as $middle |
    if $middle == 0 then null
    else [$values[] | ((. - $middle) | abs) / $middle * 100] | max end;
  group_by([.product.name, .connections]) |
  map(. as $runs |
    [$runs[].successful_rps] as $rates |
    {
      product: $runs[0].product.name,
      connections: $runs[0].connections,
      repetitions: ($runs | length),
      median_successful_rps: ($rates | median),
      maximum_rate_deviation_percent: deviation($rates),
      median_p999_ms: ([$runs[].latency_ms.p999] | median),
      maximum_p999_ms: ([$runs[].latency_ms.p999] | max),
      maximum_error_rate: ([$runs[].error_rate] | max),
      mean_gateway_capacity_percent:
        ([$runs[].gateway.capacity_percent] | add / length),
      maximum_upstream_capacity_percent:
        ([$runs[].upstream.capacity_percent] | max),
      maximum_load_generator_capacity_percent:
        ([$runs[].load_generator.capacity_percent] | max),
      maximum_gateway_container_memory_usage_bytes:
        ([$runs[].gateway.maximum_container_memory_usage_bytes] | max)
    }) as $points |
  ($points | map(.median_successful_rps) | max) as $maximum_gateway_rps |
  ($upstream_capacity_rps / $maximum_gateway_rps) as $headroom |
  [$connection_counts[] as $connection |
    ($points[] | select(.product == "bonvoyage" and
      .connections == $connection)) as $bonvoyage |
    ($points[] | select(.product == "nginx" and
      .connections == $connection)) as $nginx |
    {
      connections: $connection,
      bonvoyage_rps: $bonvoyage.median_successful_rps,
      nginx_rps: $nginx.median_successful_rps,
      bonvoyage_advantage_percent:
        (($bonvoyage.median_successful_rps / $nginx.median_successful_rps - 1) * 100)
    }
  ] as $comparisons |
  ($points | all(
    .repetitions >= 3 and
    .maximum_rate_deviation_percent <= $maximum_variation_percent and
    .maximum_error_rate <= $maximum_error_rate and
    .maximum_upstream_capacity_percent <= $maximum_support_capacity_percent and
    .maximum_load_generator_capacity_percent <= $maximum_support_capacity_percent
  )) as $measurements_valid |
  {
    schema_version: 1,
    evidence_class: "local-functional-exploratory",
    run_id: $run_id,
    captured_at: $captured_at,
    publication_authorized: false,
    publication_reason:
      "single shared-tenancy host; exploratory evidence only",
    gateway_cores: $gateway_cores,
    cpu_allocation: {
      reserved: $reserved_cpus,
      reserved_count: $reserved_cpu_count,
      gateway: $gateway_cpus,
      load_generator: $load_generator_cpus,
      upstream: $upstream_cpus
    },
    host_limits: {
      aio_max_nr: $aio_max_nr,
      minimum_aio_max_nr: $minimum_aio_max_nr,
      aio_capacity_pass: ($aio_max_nr >= $minimum_aio_max_nr)
    },
    connection_counts: $connection_counts,
    direct_upstream_rps: $upstream_capacity_rps,
    points: $points,
    comparisons: $comparisons,
    gates: {
      latency_ceiling_ms: $latency_ceiling_ms,
      maximum_error_rate: $maximum_error_rate,
      maximum_variation_percent: $maximum_variation_percent,
      maximum_support_capacity_percent: $maximum_support_capacity_percent,
      measurements_valid: $measurements_valid,
      upstream_headroom_ratio: $headroom,
      minimum_headroom_ratio: $minimum_headroom_ratio,
      upstream_headroom_pass: ($headroom >= $minimum_headroom_ratio),
      host_not_saturated:
        ($measurements_valid and $headroom >= $minimum_headroom_ratio)
    }
  }' "$run_dir"/*.result.json >"$summary_path"

report_path="$run_dir/report.md"
{
  printf '# Exploratory %s-core Sweep: %s\n\n' "$gateway_cores" "$run_id"
  printf -- "- Evidence class: \`local-functional-exploratory\`\n"
  printf -- "- CPU allocation: reserved \`%s\`; gateway \`%s\`; load generator \`%s\`; upstream \`%s\`\n" \
    "$reserved_cpus" "$gateway_cpus" "$load_generator_cpus" "$upstream_cpus"
  printf -- "- Direct upstream capacity: \`%.2f RPS\`\n" "$upstream_capacity_rps"
  printf -- "- Linux AIO capacity: \`%s\` (required \`%s\`)\n" \
    "$aio_max_nr" "$minimum_aio_max_nr"
  printf -- "- Host not saturated: \`%s\`\n\n" \
    "$(jq -r '.gates.host_not_saturated' "$summary_path")"
  printf '| Product | Connections | Median successful RPS | Max variation | Median p99.9 | Max p99.9 | Max errors | Upstream max | Load generator max |\n'
  printf '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n'
  jq -r '.points[] |
    "| \(.product) | \(.connections) | \(.median_successful_rps | floor) | " +
    "\(.maximum_rate_deviation_percent)% | \(.median_p999_ms) ms | " +
    "\(.maximum_p999_ms) ms | \(.maximum_error_rate * 100)% | " +
    "\(.maximum_upstream_capacity_percent)% | " +
    "\(.maximum_load_generator_capacity_percent)% |"' "$summary_path"
  printf '\n| Connections | BonVoyage RPS | NGINX RPS | BonVoyage advantage |\n'
  printf '| ---: | ---: | ---: | ---: |\n'
  jq -r '.comparisons[] |
    "| \(.connections) | \(.bonvoyage_rps | floor) | \(.nginx_rps | floor) | " +
    "\(.bonvoyage_advantage_percent)% |"' "$summary_path"
  printf '\nThese results are exploratory and cannot support a public performance claim.\n'
} >"$report_path"

echo "Exploratory core sweep: $run_relative"
echo "Host not saturated: $(jq -r '.gates.host_not_saturated' "$summary_path")"
