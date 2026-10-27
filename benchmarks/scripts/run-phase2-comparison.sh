#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
cd "$repo_root"

workload_id="http1-keepalive-phase2-baseline"
product_lock="benchmarks/products/lock.json"
dataplane_image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:phase2-benchmark}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-benchmark-upstream:phase2}"
gateway_one_cpus="${BONVOYAGE_GATEWAY_ONE_CPUS:-2}"
gateway_two_cpus="${BONVOYAGE_GATEWAY_TWO_CPUS:-2,3}"
load_generator_cpus="${BONVOYAGE_LOAD_GENERATOR_CPUS:-4-7}"
upstream_cpus="${BONVOYAGE_UPSTREAM_CPUS:-8-11}"
irq_cpus="${BONVOYAGE_IRQ_CPUS:-not-isolated-local-qualification}"
one_concurrency="${BONVOYAGE_ONE_CORE_CONCURRENCY:-64}"
two_concurrency="${BONVOYAGE_TWO_CORE_CONCURRENCY:-64}"
warmup_seconds="${BONVOYAGE_BENCH_WARMUP_SECONDS:-30}"
discovery_seconds="${BONVOYAGE_PHASE2_DISCOVERY_SECONDS:-15}"
measurement_seconds="${BONVOYAGE_BENCH_MEASUREMENT_SECONDS:-30}"
churn_seconds="${BONVOYAGE_PHASE2_CHURN_SECONDS:-60}"
repetitions="${BONVOYAGE_BENCH_REPETITIONS:-5}"
resilience_repetitions="${BONVOYAGE_PHASE2_RESILIENCE_REPETITIONS:-3}"
cooldown_seconds="${BONVOYAGE_BENCH_COOLDOWN_SECONDS:-5}"
upstream_capacity_seconds="${BONVOYAGE_UPSTREAM_CAPACITY_SECONDS:-15}"
discovery_multipliers="${BONVOYAGE_PHASE2_DISCOVERY_MULTIPLIERS:-0.10 0.15 0.20 0.25 0.30 0.35 0.40 0.45 0.50 0.55 0.60 0.65 0.70 0.75 0.80 0.85 0.90 0.95 1.00 1.05 1.10 1.15 1.20}"
latency_ceiling_ms="${BONVOYAGE_LATENCY_CEILING_MS:-4.0}"
maximum_error_rate="${BONVOYAGE_MAXIMUM_ERROR_RATE:-0.001}"
maximum_support_capacity_percent="${BONVOYAGE_MAXIMUM_SUPPORT_ROLE_CAPACITY_PERCENT:-80.0}"
minimum_headroom_ratio="${BONVOYAGE_MINIMUM_HEADROOM_RATIO:-1.2}"
minimum_resource_samples="${BONVOYAGE_MINIMUM_RESOURCE_SAMPLES:-3}"
seed="${BONVOYAGE_PHASE2_SEED:-bonvoyage-phase2-baseline-v1}"
comparison_products="${BONVOYAGE_PHASE2_PRODUCTS:-bonvoyage envoy nginx haproxy}"
skip_build="${BONVOYAGE_SKIP_BUILD:-0}"
skip_pull="${BONVOYAGE_PHASE2_SKIP_PULL:-0}"
publishable_request="${BONVOYAGE_PUBLISHABLE:-0}"
qualification_attestation="${BONVOYAGE_QUALIFICATION_ATTESTATION:-}"
phase1_evidence="${BONVOYAGE_PHASE1_EVIDENCE:-}"
phase1_environment=""
product_qualification="${BONVOYAGE_PHASE2_PRODUCT_QUALIFICATION:-}"
network_mode="${BONVOYAGE_NETWORK_MODE:-loopback}"
network_nic="${BONVOYAGE_NETWORK_NIC:-lo}"
network_speed_mbps="${BONVOYAGE_NETWORK_SPEED_MBPS:-100000}"
network_mtu="${BONVOYAGE_NETWORK_MTU:-65536}"

fail() {
  echo "phase2: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command '$1' is unavailable"
}

require_positive_integer() {
  case "$2" in ''|*[!0-9]*) fail "$1 must be a positive integer" ;; esac
  [ "$2" -gt 0 ] || fail "$1 must be a positive integer"
}

product_selected() {
  case " $comparison_products " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
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
      '{ print $1 " " label }' >>"$assignments_file"
  done
  conflict="$(sort -n "$assignments_file" | awk '
    seen[$1] { print "CPU " $1 " is shared by " owner[$1] " and " $2; exit }
    { seen[$1] = 1; owner[$1] = $2 }
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
    'BEGIN { printf "%.0f", number * multiplier }'
}

for command_name in awk date docker git go grep jq mktemp node sed sort tr wc; do
  require_command "$command_name"
done
if ! command -v sha256sum >/dev/null 2>&1; then
  require_command shasum
fi
selected_products_seen=""
selected_products_count=0
for selected_product in $comparison_products; do
  case "$selected_product" in
    bonvoyage|envoy|nginx|haproxy) ;;
    *) fail "unsupported Phase 2 product '$selected_product'" ;;
  esac
  case " $selected_products_seen " in
    *" $selected_product "*) fail "duplicate Phase 2 product '$selected_product'" ;;
  esac
  selected_products_seen="$selected_products_seen $selected_product"
  selected_products_count=$((selected_products_count + 1))
done
[ "$selected_products_count" -ge 2 ] || \
  fail "Phase 2 requires BonVoyage and at least one comparator"
product_selected bonvoyage || fail "Phase 2 product selection must include bonvoyage"
deferred_products=""
selected_comparators=""
for candidate_product in bonvoyage envoy nginx haproxy; do
  if ! product_selected "$candidate_product"; then
    deferred_products="${deferred_products:+$deferred_products }$candidate_product"
  elif [ "$candidate_product" != "bonvoyage" ]; then
    selected_comparators="${selected_comparators:+$selected_comparators }$candidate_product"
  fi
done
selected_comparators_json="$(printf '%s\n' "$selected_comparators" | \
  tr ' ' '\n' | jq -R . | jq -s 'sort')"
for value in \
  "warm-up=$warmup_seconds" \
  "discovery=$discovery_seconds" \
  "measurement=$measurement_seconds" \
  "churn=$churn_seconds" \
  "repetitions=$repetitions" \
  "resilience-repetitions=$resilience_repetitions" \
  "upstream-capacity=$upstream_capacity_seconds" \
  "minimum-resource-samples=$minimum_resource_samples" \
  "one-core-concurrency=$one_concurrency" \
  "two-core-concurrency=$two_concurrency"; do
  require_positive_integer "${value%%=*}" "${value#*=}"
done
[ "$repetitions" -ge 5 ] || fail "at least five repetitions are required"

one_cpu_count="$(expand_cpu_set "$gateway_one_cpus" | wc -l | tr -d ' ')"
two_cpu_count="$(expand_cpu_set "$gateway_two_cpus" | wc -l | tr -d ' ')"
loadgen_cpu_count="$(expand_cpu_set "$load_generator_cpus" | wc -l | tr -d ' ')"
upstream_cpu_count="$(expand_cpu_set "$upstream_cpus" | wc -l | tr -d ' ')"
[ "$one_cpu_count" -eq 1 ] || fail "one-core CPU set must contain one CPU"
[ "$two_cpu_count" -eq 2 ] || fail "two-core CPU set must contain two CPUs"
gateway_one_cpu="$(expand_cpu_set "$gateway_one_cpus")"
expand_cpu_set "$gateway_two_cpus" | grep -Fxq "$gateway_one_cpu" || \
  fail "the one-core CPU must also be present in the two-core CPU set"
assert_disjoint \
  "gateway=$gateway_one_cpus" \
  "load-generator=$load_generator_cpus" \
  "upstream=$upstream_cpus"
assert_disjoint \
  "gateway=$gateway_two_cpus" \
  "load-generator=$load_generator_cpus" \
  "upstream=$upstream_cpus"

docker_arch="$(docker info --format '{{.Architecture}}')"
docker_cpus="$(docker info --format '{{.NCPU}}')"
case "$docker_arch" in
  x86_64|amd64)
    platform="linux/amd64"
    manifest_key="linux_amd64"
    architecture="x86_64"
    ;;
  aarch64|arm64)
    platform="linux/arm64"
    manifest_key="linux_arm64"
    architecture="aarch64"
    ;;
  *) fail "unsupported Docker architecture '$docker_arch'" ;;
esac
highest_cpu="$({
  expand_cpu_set "$gateway_two_cpus"
  expand_cpu_set "$load_generator_cpus"
  expand_cpu_set "$upstream_cpus"
} | sort -n | tail -n 1)"
[ "$highest_cpu" -lt "$docker_cpus" ] || \
  fail "CPU $highest_cpu is outside Docker's $docker_cpus logical CPUs"

git_commit="$(git rev-parse HEAD)"
printf '%s\n' "$git_commit" | grep -Eq '^[0-9a-f]{40}$' || \
  fail "a full Git commit is required"
source_changes="$(git status --porcelain -- . \
  ':(exclude)benchmarks/results/**' 2>/dev/null || true)"
git_dirty=false
[ -z "$source_changes" ] || git_dirty=true

evidence_class="local-functional"
publication_authorized=false
publication_notes='["local or virtualized evidence is not a public performance claim"]'
if [ -n "$deferred_products" ]; then
  publication_notes="$(jq -nc \
    --arg selected "$comparison_products" \
    --arg deferred "$deferred_products" \
    '["local or virtualized evidence is not a public performance claim",
      "exploratory subset selected: " + $selected,
      "comparators deferred from this run: " + $deferred]')"
fi
if [ "$publishable_request" = "1" ]; then
  [ -z "$deferred_products" ] || \
    fail "publishable mode requires BonVoyage and every locked comparator"
  [ "$(uname -s)" = "Linux" ] || fail "publishable mode requires native Linux"
  [ "$architecture" = "x86_64" ] || fail "publishable mode requires x86-64"
  [ "$git_dirty" = "false" ] || fail "publishable mode requires a clean source tree"
  [ "$irq_cpus" != "not-isolated-local-qualification" ] || \
    fail "publishable mode requires an explicit IRQ CPU allocation"
  irq_cpu_count="$(expand_cpu_set "$irq_cpus" | wc -l | tr -d ' ')" || \
    fail "publishable mode requires a valid IRQ CPU set"
  [ "$irq_cpu_count" -gt 0 ] || fail "publishable mode requires IRQ CPUs"
  assert_disjoint \
    "irq=$irq_cpus" \
    "gateway=$gateway_two_cpus" \
    "load-generator=$load_generator_cpus" \
    "upstream=$upstream_cpus"
  irq_highest_cpu="$(expand_cpu_set "$irq_cpus" | sort -n | tail -n 1)"
  [ "$irq_highest_cpu" -lt "$docker_cpus" ] || \
    fail "IRQ CPU $irq_highest_cpu is outside Docker's $docker_cpus logical CPUs"
  [ "$qualification_attestation" = "fairness-contract-reviewed" ] || \
    fail "publishable mode requires the fairness-contract attestation"
  [ -n "$phase1_evidence" ] && [ -f "$phase1_evidence" ] || \
    fail "BONVOYAGE_PHASE1_EVIDENCE must name the native Phase 1 summary"
  jq -e '.evidence_class == "native-qualification" and
    .gates.phase1_exit_pass == true' "$phase1_evidence" >/dev/null || \
    fail "native Phase 1 evidence has not passed"
  phase1_environment="$(find "$(dirname "$phase1_evidence")" -maxdepth 1 \
    -name '*.environment.json' -type f -print | sort | head -n 1)"
  [ -n "$phase1_environment" ] || \
    fail "native Phase 1 evidence lacks its environment manifest"
  jq -e --arg commit "$git_commit" \
    '.git.commit == $commit and .git.dirty == false' \
    "$phase1_environment" >/dev/null || \
    fail "native Phase 1 evidence is not from this clean source commit"
  threads_per_core="$(lscpu | awk -F: '/Thread\(s\) per core/ {gsub(/ /, "", $2); print $2}')"
  [ "$threads_per_core" = "1" ] || \
    fail "publishable mode requires SMT disabled (Thread(s) per core must be 1)"
  governors="$(find /sys/devices/system/cpu/cpufreq -name scaling_governor \
    -exec cat {} \; 2>/dev/null | sort -u | tr '\n' ' ')"
  [ "$governors" = "performance " ] || \
    fail "publishable mode requires the performance CPU governor"
  evidence_class="native-qualification"
  publication_authorized=true
  publication_notes='["operator attested physical CPU, IRQ, NUMA, thermal, firmware, and network isolation against the fairness contract"]'
fi

product_lock_sha256="$(sha256_file "$product_lock")"
if [ -z "$product_qualification" ]; then
  for candidate in $(find benchmarks/results/qualification \
    -name '*.qualification.json' -type f 2>/dev/null | sort -r); do
    if jq -e \
      --arg architecture "$architecture" \
      --arg lock "$product_lock_sha256" \
      --arg publishable "$publishable_request" \
      --argjson selected "$selected_comparators_json" \
      '.passed == true and .architecture == $architecture and
       .product_lock_sha256 == $lock and
       ([.products[].name] | sort) == $selected and
       ($publishable != "1" or .evidence_class == "native-qualification")' \
      "$candidate" >/dev/null; then
      product_qualification="$candidate"
      break
    fi
  done
fi
[ -n "$product_qualification" ] && [ -f "$product_qualification" ] || \
  fail "run make benchmark-phase2-products for this architecture first"
jq -e \
  --arg architecture "$architecture" \
  --arg lock "$product_lock_sha256" \
  --arg publishable "$publishable_request" \
  --argjson selected "$selected_comparators_json" \
  '.passed == true and .architecture == $architecture and
   .product_lock_sha256 == $lock and
   ([.products[].name] | sort) == $selected and
   ($publishable != "1" or .evidence_class == "native-qualification")' \
  "$product_qualification" >/dev/null || \
  fail "comparator qualification does not match this host and product lock"
for product in envoy nginx haproxy; do
  product_selected "$product" || continue
  locked_config="$(jq -r --arg product "$product" \
    '.products[] | select(.name == $product) | .config' "$product_lock")"
  locked_config_sha256="$(jq -r --arg product "$product" \
    '.products[] | select(.name == $product) | .config_sha256' "$product_lock")"
  qualification_config_sha256="$(jq -r --arg product "$product" \
    '.products[] | select(.name == $product) | .config_sha256' \
    "$product_qualification")"
  [ "$(sha256_file "$locked_config")" = "$locked_config_sha256" ] || \
    fail "$product config has changed since the product lock was written"
  [ "$qualification_config_sha256" = "$locked_config_sha256" ] || \
    fail "$product qualification is stale for the current config"
done

captured_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
run_stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
run_id="phase2-comparison-$run_stamp"
raw_relative="benchmarks/results/raw/$run_id"
report_relative="benchmarks/results/reports/$run_id.md"
raw_dir="$repo_root/$raw_relative"
report_path="$repo_root/$report_relative"
mkdir -p "$raw_dir" "$(dirname "$report_path")"
plan_path="$raw_dir/$run_id.plan.json"
node benchmarks/scripts/phase2-plan.mjs \
  --seed "$seed" \
  --repetitions "$repetitions" \
  --resilience-repetitions "$resilience_repetitions" \
  --output "$plan_path"
plan_id="$(jq -r '.plan_id' "$plan_path")"
cp "$product_qualification" "$raw_dir/comparator-qualification.json"

suffix="$$-$run_stamp"
gateway_name=""
gateway_product=""
gateway_instance_label=""
gateway_initial_process_identity=""
loadgen_name=""
upstream_name="bonvoyage-p2-upstream-$suffix"
extract_name=""

cleanup() {
  set +e
  [ -z "$loadgen_name" ] || docker rm --force "$loadgen_name" >/dev/null 2>&1
  [ -z "$gateway_name" ] || docker rm --force "$gateway_name" >/dev/null 2>&1
  [ -z "$upstream_name" ] || docker rm --force "$upstream_name" >/dev/null 2>&1
  [ -z "$extract_name" ] || docker rm --force "$extract_name" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

echo "Preparing Phase 2 images for $platform..."
if [ "$skip_build" != "1" ]; then
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

locked_product_image() {
  locked_product="$1"
  locked_repository="$(jq -r --arg product "$locked_product" \
    '.products[] | select(.name == $product) | .repository' "$product_lock")"
  locked_manifest="$(jq -r --arg product "$locked_product" --arg key "$manifest_key" \
    '.products[] | select(.name == $product) | .manifests[$key]' "$product_lock")"
  printf '%s@%s\n' "$locked_repository" "$locked_manifest"
}

loadgen_repository="$(jq -r '.load_generator.repository' "$product_lock")"
loadgen_manifest="$(jq -r --arg key "$manifest_key" \
  '.load_generator.manifests[$key]' "$product_lock")"
loadgen_image="$loadgen_repository@$loadgen_manifest"
envoy_image="$(locked_product_image envoy)"
nginx_image="$(locked_product_image nginx)"
haproxy_image="$(locked_product_image haproxy)"
if [ "$skip_pull" != "1" ]; then
  docker pull "$loadgen_image" >/dev/null
  for product in envoy nginx haproxy; do
    product_selected "$product" || continue
    docker pull "$(locked_product_image "$product")" >/dev/null
  done
fi

snapshot_path="$raw_dir/snapshot.pb"
(
  cd control-plane
  go run ./cmd/bonvoyage-control-plane \
    -input ../benchmarks/products/bonvoyage/host-network.yaml \
    -output "$snapshot_path"
)

dataplane_image_id="$(docker image inspect --format '{{.Id}}' "$dataplane_image")"
dataplane_version="$(docker image inspect \
  --format '{{index .Config.Labels "org.opencontainers.image.version"}}' \
  "$dataplane_image")"
snapshot_sha256="$(sha256_file "$snapshot_path")"
extract_name="bonvoyage-p2-extract-$suffix"
docker create --name "$extract_name" "$dataplane_image" --version >/dev/null
docker cp "$extract_name:/usr/local/bin/bonvoyage-dataplane" \
  "$raw_dir/.bonvoyage-dataplane" >/dev/null
dataplane_executable_sha256="$(sha256_file "$raw_dir/.bonvoyage-dataplane")"
docker rm "$extract_name" >/dev/null
extract_name=""
rm -f "$raw_dir/.bonvoyage-dataplane"

product_identity() {
  identity_product="$1"
  if [ "$identity_product" = "bonvoyage" ]; then
    jq -n \
      --arg name bonvoyage \
      --arg version "$dataplane_version" \
      --arg image_digest "$dataplane_image_id" \
      --arg config_sha256 "$snapshot_sha256" \
      --arg executable_sha256 "$dataplane_executable_sha256" \
      '{name: $name, version: $version, image_digest: $image_digest,
        config_sha256: $config_sha256,
        executable_sha256: $executable_sha256}'
  else
    jq -c --arg product "$identity_product" \
      '.products[] | select(.name == $product) |
       {name, version, image_digest: .image_manifest_digest, config_sha256,
        executable_sha256}' "$product_qualification"
  fi
}

product_image() {
  case "$1" in
    bonvoyage) printf '%s\n' "$dataplane_image" ;;
    envoy) printf '%s\n' "$envoy_image" ;;
    nginx) printf '%s\n' "$nginx_image" ;;
    haproxy) printf '%s\n' "$haproxy_image" ;;
    *) fail "unknown product '$1'" ;;
  esac
}

product_config() {
  case "$1" in
    envoy) printf '%s\n' benchmarks/products/envoy/envoy.yaml ;;
    nginx) printf '%s\n' benchmarks/products/nginx/nginx.conf ;;
    haproxy) printf '%s\n' benchmarks/products/haproxy/haproxy.cfg ;;
    *) fail "product '$1' has no text comparator config" ;;
  esac
}

fetch_url() {
  docker run --rm \
    --network host \
    --cpuset-cpus "$load_generator_cpus" \
    --entrypoint /usr/bin/wget \
    "$upstream_image" \
    -q -O - "$1"
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

gateway_readiness_path() {
  case "$1" in
    envoy) printf '%s\n' /ready ;;
    bonvoyage|nginx|haproxy) printf '%s\n' /health/ready ;;
    *) fail "unknown product '$1'" ;;
  esac
}

container_process_identity() {
  docker top "$1" -eo pid,comm 2>/dev/null | sed '1d' | sort
}

start_gateway() {
  start_product="$1"
  start_cores="$2"
  start_cpuset="$3"
  start_label="$4"
  safe_start_label="$(printf '%s' "$start_label" | tr '.' '-')"
  gateway_name="bonvoyage-p2-$start_product-${start_cores}c-$safe_start_label-$suffix"
  gateway_product="$start_product"
  gateway_instance_label="$safe_start_label"
  start_image="$(product_image "$start_product")"

  case "$start_product" in
    bonvoyage)
      docker run --detach \
        --name "$gateway_name" \
        --network host \
        --cpuset-cpus "$start_cpuset" \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --memory 512m \
        --memory-swap 512m \
        --pids-limit 4096 \
        --ulimit nofile=1048576:1048576 \
        --volume "$snapshot_path:/etc/bonvoyage/snapshot.pb:ro" \
        "$start_image" \
        --snapshot /etc/bonvoyage/snapshot.pb \
        --admin-address 127.0.0.1 \
        --metrics-address 127.0.0.1 \
        --smp "$start_cores" \
        --memory 384M >/dev/null
      ;;
    envoy)
      start_config="$(product_config "$start_product")"
      docker run --detach \
        --name "$gateway_name" \
        --network host \
        --cpuset-cpus "$start_cpuset" \
        --user 65532:65532 \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --memory 512m \
        --memory-swap 512m \
        --pids-limit 4096 \
        --ulimit nofile=1048576:1048576 \
        --volume "$repo_root/$start_config:/etc/phase2/envoy.yaml:ro" \
        --entrypoint /usr/local/bin/envoy \
        "$start_image" \
        -c /etc/phase2/envoy.yaml \
        --concurrency "$start_cores" \
        --disable-hot-restart \
        --log-level critical >/dev/null
      ;;
    nginx)
      start_config="$(product_config "$start_product")"
      docker run --detach \
        --name "$gateway_name" \
        --network host \
        --cpuset-cpus "$start_cpuset" \
        --user 65532:65532 \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --memory 512m \
        --memory-swap 512m \
        --pids-limit 4096 \
        --ulimit nofile=1048576:1048576 \
        --volume "$repo_root/$start_config:/etc/nginx/nginx.conf:ro" \
        --entrypoint /usr/sbin/nginx \
        "$start_image" \
        -c /etc/nginx/nginx.conf \
        -g "daemon off; worker_processes $start_cores;" >/dev/null
      ;;
    haproxy)
      start_config="$(product_config "$start_product")"
      docker run --detach \
        --name "$gateway_name" \
        --network host \
        --cpuset-cpus "$start_cpuset" \
        --user 65532:65532 \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --memory 512m \
        --memory-swap 512m \
        --pids-limit 4096 \
        --ulimit nofile=1048576:1048576 \
        --volume "$repo_root/$start_config:/usr/local/etc/haproxy/haproxy.cfg:ro" \
        --entrypoint /usr/local/sbin/haproxy \
        "$start_image" \
        -W -db -f /usr/local/etc/haproxy/haproxy.cfg \
        -nbthread "$start_cores" >/dev/null
      ;;
    *) fail "unknown product '$start_product'" ;;
  esac

  readiness_path="$(gateway_readiness_path "$start_product")"
  if ! wait_for_url "http://127.0.0.1:9901$readiness_path" "$start_product"; then
    docker logs "$gateway_name" >&2 || true
    fail "$start_product failed to become ready"
  fi
  gateway_initial_process_identity="$(container_process_identity "$gateway_name")"
  [ -n "$gateway_initial_process_identity" ] || \
    fail "$start_product process identity could not be captured"
  fetch_url http://127.0.0.1:8080/payload/256 \
    >"$raw_dir/$start_product-${start_cores}core-$safe_start_label.payload"
  [ "$(wc -c <"$raw_dir/$start_product-${start_cores}core-$safe_start_label.payload" | tr -d ' ')" -eq 256 ] || \
    fail "$start_product returned the wrong payload size"
  [ "$(sha256_file "$raw_dir/$start_product-${start_cores}core-$safe_start_label.payload")" = \
    "85e62acd750c4eb56b7b6a1d66dca5bfaac5f062608a1a893410d0288936c09a" ] || \
    fail "$start_product returned the wrong payload digest"
}

stop_gateway() {
  [ -n "$gateway_name" ] || return 0
  stop_name="$gateway_name"
  stop_product="$gateway_product"
  stop_label="$gateway_instance_label"
  docker stop --timeout 30 "$stop_name" >/dev/null
  docker logs "$stop_name" \
    >"$raw_dir/$stop_product-$stop_label.gateway.log" 2>&1
  stop_exit="$(docker inspect --format '{{.State.ExitCode}}' "$stop_name")"
  docker rm "$stop_name" >/dev/null
  gateway_name=""
  gateway_product=""
  gateway_instance_label=""
  gateway_initial_process_identity=""
  [ "$stop_exit" -eq 0 ] || fail "$stop_product exited with status $stop_exit"
}

warm_gateway() {
  warm_product="$1"
  warm_cores="$2"
  warm_concurrency="$3"
  warm_label="$4"
  echo "    warming $warm_product ${warm_cores}-core for ${warmup_seconds}s"
  docker run --rm \
    --network host \
    --cpuset-cpus "$load_generator_cpus" \
    "$loadgen_image" \
    -z "${warmup_seconds}s" \
    -c "$warm_concurrency" \
    -w \
    --no-tui \
    --output-format json \
    http://127.0.0.1:8080/payload/256 \
    >"$raw_dir/$warm_label.warmup.oha.json"
}

echo "Starting the controlled upstream..."
docker run --detach \
  --name "$upstream_name" \
  --network host \
  --cpuset-cpus "$upstream_cpus" \
  --memory 512m \
  --memory-swap 512m \
  --pids-limit 4096 \
  --ulimit nofile=1048576:1048576 \
  "$upstream_image" >/dev/null
if ! wait_for_url http://127.0.0.1:8081/healthz "controlled upstream"; then
  docker logs "$upstream_name" >&2 || true
  fail "controlled upstream failed to start"
fi
fetch_url http://127.0.0.1:8081/payload/256 \
  >"$raw_dir/controlled-upstream.payload"
[ "$(sha256_file "$raw_dir/controlled-upstream.payload")" = \
  "85e62acd750c4eb56b7b6a1d66dca5bfaac5f062608a1a893410d0288936c09a" ] || \
  fail "controlled upstream payload failed identity verification"

echo "Measuring direct upstream and load-generator capacity..."
docker run --rm \
  --network host \
  --cpuset-cpus "$load_generator_cpus" \
  "$loadgen_image" \
  -z "${upstream_capacity_seconds}s" \
  -c "$two_concurrency" \
  -w \
  --no-tui \
  --output-format json \
  http://127.0.0.1:8081/payload/256 \
  >"$raw_dir/upstream-capacity.oha.json"
jq -e '
  ([.statusCodeDistribution[]?] | add // 0) > 0 and
  ([.statusCodeDistribution | to_entries[]? |
    select(.key != "200") | .value] | add // 0) == 0 and
  ([.errorDistribution[]?] | add // 0) == 0
' \
  "$raw_dir/upstream-capacity.oha.json" >/dev/null || \
  fail "direct upstream HTTP 200 capacity preflight failed"
upstream_capacity_rps="$(jq -r \
  '(.statusCodeDistribution["200"] // 0) / .summary.total' \
  "$raw_dir/upstream-capacity.oha.json")"

docker_os="$(docker info --format '{{.OperatingSystem}}')"
docker_kernel="$(docker info --format '{{.KernelVersion}}')"
docker_memory="$(docker info --format '{{.MemTotal}}')"
docker_engine_version="$(docker version --format '{{.Server.Version}}')"
cpu_model="$(docker run --rm --entrypoint /bin/sh "$upstream_image" -c \
  'awk -F: '\''/model name|Hardware|Processor/ { sub(/^[[:space:]]+/, "", $2); if ($2 != "") { print $2; exit } }'\'' /proc/cpuinfo')"
[ -n "$cpu_model" ] || cpu_model="unavailable in container runtime"

physical_cores="$docker_cpus"
smt_enabled=false
governor="unavailable in container runtime"
frequency_driver="unavailable in container runtime"
turbo_policy="unavailable in container runtime"
numa_nodes=1
if [ "$(uname -s)" = "Linux" ]; then
  physical_cores="$(lscpu -p=SOCKET,CORE | grep -v '^#' | sort -u | wc -l | tr -d ' ')"
  threads_per_core="$(lscpu | awk -F: '/Thread\(s\) per core/ {gsub(/ /, "", $2); print $2}')"
  [ "${threads_per_core:-1}" -gt 1 ] && smt_enabled=true
  governor="$(find /sys/devices/system/cpu/cpufreq -name scaling_governor \
    -exec cat {} \; 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')"
  [ -n "$governor" ] || governor="unavailable"
  frequency_driver="$(find /sys/devices/system/cpu/cpufreq -name scaling_driver \
    -exec cat {} \; 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')"
  [ -n "$frequency_driver" ] || frequency_driver="unavailable"
  if [ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
    turbo_policy="intel_pstate_no_turbo=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)"
  elif [ -f /sys/devices/system/cpu/cpufreq/boost ]; then
    turbo_policy="cpufreq_boost=$(cat /sys/devices/system/cpu/cpufreq/boost)"
  else
    turbo_policy="unavailable"
  fi
  numa_nodes="$(lscpu | awk -F: '/NUMA node\(s\)/ {gsub(/ /, "", $2); print $2}')"
  [ -n "$numa_nodes" ] || numa_nodes=1
  lscpu --extended >"$raw_dir/host-lscpu.txt"
  cp /proc/interrupts "$raw_dir/host-interrupts.txt" 2>/dev/null || true
  find /sys/devices/system/cpu/cpufreq -name scaling_cur_freq -exec sh -c \
    'printf "%s " "$1"; cat "$1"' sh {} \; \
    >"$raw_dir/host-frequency-before.txt" 2>/dev/null || true
fi
docker info >"$raw_dir/docker-info.txt"
uname -a >"$raw_dir/uname.txt"

environment_path="$raw_dir/$run_id.environment.json"
jq -n \
  --arg captured_at "$captured_at" \
  --arg commit "$git_commit" \
  --argjson dirty "$git_dirty" \
  --arg os "$docker_os" \
  --arg kernel "$docker_kernel" \
  --arg architecture "$architecture" \
  --arg cpu_model "$cpu_model" \
  --argjson logical_cpus "$docker_cpus" \
  --argjson physical_cores "$physical_cores" \
  --argjson memory_bytes "$docker_memory" \
  --argjson smt_enabled "$smt_enabled" \
  --arg governor "$governor" \
  --arg frequency_driver "$frequency_driver" \
  --arg turbo_policy "$turbo_policy" \
  --argjson numa_nodes "$numa_nodes" \
  --arg mode "$network_mode" \
  --arg nic "$network_nic" \
  --argjson link_speed_mbps "$network_speed_mbps" \
  --argjson mtu "$network_mtu" \
  --arg engine_version "$docker_engine_version" \
  --arg load_generator "$load_generator_cpus" \
  --arg gateway "1 core: $gateway_one_cpus; 2 cores: $gateway_two_cpus" \
  --arg upstream "$upstream_cpus" \
  --arg irq "$irq_cpus" \
  --arg evidence_class "$evidence_class" \
  --argjson publication_authorized "$publication_authorized" \
  --argjson notes "$publication_notes" \
  '{
    schema_version: 2,
    captured_at: $captured_at,
    git: {commit: $commit, dirty: $dirty},
    host: {
      os: $os,
      kernel: $kernel,
      architecture: $architecture,
      cpu_model: $cpu_model,
      logical_cpus: $logical_cpus,
      physical_cores: $physical_cores,
      memory_bytes: $memory_bytes,
      smt_enabled: $smt_enabled,
      governor: $governor,
      frequency_driver: $frequency_driver,
      turbo_policy: $turbo_policy,
      numa_nodes: $numa_nodes
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
    },
    qualification: {
      evidence_class: $evidence_class,
      fairness_contract_attested: $publication_authorized,
      physical_core_isolation: $publication_authorized,
      irq_isolation: $publication_authorized,
      thermal_stability: $publication_authorized,
      publication_authorized: $publication_authorized,
      notes: $notes
    }
  }' >"$environment_path"
environment_sha256="$(sha256_file "$environment_path")"

container_context_switches() {
  context_container="$1"
  context_values="$(mktemp)"
  docker top "$context_container" -eo pid 2>/dev/null | awk 'NR > 1 {print $1}' | \
    while IFS= read -r process_id; do
      for status_path in /proc/"$process_id"/task/*/status; do
        [ -f "$status_path" ] || continue
        awk '/^(voluntary|nonvoluntary)_ctxt_switches:/ {sum += $2}
          END {print sum + 0}' "$status_path"
      done
    done >"$context_values"
  awk '{sum += $1} END {print sum + 0}' "$context_values"
  rm -f "$context_values"
}

network_byte_counter() {
  counter=0
  if [ "$(uname -s)" = "Linux" ]; then
    rx_path="/sys/class/net/$network_nic/statistics/rx_bytes"
    tx_path="/sys/class/net/$network_nic/statistics/tx_bytes"
    if [ -r "$rx_path" ] && [ -r "$tx_path" ]; then
      counter=$(( $(cat "$rx_path") + $(cat "$tx_path") ))
    fi
  fi
  printf '%s\n' "$counter"
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

append_reason() {
  printf '%s\n' "$1" >>"$measurement_reasons"
}

measure_point() {
  measurement_product="$1"
  measurement_cores="$2"
  measurement_concurrency="$3"
  measurement_stage="$4"
  measurement_repetition="$5"
  measurement_attempt="$6"
  measurement_offered_rps="$7"
  measurement_duration="$8"
  measurement_schedule_key="$9"
  shift 9
  measurement_position="$1"
  measurement_utilization="$2"
  measurement_intentional_overload="$3"
  measurement_keepalive="$4"
  measurement_initial_container_id="$5"
  measurement_previous_offered="$6"
  measurement_previous_successful="$7"

  utilization_label="$measurement_utilization"
  [ "$utilization_label" != "none" ] || utilization_label="na"
  safe_utilization="$(printf '%s' "$utilization_label" | tr '.' 'p')"
  measurement_base="$measurement_product-${measurement_cores}core-$measurement_stage-rep${measurement_repetition}-u${safe_utilization}-a${measurement_attempt}"
  measurement_raw="$raw_dir/$measurement_base.oha.json"
  measurement_stats="$raw_dir/$measurement_base.stats.tsv"
  measurement_reasons="$raw_dir/$measurement_base.reasons.txt"
  measurement_result="$raw_dir/$measurement_base.result.json"
  measurement_sample="$raw_dir/.$measurement_base.stats.sample"
  measurement_processes_before="$raw_dir/$measurement_base.processes-before.txt"
  measurement_processes_after="$raw_dir/$measurement_base.processes-after.txt"
  : >"$measurement_stats"
  : >"$measurement_reasons"

  measurement_started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  context_start="$(container_context_switches "$gateway_name")"
  network_start="$(network_byte_counter)"
  rss_before="$(container_process_rss_bytes "$gateway_name")" || rss_before=0
  restart_before="$(docker inspect --format '{{.RestartCount}}' "$gateway_name")"
  container_id_before="$(docker inspect --format '{{.Id}}' "$gateway_name")"
  container_process_identity "$gateway_name" >"$measurement_processes_before"

  loadgen_name="bonvoyage-p2-oha-$measurement_base-$suffix"
  set -- \
    -z "${measurement_duration}s" \
    -c "$measurement_concurrency" \
    -w \
    --http-version 1.1 \
    --disable-compression \
    -H 'accept: application/octet-stream' \
    --no-tui \
    --output-format json
  if awk -v offered="$measurement_offered_rps" 'BEGIN {exit !(offered > 0)}'; then
    set -- "$@" -q "$measurement_offered_rps" --latency-correction
  fi
  if [ "$measurement_keepalive" = "false" ]; then
    set -- "$@" --disable-keepalive
  fi
  set -- "$@" http://127.0.0.1:8080/payload/256

  docker run --detach \
    --name "$loadgen_name" \
    --network host \
    --cpuset-cpus "$load_generator_cpus" \
    "$loadgen_image" "$@" >/dev/null

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
        "$sample_time" "$sample_name" "$sample_cpu" "$sample_memory_bytes" \
        "$sample_process_rss"
    done <"$measurement_sample" >>"$measurement_stats"
    sleep 1
  done
  rm -f "$measurement_sample"

  measurement_exit="$(docker wait "$loadgen_name")"
  docker logs "$loadgen_name" >"$measurement_raw" 2>&1
  docker rm "$loadgen_name" >/dev/null
  loadgen_name=""
  [ "$measurement_exit" -eq 0 ] || \
    append_reason "load generator exited with status $measurement_exit"
  if ! jq -e '.summary.requestsPerSec > 0 and .summary.successRate >= 0' \
    "$measurement_raw" >/dev/null 2>&1; then
    fail "$measurement_base did not produce valid oha JSON"
  fi

  actual_duration="$(jq -r '.summary.total' "$measurement_raw")"
  successful_requests="$(jq -r \
    '.statusCodeDistribution["200"] // 0' "$measurement_raw")"
  completed_requests="$(jq -r '
    ([.statusCodeDistribution[]?] | add // 0) +
    ([.errorDistribution[]?] | add // 0)
  ' "$measurement_raw")"
  successful_rps="$(awk -v successful="$successful_requests" \
    -v duration="$actual_duration" \
    'BEGIN {if (duration <= 0) print 0; else printf "%.12f", successful / duration}')"
  error_rate="$(awk -v successful="$successful_requests" \
    -v completed="$completed_requests" \
    'BEGIN {if (completed <= 0) print 1;
      else printf "%.12f", 1 - successful / completed}')"
  p50_ms="$(jq -r '.latencyPercentiles.p50 * 1000' "$measurement_raw")"
  p95_ms="$(jq -r '.latencyPercentiles.p95 * 1000' "$measurement_raw")"
  p99_ms="$(jq -r '.latencyPercentiles.p99 * 1000' "$measurement_raw")"
  p999_ms="$(jq -r '.latencyPercentiles["p99.9"] * 1000' "$measurement_raw")"

  gateway_sample_count="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name {count++} END {print count + 0}' "$measurement_stats")"
  upstream_sample_count="$(awk -F '\t' -v name="$upstream_name" '
    $2 == name {count++} END {print count + 0}' "$measurement_stats")"
  measured_loadgen_name="bonvoyage-p2-oha-$measurement_base-$suffix"
  loadgen_sample_count="$(awk -F '\t' -v name="$measured_loadgen_name" '
    $2 == name {count++} END {print count + 0}' "$measurement_stats")"
  for resource_sample in \
    "gateway=$gateway_sample_count" \
    "upstream=$upstream_sample_count" \
    "load-generator=$loadgen_sample_count"; do
    if [ "${resource_sample#*=}" -lt "$minimum_resource_samples" ]; then
      append_reason "${resource_sample%%=*} supplied fewer than $minimum_resource_samples resource samples"
    fi
  done

  gateway_cpu="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name {sum += $3; count++}
    END {if (count == 0) print 0; else printf "%.6f", sum / count}
  ' "$measurement_stats")"
  gateway_container_memory="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name && $4 > maximum {maximum = $4}
    END {printf "%.0f", maximum + 0}
  ' "$measurement_stats")"
  gateway_rss="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name && $5 > maximum {maximum = $5}
    END {printf "%.0f", maximum + 0}
  ' "$measurement_stats")"
  [ "$gateway_rss" -gt 0 ] || gateway_rss="$rss_before"
  gateway_rss_start="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name && $5 > 0 {print $5; exit}
  ' "$measurement_stats")"
  gateway_rss_end="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name && $5 > 0 {value = $5}
    END {print value + 0}
  ' "$measurement_stats")"
  [ -n "$gateway_rss_start" ] || gateway_rss_start="$rss_before"
  [ "$gateway_rss_end" -gt 0 ] || gateway_rss_end="$rss_before"
  gateway_rss_sample_count="$(awk -F '\t' -v name="$gateway_name" '
    $2 == name && $5 > 0 {count++} END {print count + 0}' \
    "$measurement_stats")"
  upstream_cpu="$(awk -F '\t' -v name="$upstream_name" '
    $2 == name {sum += $3; count++}
    END {if (count == 0) print 0; else printf "%.6f", sum / count}
  ' "$measurement_stats")"
  loadgen_cpu="$(awk -F '\t' -v name="$measured_loadgen_name" '
    $2 == name {sum += $3; count++}
    END {if (count == 0) print 0; else printf "%.6f", sum / count}
  ' "$measurement_stats")"
  upstream_capacity_percent="$(awk -v cpu="$upstream_cpu" \
    -v count="$upstream_cpu_count" 'BEGIN {printf "%.6f", cpu / count}')"
  loadgen_capacity_percent="$(awk -v cpu="$loadgen_cpu" \
    -v count="$loadgen_cpu_count" 'BEGIN {printf "%.6f", cpu / count}')"

  context_end="$(container_context_switches "$gateway_name")"
  network_end="$(network_byte_counter)"
  context_rate="$(awk -v start="$context_start" -v end="$context_end" \
    -v duration="$actual_duration" \
    'BEGIN {delta = end - start; if (delta < 0 || duration <= 0) delta = 0;
      printf "%.6f", delta / duration}')"
  network_rate="$(awk -v start="$network_start" -v end="$network_end" \
    -v duration="$actual_duration" \
    'BEGIN {delta = end - start; if (delta < 0 || duration <= 0) delta = 0;
      printf "%.6f", delta / duration}')"
  rss_growth="$((gateway_rss_end - gateway_rss_start))"
  rss_slope="$(awk -v growth="$rss_growth" -v duration="$actual_duration" \
    'BEGIN {if (duration <= 0) print 0; else printf "%.6f", growth / duration}')"

  gateway_running="$(docker inspect --format '{{.State.Running}}' "$gateway_name")"
  restart_after="$(docker inspect --format '{{.RestartCount}}' "$gateway_name")"
  container_id_after="$(docker inspect --format '{{.Id}}' "$gateway_name")"
  container_process_identity "$gateway_name" >"$measurement_processes_after" || true
  process_identity_before="$(cat "$measurement_processes_before")"
  process_identity_after="$(cat "$measurement_processes_after")"
  process_restarted=false
  if [ "$restart_after" -ne "$restart_before" ] || \
     [ "$container_id_after" != "$container_id_before" ] || \
     [ -z "$process_identity_after" ] || \
     [ "$process_identity_after" != "$process_identity_before" ] || \
     [ "$process_identity_after" != "$gateway_initial_process_identity" ] || \
     { [ -n "$measurement_initial_container_id" ] && \
       [ "$container_id_after" != "$measurement_initial_container_id" ]; }; then
    process_restarted=true
  fi

  if [ "$gateway_running" != "true" ]; then
    append_reason "gateway process stopped during the measurement"
  fi
  if [ "$measurement_intentional_overload" != "true" ]; then
    if awk -v value="$error_rate" -v limit="$maximum_error_rate" \
      'BEGIN {exit !(value > limit)}'; then
      append_reason "error rate exceeded $maximum_error_rate"
    fi
    if awk -v value="$p999_ms" -v limit="$latency_ceiling_ms" \
      'BEGIN {exit !(value > limit)}'; then
      append_reason "p99.9 exceeded ${latency_ceiling_ms}ms"
    fi
    if awk -v value="$upstream_capacity_percent" \
      -v limit="$maximum_support_capacity_percent" \
      'BEGIN {exit !(value > limit)}'; then
      append_reason "upstream exceeded ${maximum_support_capacity_percent}% capacity"
    fi
    if awk -v value="$loadgen_capacity_percent" \
      -v limit="$maximum_support_capacity_percent" \
      'BEGIN {exit !(value > limit)}'; then
      append_reason "load generator exceeded ${maximum_support_capacity_percent}% capacity"
    fi
    if awk -v offered="$measurement_previous_offered" \
      -v previous="$measurement_previous_successful" \
      -v current_offered="$measurement_offered_rps" \
      -v current="$successful_rps" \
      'BEGIN {exit !(offered > 0 && previous > 0 &&
        current_offered >= offered * 1.04 && current < previous * 1.02)}'; then
      append_reason "successful throughput plateaued after at least a 4% offered-load increase"
    fi
  fi
  if [ "$measurement_stage" = "connection-churn" ] && \
     [ "$gateway_rss_sample_count" -lt "$minimum_resource_samples" ]; then
    append_reason "gateway supplied fewer than $minimum_resource_samples process RSS samples"
  fi

  reasons_json="$(jq -R -s 'split("\n") | map(select(length > 0))' \
    "$measurement_reasons")"
  valid=true
  [ "$(printf '%s' "$reasons_json" | jq 'length')" -eq 0 ] || valid=false
  product_json="$(product_identity "$measurement_product")"
  raw_oha="$raw_relative/$measurement_base.oha.json"
  raw_stats="$raw_relative/$measurement_base.stats.tsv"
  raw_reasons="$raw_relative/$measurement_base.reasons.txt"
  raw_processes_before="$raw_relative/$measurement_base.processes-before.txt"
  raw_processes_after="$raw_relative/$measurement_base.processes-after.txt"

  jq -n \
    --arg run_id "$run_id" \
    --arg workload_id "$workload_id" \
    --arg environment_sha256 "$environment_sha256" \
    --argjson product "$product_json" \
    --arg started_at "$measurement_started_at" \
    --arg stage "$measurement_stage" \
    --arg plan_id "$plan_id" \
    --arg schedule_key "$measurement_schedule_key" \
    --arg utilization "$measurement_utilization" \
    --arg container_id "$container_id_after" \
    --arg recovery_of "$measurement_schedule_key" \
    --argjson cores "$measurement_cores" \
    --argjson repetition "$measurement_repetition" \
    --argjson attempt "$measurement_attempt" \
    --argjson offered_rps "$measurement_offered_rps" \
    --argjson position "$measurement_position" \
    --argjson duration_seconds "$measurement_duration" \
    --argjson successful_rps "$successful_rps" \
    --argjson error_rate "$error_rate" \
    --argjson p50 "$p50_ms" \
    --argjson p95 "$p95_ms" \
    --argjson p99 "$p99_ms" \
    --argjson p999 "$p999_ms" \
    --argjson gateway_cpu "$gateway_cpu" \
    --argjson gateway_container_memory "$gateway_container_memory" \
    --argjson gateway_rss "$gateway_rss" \
    --argjson gateway_rss_start "$gateway_rss_start" \
    --argjson gateway_rss_end "$gateway_rss_end" \
    --argjson connections "$measurement_concurrency" \
    --argjson completed_requests "$completed_requests" \
    --argjson context_rate "$context_rate" \
    --argjson network_rate "$network_rate" \
    --argjson upstream_cpu "$upstream_cpu" \
    --argjson upstream_capacity "$upstream_capacity_percent" \
    --argjson loadgen_cpu "$loadgen_cpu" \
    --argjson loadgen_capacity "$loadgen_capacity_percent" \
    --argjson valid "$valid" \
    --argjson reasons "$reasons_json" \
    --argjson intentional_overload "$measurement_intentional_overload" \
    --argjson process_restarted "$process_restarted" \
    --argjson rss_growth "$rss_growth" \
    --argjson rss_slope "$rss_slope" \
    --arg raw_oha "$raw_oha" \
    --arg raw_stats "$raw_stats" \
    --arg raw_reasons "$raw_reasons" \
    --arg raw_processes_before "$raw_processes_before" \
    --arg raw_processes_after "$raw_processes_after" \
    '{
      schema_version: 2,
      fixture: false,
      run_id: $run_id,
      workload_id: $workload_id,
      environment_sha256: $environment_sha256,
      product: $product,
      execution: ({
        started_at: $started_at,
        gateway_cores: $cores,
        repetition: $repetition,
        offered_rps: $offered_rps,
        stage: $stage,
        plan_id: $plan_id,
        schedule_key: $schedule_key,
        randomized_position: $position,
        attempt: $attempt,
        duration_seconds: $duration_seconds
      } + if $utilization == "none" then {} else
        {utilization_target: ($utilization | tonumber)} end),
      metrics: {
        successful_rps: $successful_rps,
        error_rate: $error_rate,
        latency_ms: {p50: $p50, p95: $p95, p99: $p99, p999: $p999},
        gateway_cpu_percent: $gateway_cpu,
        gateway_container_memory_usage_bytes: $gateway_container_memory,
        gateway_rss_bytes: $gateway_rss,
        gateway_rss_start_bytes: $gateway_rss_start,
        gateway_rss_end_bytes: $gateway_rss_end,
        connections: $connections,
        completed_requests: $completed_requests,
        context_switches_per_second: $context_rate,
        network_bytes_per_second: $network_rate,
        upstream_cpu_percent: $upstream_cpu,
        upstream_capacity_percent: $upstream_capacity,
        load_generator_cpu_percent: $loadgen_cpu,
        load_generator_capacity_percent: $loadgen_capacity
      },
      qualification: {
        valid: $valid,
        reasons: $reasons,
        intentional_overload: $intentional_overload
      },
      resilience: ({
        gateway_container_id: $container_id,
        process_restarted: $process_restarted,
        rss_growth_bytes: $rss_growth,
        rss_slope_bytes_per_second: $rss_slope
      } + if $stage == "recovery" then {recovery_of: $recovery_of} else {} end),
      raw_artifacts: [
        $raw_oha,
        $raw_stats,
        $raw_reasons,
        $raw_processes_before,
        $raw_processes_after
      ]
    }' >"$measurement_result"

  last_successful_rps="$successful_rps"
  last_valid="$valid"
  printf '      %s: %.0f successful RPS, p99.9 %.3f ms, valid=%s\n' \
    "$measurement_stage" "$successful_rps" "$p999_ms" "$valid"
  sleep "$cooldown_seconds"
}

capacity_path="$raw_dir/capacities.json"
printf '{}\n' >"$capacity_path"

set_capacity() {
  capacity_product="$1"
  capacity_cores="$2"
  capacity_rate="$3"
  capacity_tmp="$raw_dir/.capacities.tmp"
  jq \
    --arg product "$capacity_product" \
    --arg cores "$capacity_cores" \
    --argjson rate "$capacity_rate" \
    '.[$product][$cores] = $rate' "$capacity_path" >"$capacity_tmp"
  mv "$capacity_tmp" "$capacity_path"
}

get_capacity() {
  jq -er --arg product "$1" --arg cores "$2" \
    '.[$product][$cores]' "$capacity_path"
}

core_cpuset() {
  if [ "$1" -eq 1 ]; then
    printf '%s\n' "$gateway_one_cpus"
  else
    printf '%s\n' "$gateway_two_cpus"
  fi
}

core_concurrency() {
  if [ "$1" -eq 1 ]; then
    printf '%s\n' "$one_concurrency"
  else
    printf '%s\n' "$two_concurrency"
  fi
}

plan_order() {
  jq -er --arg key "$1" \
    '.groups[] | select(.key == $key) | .product_order[]' "$plan_path"
}

cp "$product_lock" "$raw_dir/product-lock.json"
cp benchmarks/products/envoy/envoy.yaml "$raw_dir/envoy.yaml"
cp benchmarks/products/nginx/nginx.conf "$raw_dir/nginx.conf"
cp benchmarks/products/haproxy/haproxy.cfg "$raw_dir/haproxy.cfg"
cp benchmarks/workloads/http1-keepalive/phase2-baseline.yaml \
  "$raw_dir/phase2-baseline.workload.yaml"
if [ -n "$phase1_evidence" ] && [ -f "$phase1_evidence" ]; then
  cp "$phase1_evidence" "$raw_dir/phase1-native-summary.json"
  if [ -n "$phase1_environment" ] && [ -f "$phase1_environment" ]; then
    cp "$phase1_environment" "$raw_dir/phase1-native-environment.json"
  fi
fi
for identity_image in \
  "$dataplane_image" "$upstream_image" "$loadgen_image" \
  "$envoy_image" "$nginx_image" "$haproxy_image"; do
  docker image inspect --format '{{json .}}' "$identity_image"
done >"$raw_dir/image-inspection.jsonl"

smoke_only="${BONVOYAGE_PHASE2_SMOKE_ONLY:-0}"
if [ "$smoke_only" = "1" ]; then
  smoke_product="${BONVOYAGE_PHASE2_SMOKE_PRODUCT:-envoy}"
  smoke_cores="${BONVOYAGE_PHASE2_SMOKE_CORES:-1}"
  case "$smoke_product" in
    bonvoyage|envoy|nginx|haproxy) ;;
    *) fail "unsupported smoke product '$smoke_product'" ;;
  esac
  product_selected "$smoke_product" || \
    fail "smoke product '$smoke_product' is not in BONVOYAGE_PHASE2_PRODUCTS"
  case "$smoke_cores" in
    1|2) ;;
    *) fail "smoke gateway cores must be 1 or 2" ;;
  esac
  smoke_cpuset="$(core_cpuset "$smoke_cores")"
  smoke_concurrency="$(core_concurrency "$smoke_cores")"
  smoke_key="capacity-discovery.${smoke_cores}core.rep1"
  smoke_position="$(jq -r --arg key "$smoke_key" --arg product "$smoke_product" '
    .groups[] | select(.key == $key) | .product_order |
    (index($product) + 1)' "$plan_path")"
  echo "Running a non-publishable Phase 2 measurement smoke for $smoke_product..."
  start_gateway "$smoke_product" "$smoke_cores" "$smoke_cpuset" \
    "smoke-$smoke_product"
  warm_gateway "$smoke_product" "$smoke_cores" "$smoke_concurrency" \
    "smoke-$smoke_product"
  initial_container_id="$(docker inspect --format '{{.Id}}' "$gateway_name")"
  measure_point \
    "$smoke_product" "$smoke_cores" "$smoke_concurrency" \
    capacity-probe 1 1 0 "$discovery_seconds" \
    "$smoke_key" "$smoke_position" none false true \
    "$initial_container_id" 0 0
  smoke_rate="$(awk -v capacity="$last_successful_rps" \
    'BEGIN {rate = int(capacity * 0.30 + 0.5); if (rate < 1) rate = 1; print rate}')"
  measure_point \
    "$smoke_product" "$smoke_cores" "$smoke_concurrency" \
    capacity-discovery 1 1 "$smoke_rate" "$discovery_seconds" \
    "$smoke_key" "$smoke_position" 0.3 false true \
    "$initial_container_id" 0 0
  set_capacity "$smoke_product" "$smoke_cores" "$smoke_rate"
  stop_gateway
else
echo "Discovering sustainable capacity with randomized product order..."
for cores in 1 2; do
  cpuset="$(core_cpuset "$cores")"
  concurrency="$(core_concurrency "$cores")"
  discovery_key="capacity-discovery.${cores}core.rep1"
  position=0
  for product in $(plan_order "$discovery_key"); do
    position=$((position + 1))
    if ! product_selected "$product"; then
      echo "  [$discovery_key position $position] $product deferred"
      continue
    fi
    echo "  [$discovery_key position $position] $product"
    instance_label="$discovery_key-$product"
    start_gateway "$product" "$cores" "$cpuset" "$instance_label"
    warm_gateway "$product" "$cores" "$concurrency" "$instance_label"
    initial_container_id="$(docker inspect --format '{{.Id}}' "$gateway_name")"

    measure_point \
      "$product" "$cores" "$concurrency" \
      capacity-probe 1 1 0 "$discovery_seconds" \
      "$discovery_key" "$position" none false true \
      "$initial_container_id" 0 0
    capacity_probe="$last_successful_rps"
    candidate_rate=0
    previous_offered=0
    previous_successful=0
    discovery_attempt=1
    for multiplier in $discovery_multipliers; do
      offered_rate="$(awk -v capacity="$capacity_probe" -v factor="$multiplier" \
        'BEGIN {rate = int(capacity * factor + 0.5); if (rate < 1) rate = 1; print rate}')"
      measure_point \
        "$product" "$cores" "$concurrency" \
        capacity-discovery 1 "$discovery_attempt" "$offered_rate" \
        "$discovery_seconds" "$discovery_key" "$position" "$multiplier" \
        false true "$initial_container_id" \
        "$previous_offered" "$previous_successful"
      if [ "$last_valid" != "true" ]; then
        break
      fi
      candidate_rate="$offered_rate"
      previous_offered="$offered_rate"
      previous_successful="$last_successful_rps"
      discovery_attempt=$((discovery_attempt + 1))
    done
    [ "$candidate_rate" -gt 0 ] || \
      fail "$product ${cores}-core discovery found no valid operating point"
    headroom_ratio="$(awk -v upstream="$upstream_capacity_rps" \
      -v gateway="$candidate_rate" 'BEGIN {printf "%.6f", upstream / gateway}')"
    if awk -v value="$headroom_ratio" -v minimum="$minimum_headroom_ratio" \
      'BEGIN {exit !(value < minimum)}'; then
      fail "$product ${cores}-core candidate lacks direct upstream headroom ($headroom_ratio)"
    fi
    set_capacity "$product" "$cores" "$candidate_rate"
    echo "    selected sustainable candidate: $candidate_rate RPS"
    stop_gateway
  done
done

echo "Confirming sustainable capacities with five randomized repetitions..."
for cores in 1 2; do
  cpuset="$(core_cpuset "$cores")"
  concurrency="$(core_concurrency "$cores")"
  repetition=1
  while [ "$repetition" -le "$repetitions" ]; do
    confirmation_key="capacity-confirmation.${cores}core.rep${repetition}"
    position=0
    for product in $(plan_order "$confirmation_key"); do
      position=$((position + 1))
      if ! product_selected "$product"; then
        echo "  [$confirmation_key position $position] $product deferred"
        continue
      fi
      offered_rate="$(get_capacity "$product" "$cores")"
      echo "  [$confirmation_key position $position] $product at $offered_rate RPS"
      instance_label="$confirmation_key-$product"
      start_gateway "$product" "$cores" "$cpuset" "$instance_label"
      warm_gateway "$product" "$cores" "$concurrency" "$instance_label"
      initial_container_id="$(docker inspect --format '{{.Id}}' "$gateway_name")"
      measure_point \
        "$product" "$cores" "$concurrency" \
        capacity-confirmation "$repetition" 1 "$offered_rate" \
        "$measurement_seconds" "$confirmation_key" "$position" none \
        false true "$initial_container_id" 0 0
      stop_gateway
    done
    repetition=$((repetition + 1))
  done
done

echo "Measuring 50/70/80/90/95 percent operating curves..."
for cores in 1 2; do
  cpuset="$(core_cpuset "$cores")"
  concurrency="$(core_concurrency "$cores")"
  repetition=1
  while [ "$repetition" -le "$repetitions" ]; do
    curve_key="operating-curve.${cores}core.rep${repetition}"
    position=0
    for product in $(plan_order "$curve_key"); do
      position=$((position + 1))
      if ! product_selected "$product"; then
        echo "  [$curve_key position $position] $product deferred"
        continue
      fi
      sustainable_rate="$(get_capacity "$product" "$cores")"
      echo "  [$curve_key position $position] $product"
      instance_label="$curve_key-$product"
      start_gateway "$product" "$cores" "$cpuset" "$instance_label"
      warm_gateway "$product" "$cores" "$concurrency" "$instance_label"
      initial_container_id="$(docker inspect --format '{{.Id}}' "$gateway_name")"
      for target in 0.5 0.7 0.8 0.9 0.95; do
        offered_rate="$(awk -v capacity="$sustainable_rate" -v factor="$target" \
          'BEGIN {rate = int(capacity * factor + 0.5); if (rate < 1) rate = 1; print rate}')"
        measure_point \
          "$product" "$cores" "$concurrency" \
          operating-curve "$repetition" 1 "$offered_rate" \
          "$measurement_seconds" "$curve_key" "$position" "$target" \
          false true "$initial_container_id" 0 0
      done
      stop_gateway
    done
    repetition=$((repetition + 1))
  done
done

echo "Testing overload recovery and connection churn..."
repetition=1
while [ "$repetition" -le "$resilience_repetitions" ]; do
  resilience_key="resilience.2core.rep${repetition}"
  position=0
  for product in $(plan_order "$resilience_key"); do
    position=$((position + 1))
    if ! product_selected "$product"; then
      echo "  [$resilience_key position $position] $product deferred"
      continue
    fi
    sustainable_rate="$(get_capacity "$product" 2)"
    overload_rate="$(awk -v capacity="$sustainable_rate" \
      'BEGIN {print int(capacity * 1.20 + 0.5)}')"
    recovery_rate="$(awk -v capacity="$sustainable_rate" \
      'BEGIN {print int(capacity * 0.70 + 0.5)}')"
    churn_rate="$(awk -v capacity="$sustainable_rate" \
      'BEGIN {print int(capacity * 0.50 + 0.5)}')"
    echo "  [$resilience_key position $position] $product"
    instance_label="$resilience_key-$product"
    start_gateway "$product" 2 "$gateway_two_cpus" "$instance_label"
    warm_gateway "$product" 2 "$two_concurrency" "$instance_label"
    initial_container_id="$(docker inspect --format '{{.Id}}' "$gateway_name")"
    measure_point \
      "$product" 2 "$two_concurrency" \
      overload "$repetition" 1 "$overload_rate" \
      "$measurement_seconds" "$resilience_key" "$position" 1.2 \
      true true "$initial_container_id" 0 0
    measure_point \
      "$product" 2 "$two_concurrency" \
      recovery "$repetition" 1 "$recovery_rate" \
      "$measurement_seconds" "$resilience_key" "$position" 0.7 \
      false true "$initial_container_id" 0 0
    measure_point \
      "$product" 2 "$two_concurrency" \
      connection-churn "$repetition" 1 "$churn_rate" \
      "$churn_seconds" "$resilience_key" "$position" 0.5 \
      false false "$initial_container_id" 0 0
    stop_gateway
  done
  repetition=$((repetition + 1))
done
fi

docker logs "$upstream_name" >"$raw_dir/upstream.log" 2>&1
docker stop --timeout 30 "$upstream_name" >/dev/null
upstream_exit="$(docker inspect --format '{{.State.ExitCode}}' "$upstream_name")"
docker rm "$upstream_name" >/dev/null
upstream_name=""
[ "$upstream_exit" -eq 0 ] || fail "controlled upstream exited $upstream_exit"

if [ "$(uname -s)" = "Linux" ]; then
  find /sys/devices/system/cpu/cpufreq -name scaling_cur_freq -exec sh -c \
    'printf "%s " "$1"; cat "$1"' sh {} \; \
    >"$raw_dir/host-frequency-after.txt" 2>/dev/null || true
fi

summary_path="$raw_dir/$run_id.summary.json"
node benchmarks/scripts/summarize-phase2.mjs \
  --raw-dir "$raw_dir" \
  --summary "$summary_path" \
  --report "$report_path"

if [ -d website/node_modules/ajv ]; then
  (cd website && npm run validate:project >/dev/null)
else
  echo "website dependencies are absent; run make benchmark-contracts to validate all result documents"
fi

phase2_exit_pass="$(jq -r '.gates.phase2_exit_pass' "$summary_path")"
decision="$(jq -r '.gates.decision' "$summary_path")"
echo "Phase 2 report: $report_relative"
echo "Decision: $decision"
echo "Canonical Phase 2 exit gate: $phase2_exit_pass"

require_phase2_gate="${BONVOYAGE_REQUIRE_PHASE2_GATE:-$publishable_request}"
if [ "$require_phase2_gate" = "1" ] && [ "$phase2_exit_pass" != "true" ]; then
  exit 2
fi
