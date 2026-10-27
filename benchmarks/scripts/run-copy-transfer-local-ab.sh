#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo="${BONVOYAGE_REPO:-$(CDPATH='' cd -- "$script_dir/../.." && pwd)}"
baseline_image="${BONVOYAGE_AB_BASELINE_IMAGE:-bonvoyage-dataplane:copy-transfer-baseline}"
candidate_image="${BONVOYAGE_AB_CANDIDATE_IMAGE:-bonvoyage-dataplane:copy-transfer-candidate}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-benchmark-upstream:phase2}"
loadgen_image="${BONVOYAGE_LOADGEN_IMAGE:-ghcr.io/hatoo/oha@sha256:7636e482ec11bd9a51c0fdf73ec075aad861a1eb227388c5ac6d694c986232c5}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
gateway_cpus="${BONVOYAGE_AB_GATEWAY_CPUS:-2-3}"
loadgen_cpus="${BONVOYAGE_AB_LOADGEN_CPUS:-4-7}"
upstream_cpus="${BONVOYAGE_AB_UPSTREAM_CPUS:-8-13}"
gateway_cores="${BONVOYAGE_AB_GATEWAY_CORES:-2}"
loadgen_cores="${BONVOYAGE_AB_LOADGEN_CORES:-4}"
upstream_cores="${BONVOYAGE_AB_UPSTREAM_CORES:-6}"
connections="${BONVOYAGE_AB_CONNECTIONS:-128}"
request_path="${BONVOYAGE_AB_REQUEST_PATH:-/payload/256}"
warmup_seconds="${BONVOYAGE_AB_WARMUP_SECONDS:-8}"
measurement_seconds="${BONVOYAGE_AB_MEASUREMENT_SECONDS:-15}"
experiment_id="${BONVOYAGE_AB_EXPERIMENT_ID:-copy-transfer-local-ab}"
report_title="${BONVOYAGE_AB_REPORT_TITLE:-Copy-transfer local A/B}"
evidence_class="${BONVOYAGE_AB_EVIDENCE_CLASS:-local-virtualized-balanced-optimization-ab}"
publication_reason="${BONVOYAGE_AB_PUBLICATION_REASON:-Docker Desktop ARM64 VM; engineering decision evidence only}"
sequence="baseline candidate candidate baseline baseline candidate candidate baseline baseline candidate"
stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
case "$experiment_id" in
  *[!a-z0-9-]*|'')
    echo "A/B experiment id must contain only lowercase letters, digits, and hyphens" >&2
    exit 2
    ;;
esac
run_id="$experiment_id-$stamp"
temporary_root="${TMPDIR:-/tmp}"
result_root="${BONVOYAGE_AB_RESULT_ROOT:-$temporary_root}"
run_dir="${BONVOYAGE_AB_RESULT_DIR:-$result_root/$run_id}"
suffix="$$-$stamp"
network="bonvoyage-copy-ab-$suffix"
volume="bonvoyage-copy-ab-$suffix"
upstream="bonvoyage-copy-ab-upstream-$suffix"
gateway=""
loadgen=""

fail() {
  echo "$experiment_id: $*" >&2
  exit 1
}

cleanup() {
  status="$?"
  set +e
  [ -z "$loadgen" ] || docker rm --force "$loadgen" >/dev/null 2>&1
  [ -z "$gateway" ] || docker rm --force "$gateway" >/dev/null 2>&1
  docker rm --force "$upstream" >/dev/null 2>&1
  docker network rm "$network" >/dev/null 2>&1
  docker volume rm "$volume" >/dev/null 2>&1
  exit "$status"
}
trap cleanup EXIT INT TERM

wait_for_gateway() {
  attempt=0
  until docker exec "$upstream" wget -q -O - \
      http://gateway:9901/health/ready >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 30 ] || return 1
    sleep 1
  done
}

mkdir -p "$run_dir"
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null

docker run --rm --platform "$platform" \
  --volume "$repo/config/examples/local.yaml:/etc/bonvoyage/local.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" \
  -input /etc/bonvoyage/local.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >/dev/null

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --cpuset-cpus "$upstream_cpus" --memory 1g --memory-swap 1g \
  --pids-limit 2048 --ulimit nofile=1048576:1048576 \
  "$upstream_image" >/dev/null

attempt=0
until docker exec "$upstream" wget -q -O - \
    http://127.0.0.1:8081/healthz >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 30 ] || fail "controlled upstream did not become ready"
  sleep 1
done

docker run --rm --platform "$platform" --network "$network" \
  --cpuset-cpus "$loadgen_cpus" "$loadgen_image" \
  -z 15s -c "$connections" -w --http-version 1.1 \
  --disable-compression -H 'accept: application/octet-stream' \
  --no-tui --no-color --output-format json \
  "http://upstream:8081$request_path" >"$run_dir/upstream-capacity.oha.json"

jq -e '
  .summary.requestsPerSec > 0 and
  ([.statusCodeDistribution | to_entries[]? | select(.key != "200") | .value] | add // 0) == 0 and
  ([.errorDistribution[]?] | add // 0) == 0
' "$run_dir/upstream-capacity.oha.json" >/dev/null || \
  fail "direct upstream capacity check failed"

git -C "$repo" rev-parse HEAD >"$run_dir/git-commit.txt"
git -C "$repo" status --short >"$run_dir/git-status.txt"
git -C "$repo" diff --binary >"$run_dir/candidate.diff"
docker image inspect "$baseline_image" >"$run_dir/baseline-image-inspect.json"
docker image inspect "$candidate_image" >"$run_dir/candidate-image-inspect.json"
docker image inspect "$upstream_image" >"$run_dir/upstream-image-inspect.json"
docker image inspect "$loadgen_image" >"$run_dir/loadgen-image-inspect.json"
docker info >"$run_dir/docker-info.txt"
uname -a >"$run_dir/uname.txt"
cp "$0" "$run_dir/run-copy-transfer-local-ab.sh"

baseline_rep=0
candidate_rep=0
order=0
for variant in $sequence; do
  order=$((order + 1))
  case "$variant" in
    baseline)
      baseline_rep=$((baseline_rep + 1))
      repetition="$baseline_rep"
      image="$baseline_image"
      ;;
    candidate)
      candidate_rep=$((candidate_rep + 1))
      repetition="$candidate_rep"
      image="$candidate_image"
      ;;
    *) fail "unknown variant $variant" ;;
  esac
  sample="$order-$variant-rep$repetition"
  gateway="bonvoyage-copy-ab-gateway-$order-$suffix"
  echo "[$order/10] $variant repetition $repetition"

  docker run --detach --platform "$platform" --name "$gateway" \
    --network "$network" --network-alias gateway \
    --cpuset-cpus "$gateway_cpus" --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    --cap-drop ALL --cap-add SYS_NICE --security-opt no-new-privileges \
    --memory 1g --memory-swap 1g --pids-limit 2048 \
    --ulimit nofile=1048576:1048576 \
    --volume "$volume:/etc/bonvoyage:ro" \
    "$image" --snapshot /etc/bonvoyage/snapshot.pb \
    --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
    --smp "$gateway_cores" --memory 384M --overprovisioned >/dev/null

  if ! wait_for_gateway; then
    docker logs "$gateway" >"$run_dir/$sample.gateway.log" 2>&1 || true
    fail "$sample gateway readiness failed"
  fi

  docker run --rm --platform "$platform" --network "$network" \
    --cpuset-cpus "$loadgen_cpus" "$loadgen_image" \
    -z "${warmup_seconds}s" -c "$connections" -w --http-version 1.1 \
    --disable-compression -H 'accept: application/octet-stream' \
    --no-tui --no-color --output-format json \
    "http://gateway:8080$request_path" >"$run_dir/$sample.warmup.oha.json"

  loadgen="bonvoyage-copy-ab-oha-$order-$suffix"
  docker run --detach --platform "$platform" --name "$loadgen" \
    --network "$network" --cpuset-cpus "$loadgen_cpus" \
    "$loadgen_image" -z "${measurement_seconds}s" -c "$connections" -w \
    --http-version 1.1 --disable-compression \
    -H 'accept: application/octet-stream' --no-tui --no-color \
    --output-format json "http://gateway:8080$request_path" >/dev/null

  stats="$run_dir/$sample.stats.tsv"
  printf 'epoch\trole\tcpu_percent\n' >"$stats"
  while [ "$(docker inspect --format '{{.State.Running}}' "$loadgen")" = true ]; do
    epoch="$(date -u '+%s')"
    docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}' \
      "$gateway" "$upstream" "$loadgen" 2>/dev/null | \
      while IFS='|' read -r name cpu; do
        cpu="${cpu%%%}"
        case "$name" in
          "$gateway") role=gateway ;;
          "$upstream") role=upstream ;;
          "$loadgen") role=loadgen ;;
          *) continue ;;
        esac
        printf '%s\t%s\t%s\n' "$epoch" "$role" "$cpu"
      done >>"$stats" || true
    sleep 1
  done

  load_exit="$(docker wait "$loadgen")"
  docker logs "$loadgen" >"$run_dir/$sample.oha.json" 2>&1
  docker rm "$loadgen" >/dev/null
  loadgen=""
  [ "$load_exit" -eq 0 ] || fail "$sample load generator exited $load_exit"

  jq -e '
    .summary.requestsPerSec > 0 and
    ([.statusCodeDistribution | to_entries[]? | select(.key != "200") | .value] | add // 0) == 0 and
    ([.errorDistribution[]?] | add // 0) == 0
  ' "$run_dir/$sample.oha.json" >/dev/null || fail "$sample returned errors"

  docker logs "$gateway" >"$run_dir/$sample.gateway.log" 2>&1
  [ "$(docker inspect --format '{{.State.OOMKilled}}' "$gateway")" = false ] || \
    fail "$sample gateway was OOM-killed"
  docker stop --timeout 30 "$gateway" >/dev/null
  gateway_exit="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
  docker rm "$gateway" >/dev/null
  gateway=""
  [ "$gateway_exit" -eq 0 ] || fail "$sample gateway exited $gateway_exit"

  duration="$(jq -r '.summary.total' "$run_dir/$sample.oha.json")"
  successful="$(jq -r '.statusCodeDistribution["200"] // 0' "$run_dir/$sample.oha.json")"
  successful_rps="$(awk -v successful="$successful" -v duration="$duration" \
    'BEGIN {printf "%.12f", successful / duration}')"
  p99_ms="$(jq -r '.latencyPercentiles.p99 * 1000' "$run_dir/$sample.oha.json")"
  p999_ms="$(jq -r '.latencyPercentiles["p99.9"] * 1000' "$run_dir/$sample.oha.json")"
  gateway_cpu="$(awk -F '\t' '$2 == "gateway" {sum += $3; count++} END {if (count) printf "%.6f", sum / count; else print 0}' "$stats")"
  upstream_cpu="$(awk -F '\t' '$2 == "upstream" {sum += $3; count++} END {if (count) printf "%.6f", sum / count; else print 0}' "$stats")"
  loadgen_cpu="$(awk -F '\t' '$2 == "loadgen" {sum += $3; count++} END {if (count) printf "%.6f", sum / count; else print 0}' "$stats")"
  image_id="$(docker image inspect --format '{{.Id}}' "$image")"

  jq -n --arg variant "$variant" --arg image "$image" \
    --arg image_id "$image_id" --argjson order "$order" \
    --argjson repetition "$repetition" --argjson successful_rps "$successful_rps" \
    --argjson p99_ms "$p99_ms" --argjson p999_ms "$p999_ms" \
    --argjson gateway_cpu "$gateway_cpu" --argjson upstream_cpu "$upstream_cpu" \
    --argjson loadgen_cpu "$loadgen_cpu" \
    '{variant: $variant, image: $image, image_id: $image_id, order: $order,
      repetition: $repetition, successful_rps: $successful_rps, error_rate: 0,
      latency_ms: {p99: $p99_ms, p999: $p999_ms},
      cpu_percent: {gateway: $gateway_cpu, upstream: $upstream_cpu,
                    load_generator: $loadgen_cpu}}' \
    >"$run_dir/$sample.result.json"
  printf '  %.0f RPS, p99.9 %.3f ms\n' "$successful_rps" "$p999_ms"
  sleep 2
done

docker logs "$upstream" >"$run_dir/upstream.log" 2>&1

jq -s --arg run_id "$run_id" \
  --arg evidence_class "$evidence_class" \
  --arg publication_reason "$publication_reason" \
  --arg platform "$platform" \
  --arg gateway_cpus "$gateway_cpus" --arg loadgen_cpus "$loadgen_cpus" \
  --arg upstream_cpus "$upstream_cpus" \
  --argjson gateway_cores "$gateway_cores" \
  --argjson loadgen_cores "$loadgen_cores" \
  --argjson upstream_cores "$upstream_cores" \
  --argjson connections "$connections" \
  --arg request_path "$request_path" \
  --argjson warmup_seconds "$warmup_seconds" \
  --argjson measurement_seconds "$measurement_seconds" '
  def median: sort as $v | ($v | length) as $n |
    if $n % 2 == 1 then $v[($n / 2 | floor)]
    else ($v[$n / 2 - 1] + $v[$n / 2]) / 2 end;
  def abs: if . < 0 then -. else . end;
  def deviation($v): ($v | median) as $m |
    [$v[] | ((. - $m) | abs) / $m * 100] | max;
  sort_by(.order) as $runs |
  [$runs | group_by(.variant)[] | . as $g |
    [$g[].successful_rps] as $rates |
    {variant: $g[0].variant, image: $g[0].image, image_id: $g[0].image_id,
     repetitions: ($g | length), median_successful_rps: ($rates | median),
     maximum_rps_deviation_percent: deviation($rates),
     median_p999_ms: ([$g[].latency_ms.p999] | median),
     maximum_p999_ms: ([$g[].latency_ms.p999] | max),
     mean_gateway_cpu_percent: ([$g[].cpu_percent.gateway] | add / length),
     maximum_upstream_capacity_percent:
       ([$g[].cpu_percent.upstream / $upstream_cores] | max),
     maximum_load_generator_capacity_percent:
       ([$g[].cpu_percent.load_generator / $loadgen_cores] | max)}] as $variants |
  ($variants[] | select(.variant == "baseline")) as $baseline |
  ($variants[] | select(.variant == "candidate")) as $candidate |
  {schema_version: 1, run_id: $run_id, platform: $platform,
   evidence_class: $evidence_class,
   publication_authorized: false,
   publication_reason: $publication_reason,
   gateway_cores: $gateway_cores, connections: $connections,
   request_path: $request_path,
   warmup_seconds: $warmup_seconds, measurement_seconds: $measurement_seconds,
   cpu_sets: {gateway: $gateway_cpus, load_generator: $loadgen_cpus,
              upstream: $upstream_cpus},
   sequence: [$runs[].variant], runs: $runs, variants: $variants,
   candidate_rps_change_percent:
     (($candidate.median_successful_rps / $baseline.median_successful_rps - 1) * 100),
   candidate_p999_change_percent:
     (($candidate.median_p999_ms / $baseline.median_p999_ms - 1) * 100)}
' "$run_dir"/*.result.json >"$run_dir/summary.json"

{
  printf '# %s: %s\n\n' "$report_title" "$run_id"
  printf -- '- Evidence class: local virtualized engineering A/B; not publication-authorized.\n'
  printf -- "- Container platform: \`%s\`.\n" "$platform"
  printf -- "- Workload: HTTP/1.1 keep-alive, \`%s\`, %s clients, five %s-second samples per variant.\n" "$request_path" "$connections" "$measurement_seconds"
  printf -- "- CPU sets: gateway \`%s\`, load generator \`%s\`, upstream \`%s\`.\n\n" "$gateway_cpus" "$loadgen_cpus" "$upstream_cpus"
  printf '| Variant | Median successful RPS | Max deviation | Median p99.9 | Gateway CPU | Max upstream capacity | Max loadgen capacity |\n'
  printf '| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n'
  jq -r '.variants[] | "| \(.variant) | \(.median_successful_rps) | \(.maximum_rps_deviation_percent)% | \(.median_p999_ms) ms | \(.mean_gateway_cpu_percent)% | \(.maximum_upstream_capacity_percent)% | \(.maximum_load_generator_capacity_percent)% |"' "$run_dir/summary.json"
  printf "\n- Candidate RPS change: \`%s%%\`\n" "$(jq -r '.candidate_rps_change_percent' "$run_dir/summary.json")"
  printf -- "- Candidate p99.9 change: \`%s%%\`\n" "$(jq -r '.candidate_p999_change_percent' "$run_dir/summary.json")"
} >"$run_dir/report.md"

(
  cd "$run_dir"
  checksum_manifest="$(mktemp)"
  find . -type f ! -name checksums.sha256 | LC_ALL=C sort | \
    while IFS= read -r file; do
      shasum -a 256 "$file"
    done >"$checksum_manifest"
  mv "$checksum_manifest" checksums.sha256
)

cat "$run_dir/report.md"
echo "RESULT_DIR=$run_dir"
