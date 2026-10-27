#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
runtime_source_root="${BONVOYAGE_RUNTIME_SOURCE_ROOT:-$repo}"
# shellcheck disable=SC1091
. "$repo/scripts/test-fixture-secrets.sh"

platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
gateway_image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
output_root="${BONVOYAGE_PERF04_LOCAL_EVIDENCE_ROOT:-$repo/benchmarks/results/verification}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="phase5-perf04-local-preflight-$timestamp"
suffix="$$-$timestamp"
network="bonvoyage-perf04-$suffix"
snapshot_volume="bonvoyage-perf04-snapshot-$suffix"
secret_volume="bonvoyage-perf04-secrets-$suffix"
gateway="bonvoyage-perf04-gateway-$suffix"
upstream="bonvoyage-perf04-upstream-$suffix"
observer="bonvoyage-perf04-observer-$suffix"
loadgen_prefix="bonvoyage-perf04-loadgen-$suffix"
binary_helper="bonvoyage-perf04-binary-$suffix"
snapshot_helper="bonvoyage-perf04-snapshot-copy-$suffix"
work="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-perf04.XXXXXX")"
evidence="$work/evidence"
captures="$evidence/captures"
published=false
secret_staged=false

fail() {
  echo "phase5-backpressure-local: $*" >&2
  exit 1
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

hash_value() {
  hash_file "$1" | awk '{print $1}'
}

cleanup() {
  status="$?"
  set +e
  if [ -d "$evidence" ] && docker inspect "$gateway" >/dev/null 2>&1; then
    docker logs "$gateway" >"$evidence/gateway.log" 2>&1
  fi
  if [ -d "$evidence" ] && docker inspect "$upstream" >/dev/null 2>&1; then
    docker logs "$upstream" >"$evidence/upstream.log" 2>&1
  fi
  docker rm --force "$observer" "$gateway" "$upstream" \
    "$binary_helper" "$snapshot_helper" >/dev/null 2>&1
  docker ps --all --format '{{.Names}}' | grep -F "$loadgen_prefix" | \
    xargs -r docker rm --force >/dev/null 2>&1
  docker network rm "$network" >/dev/null 2>&1
  docker volume rm "$snapshot_volume" >/dev/null 2>&1
  if [ "$secret_staged" = true ]; then
    bv_remove_fixture_secrets "$secret_volume" "$work" >/dev/null 2>&1 || status=1
  fi
  if [ "$published" = false ] && [ -d "$evidence" ]; then
    printf '%s\n' "$status" >"$evidence/exit-status.txt"
    (
      cd "$evidence" || exit
      find . -type f ! -name checksums.sha256 -print | sort | while IFS= read -r file; do
        hash_file "$file"
      done >checksums.sha256
    )
    mkdir -p "$output_root"
    failed="$output_root/$run_id-failed"
    if [ ! -e "$failed" ]; then
      mv "$evidence" "$failed"
      echo "failed PERF-04 evidence retained: $failed" >&2
    fi
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT INT TERM

for tool in awk date docker find git grep jq mktemp node openssl sed shasum sort; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
[ -d "$runtime_source_root/.git" ] || git -C "$runtime_source_root" rev-parse --git-dir >/dev/null 2>&1 || \
  fail "runtime source root is not a Git worktree: $runtime_source_root"
[ -f "$runtime_source_root/tests/fixtures/phase3-route-admission.yaml" ] || \
  fail 'the committed Phase 3 route-admission fixture is missing'

source_commit="$(git -C "$runtime_source_root" rev-parse HEAD)"
runtime_status="$(git -C "$runtime_source_root" status --porcelain --untracked-files=all)"
[ -z "$runtime_status" ] || fail 'runtime source tree must be clean'
for image in "$gateway_image" "$compiler_image" "$upstream_image" "$oha_image"; do
  docker image inspect "$image" >/dev/null 2>&1 || fail "required image is missing: $image"
done
gateway_image_id="$(docker image inspect "$gateway_image" --format '{{.Id}}')"
if [ -n "${BONVOYAGE_EXPECTED_GATEWAY_IMAGE_ID:-}" ]; then
  [ "$gateway_image_id" = "$BONVOYAGE_EXPECTED_GATEWAY_IMAGE_ID" ] || \
    fail 'gateway image does not match BONVOYAGE_EXPECTED_GATEWAY_IMAGE_ID'
fi

mkdir -p "$captures" "$evidence/artifacts"
printf '%s\n' "$runtime_status" >"$evidence/runtime-git-status.txt"
git -C "$repo" status --porcelain --untracked-files=all >"$evidence/harness-git-status.txt"
git -C "$runtime_source_root" log -1 --format=fuller >"$evidence/runtime-source-commit.txt"
docker image inspect "$gateway_image" >"$evidence/runtime-image.inspect.json"
docker image inspect "$compiler_image" >"$evidence/compiler-image.inspect.json"
docker image inspect "$upstream_image" >"$evidence/upstream-image.inspect.json"
docker image inspect "$oha_image" >"$evidence/oha-image.inspect.json"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj '/CN=BonVoyage PERF-04 Local CA' \
  -keyout "$work/ca-key.pem" -out "$work/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 -subj '/CN=api.example.test' \
  -keyout "$work/server-key.pem" -out "$work/server.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:api.example.test' 'extendedKeyUsage=serverAuth' \
  'keyUsage=digitalSignature,keyEncipherment' >"$work/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work/server.csr" \
  -CA "$work/ca.pem" -CAkey "$work/ca-key.pem" -CAcreateserial \
  -extfile "$work/server-ext.cnf" -out "$work/server-chain.pem" >/dev/null 2>&1
chmod 600 "$work"/*-key.pem

docker network create "$network" >/dev/null
docker volume create "$snapshot_volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem
secret_staged=true
docker run --rm --pull never --platform "$platform" --user 0:0 \
  --network none --volume "$snapshot_volume:/output" --entrypoint python \
  "$upstream_image" -c \
  'import os; os.chmod("/output", 0o700); os.chown("/output", 65532, 65532)' \
  >/dev/null
docker run --rm --pull never --platform "$platform" \
  --volume "$runtime_source_root/tests/fixtures/phase3-route-admission.yaml:/config/input.yaml:ro" \
  --volume "$snapshot_volume:/output" "$compiler_image" \
  -input /config/input.yaml -output /output/snapshot.pb \
  >"$evidence/snapshot-compiler.log"

docker create --name "$binary_helper" "$gateway_image" >/dev/null
docker cp "$binary_helper:/usr/local/bin/bonvoyage-dataplane" \
  "$work/bonvoyage-dataplane"
docker rm "$binary_helper" >/dev/null
docker create --name "$snapshot_helper" \
  --volume "$snapshot_volume:/snapshot:ro" "$upstream_image" >/dev/null
docker cp "$snapshot_helper:/snapshot/snapshot.pb" "$evidence/artifacts/snapshot.pb"
docker rm "$snapshot_helper" >/dev/null
gateway_binary_sha256="$(hash_value "$work/bonvoyage-dataplane")"
snapshot_sha256="$(hash_value "$evidence/artifacts/snapshot.pb")"
configuration_sha256="$(hash_value "$runtime_source_root/tests/fixtures/phase3-route-admission.yaml")"

for collector in \
  "$repo/benchmarks/scripts/phase5-backpressure.mjs" \
  "$repo/benchmarks/scripts/phase5-backpressure-assemble.mjs" \
  "$repo/benchmarks/scripts/run-phase5-backpressure-local.sh"; do
  hash_file "$collector"
done >"$evidence/collector-files.sha256"
collector_sha256="$(hash_value "$evidence/collector-files.sha256")"

cat >"$work/plan-input.json" <<'EOF'
{
  "profile": "P5-Q01-local-wiring",
  "coreCount": 1,
  "rates": {
    "steady": 10,
    "near_knee": 14,
    "intentional_overload": 100,
    "recovery": 10
  },
  "durations": {
    "steady": 8,
    "near_knee": 8,
    "intentional_overload": 8,
    "recovery": 8
  },
  "latencyCeilings": {
    "steady": {"p95": 200, "p99": 500},
    "near_knee": {"p95": 200, "p99": 500},
    "intentional_overload": {"p95": 500, "p99": 1000},
    "recovery": {"p95": 200, "p99": 500}
  },
  "acceptance": {
    "minimum_attempted_rate_ratio": 0.98,
    "maximum_attempted_rate_ratio": 1.02,
    "maximum_pre_overload_error_rate": 0,
    "maximum_support_capacity_percent": 80,
    "maximum_request_imbalance_ratio": 0.20,
    "minimum_recovery_rps_ratio": 0.95,
    "maximum_recovery_rss_growth_bytes": 16777216,
    "maximum_recovery_fd_growth": 4,
    "required_overload_counter": "route_overload_rejections_total"
  }
}
EOF
node "$repo/benchmarks/scripts/phase5-backpressure.mjs" plan \
  --input "$work/plan-input.json" --output "$evidence/plan.json"
plan_id="$(jq -er '.plan_id' "$evidence/plan.json")"

docker run --detach --pull never --platform "$platform" --name "$upstream" \
  --cpus 2 --network "$network" --network-alias upstream \
  --env BONVOYAGE_UPSTREAM_ID=perf04-upstream "$upstream_image" >/dev/null
docker run --detach --pull never --platform "$platform" --name "$gateway" \
  --cpus 1 --network "$network" --network-alias gateway \
  --network-alias api.example.test --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --cap-drop ALL --cap-add SYS_NICE --security-opt no-new-privileges:true \
  --volume "$snapshot_volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
  "$gateway_image" --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --response-path-diagnostics --smp 1 --memory 384M --overprovisioned >/dev/null
bv_wait_gateway_ready "$gateway" "$upstream" "http://$gateway:9901/health/ready"
docker run --detach --pull never --platform "$platform" --name "$observer" \
  --pid "container:$gateway" --network none --read-only --entrypoint python \
  "$upstream_image" -c 'import time; time.sleep(3600)' >/dev/null

capture_process() {
  destination="$1"
  docker inspect "$gateway" >"$work/gateway-inspect.json"
  docker exec "$observer" python -c '
import json
from pathlib import Path

stat = Path("/proc/1/stat").read_text(encoding="utf-8")
fields = stat[stat.rfind(")") + 2:].split()
status = Path("/proc/1/status").read_text(encoding="utf-8").splitlines()
rss = next(line.split()[1] for line in status if line.startswith("VmRSS:"))
print(json.dumps({
    "start_ticks": int(fields[19]),
    "rss_bytes": int(rss) * 1024,
    "file_descriptors": sum(1 for _ in Path("/proc/1/fd").iterdir()),
    "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text(
        encoding="utf-8").strip(),
}))
' >"$work/process-resource.json"
  jq -n --arg service "$gateway" \
    --slurpfile inspect "$work/gateway-inspect.json" \
    --slurpfile resource "$work/process-resource.json" '
      {
        service: $service,
        pid: $inspect[0][0].State.Pid,
        start_ticks: $resource[0].start_ticks,
        restart_count: $inspect[0][0].RestartCount,
        boot_id: $resource[0].boot_id,
        rss_bytes: $resource[0].rss_bytes,
        file_descriptors: $resource[0].file_descriptors
      }
    ' >"$destination"
}

capture_metrics() {
  destination="$1"
  docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://gateway:9090/metrics", timeout=5).read().decode(), end="")
' >"$destination"
}

capture_process "$work/initial-process.json"
boot_id="$(jq -er '.boot_id' "$work/initial-process.json")"
jq -n \
  --arg run_id "$run_id" \
  --arg commit "$source_commit" \
  --arg binary "$gateway_binary_sha256" \
  --arg snapshot "$snapshot_sha256" \
  --arg configuration "$configuration_sha256" \
  --arg collector "$collector_sha256" \
  --arg boot_id "$boot_id" '
  {
    schema_version: 1,
    run_id: $run_id,
    evidence_class: "local-virtualized-engineering",
    publication_authorized: false,
    source_commit: $commit,
    source_dirty: false,
    gateway_binary_sha256: $binary,
    snapshot_sha256: $snapshot,
    configuration_sha256: $configuration,
    collector_sha256: $collector,
    boot_id: $boot_id,
    expected_shards: [0],
    support_roles: ["load_generator", "controlled_upstream"],
    required_host_counters: [],
    required_zero_host_counters: [],
    unavailable_resource_metrics: ["host_cpu_percent", "irq_cpu_percent"],
    response_path_diagnostics_enabled: true
  }
' >"$evidence/environment.json"

run_stage() {
  phase="$1"
  rate="$2"
  duration="$3"
  connections="$4"
  stage="$captures/$phase"
  loadgen="$loadgen_prefix-$phase"
  mkdir -p "$stage/metrics" "$stage/resources" "$stage/docker-stats"
  capture_metrics "$stage/before.metrics.prom"
  capture_process "$stage/process-before.json"
  jq -n --arg plan_id "$plan_id" --arg phase "$phase" \
    --arg gateway "$gateway" --arg loadgen "$loadgen" --arg upstream "$upstream" '
    {
      schema_version: 1,
      plan_id: $plan_id,
      phase: $phase,
      gateway_container: {name: $gateway, capacity_cores: 1},
      support_containers: {
        load_generator: {name: $loadgen, capacity_cores: 2},
        controlled_upstream: {name: $upstream, capacity_cores: 2}
      },
      host_cpu_percent: null,
      irq_cpu_percent: null,
      host_counters: {
        softnet_dropped: null,
        softnet_time_squeeze: null,
        ena_allowance_exceeded: null,
        ena_queue_stops: null
      }
    }
  ' >"$stage/metadata.json"

  docker run --detach --pull never --platform "$platform" --name "$loadgen" \
    --cpus 2 --network "$network" "$oha_image" \
    -z "${duration}s" -q "$rate" -c "$connections" -w \
    --latency-correction --disable-compression --no-tui --no-color \
    --http-version 1.1 --output-format json -H 'Host: api.example.test' \
    'http://gateway:8080/circuit-http1/slow/20' >/dev/null

  sample=0
  while [ "$(docker inspect --format '{{.State.Running}}' "$loadgen")" = true ]; do
    sample=$((sample + 1))
    serial="$(printf '%04d' "$sample")"
    capture_metrics "$stage/metrics/$serial.prom"
    capture_process "$work/stage-resource.json"
    jq '{rss_bytes, file_descriptors}' "$work/stage-resource.json" \
      >"$stage/resources/$serial.json"
    if ! docker stats --no-stream --format '{{json .}}' \
      "$gateway" "$upstream" "$loadgen" \
      >"$stage/docker-stats/$serial.jsonl"; then
      : >"$stage/docker-stats/$serial.jsonl"
    fi
    sleep 0.25
  done
  exit_code="$(docker wait "$loadgen")"
  docker logs "$loadgen" >"$stage/client.oha.json" 2>"$stage/client.stderr.txt"
  [ "$exit_code" -eq 0 ] || fail "$phase load generator exited $exit_code"
  [ "$sample" -gt 0 ] || fail "$phase produced no synchronized samples"
  sleep 1
  capture_metrics "$stage/after.metrics.prom"
  capture_process "$stage/process-after.json"
  docker rm "$loadgen" >/dev/null
}

run_stage steady 10 8 1
run_stage near_knee 14 8 1
run_stage intentional_overload 100 8 8
run_stage recovery 10 8 1

node "$repo/benchmarks/scripts/phase5-backpressure-assemble.mjs" \
  --plan "$evidence/plan.json" --environment "$evidence/environment.json" \
  --captures "$captures" --output "$evidence/results.json"
node "$repo/benchmarks/scripts/phase5-backpressure.mjs" summarize \
  --plan "$evidence/plan.json" --environment "$evidence/environment.json" \
  --results "$evidence/results.json" --output "$evidence/summary.json"
jq -e '.decision == "queueing-backpressure-pass" and
  (.gates | to_entries | all(.value == true)) and
  .publication_authorized == false' "$evidence/summary.json" >/dev/null || \
  fail 'local PERF-04 preflight did not pass every engineering gate'

docker logs "$gateway" >"$evidence/gateway.log" 2>&1
docker logs "$upstream" >"$evidence/upstream.log" 2>&1

cat >"$evidence/README.md" <<EOF
# PERF-04 local four-stage preflight

**LOCAL VIRTUALIZED ENGINEERING EVIDENCE - NON-PUBLISHABLE.**

This run validates the live collection and decision path for steady,
near-knee, intentional route-admission overload, and same-process recovery.
It uses one emulated AMD64 shard inside Docker Desktop and cannot establish
native capacity, Linux host CPU, IRQ cost, ENA health, or competitive results.

- Runtime source: \`$source_commit\` (clean).
- Runtime image: \`$gateway_image_id\`.
- Decision: \`$(jq -r '.decision' "$evidence/summary.json")\`.
- Publication authorized: \`false\`.

The runtime source and artifacts are checksum-bound independently from the
candidate harness. A native Linux/AWS execution must populate the host signals
that are explicitly \`null\` here.
EOF
jq -r '
  "| Stage | Target RPS | Successful RPS | Error rate | p50 | p95 | p99 |",
  "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
  (.points[] | "| \(.phase) | \(.target_rps) | \(.successful_rps | tostring) | \(.error_rate * 100)% | \(.latency_ms.p50) ms | \(.latency_ms.p95) ms | \(.latency_ms.p99) ms |")
' "$evidence/summary.json" >>"$evidence/README.md"

(
  cd "$evidence"
  find . -type f ! -name checksums.sha256 -print | sort | while IFS= read -r file; do
    hash_file "$file"
  done >checksums.sha256
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum --check checksums.sha256 >/dev/null
  else
    shasum -a 256 --check checksums.sha256 >/dev/null
  fi
)

mkdir -p "$output_root"
output_dir="$output_root/$run_id"
[ ! -e "$output_dir" ] || fail "evidence destination already exists: $output_dir"
mv "$evidence" "$output_dir"
published=true
printf '%s\n' "$run_id" >"$output_root/current-phase5-perf04-local.txt.tmp"
mv "$output_root/current-phase5-perf04-local.txt.tmp" \
  "$output_root/current-phase5-perf04-local.txt"
printf 'PERF-04 local four-stage preflight passed: %s\n' "$output_dir"
jq '{decision, gates, recovery, points: [.points[] | {
  phase, target_rps, successful_rps, error_rate, latency_ms,
  support_capacity_percent, resources
}]}' "$output_dir/summary.json"
