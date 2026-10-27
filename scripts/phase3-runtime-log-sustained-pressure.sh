#!/bin/sh
set -eu

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

umask 077

gateway_image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/arm64}"
repetitions="${BONVOYAGE_RUNTIME_LOG_COST_REPETITIONS:-5}"
cost_requests="${BONVOYAGE_RUNTIME_LOG_COST_REQUESTS:-500}"
cost_qps="${BONVOYAGE_RUNTIME_LOG_COST_QPS:-20}"
warmup_requests="${BONVOYAGE_RUNTIME_LOG_WARMUP_REQUESTS:-100}"
pressure_seconds="${BONVOYAGE_RUNTIME_LOG_PRESSURE_SECONDS:-180}"
pressure_qps="${BONVOYAGE_RUNTIME_LOG_PRESSURE_QPS:-500}"
recovery_requests="${BONVOYAGE_RUNTIME_LOG_RECOVERY_REQUESTS:-500}"
recovery_qps="${BONVOYAGE_RUNTIME_LOG_RECOVERY_QPS:-20}"
poll_seconds="${BONVOYAGE_RUNTIME_LOG_POLL_SECONDS:-5}"
alert_hold_seconds="${BONVOYAGE_RUNTIME_LOG_ALERT_HOLD_SECONDS:-120}"
settle_seconds="${BONVOYAGE_RUNTIME_LOG_SETTLE_SECONDS:-5}"
fd_growth_limit="${BONVOYAGE_RUNTIME_LOG_FD_GROWTH_LIMIT:-32}"
retain="${BONVOYAGE_RETAIN_RUNTIME_LOG_SUSTAINED_EVIDENCE:-0}"
environment="${BONVOYAGE_RUNTIME_LOG_ENVIRONMENT:-local-docker-desktop-arm64}"
gateway_cpuset="${BONVOYAGE_RUNTIME_LOG_GATEWAY_CPUSET:-}"
support_cpuset="${BONVOYAGE_RUNTIME_LOG_SUPPORT_CPUSET:-}"
load_cpuset="${BONVOYAGE_RUNTIME_LOG_LOAD_CPUSET:-}"

for value in "$repetitions" "$cost_requests" "$cost_qps" "$warmup_requests" "$pressure_seconds" \
    "$pressure_qps" "$recovery_requests" "$recovery_qps" "$poll_seconds" \
    "$alert_hold_seconds" "$settle_seconds" "$fd_growth_limit"; do
  case "$value" in
    ''|*[!0-9]*) echo "qualification controls must be positive integers" >&2; exit 1 ;;
    0) echo "qualification controls must be greater than zero" >&2; exit 1 ;;
  esac
done
[ "$repetitions" -ge 2 ] || { echo "at least two cost repetitions are required" >&2; exit 1; }
[ "$pressure_seconds" -gt "$alert_hold_seconds" ] || {
  echo "pressure duration must exceed the alert hold" >&2
  exit 1
}
case "$retain" in 0|1) ;; *) echo "retain flag must be zero or one" >&2; exit 1 ;; esac
case "$environment" in
  local-docker-desktop-arm64|aws-shared-amd64) ;;
  *) echo "unsupported runtime-log qualification environment: $environment" >&2; exit 1 ;;
esac
for cpuset in "$gateway_cpuset" "$support_cpuset" "$load_cpuset"; do
  case "$cpuset" in
    ''|*[!0-9,-]*)
      [ -z "$cpuset" ] || { echo "CPU sets may contain only digits, commas, and hyphens" >&2; exit 1; }
      ;;
  esac
done

suffix="$(date -u +%Y%m%dT%H%M%SZ)-$$"
network="bonvoyage-runtime-log-sustained-$suffix"
snapshot_volume="bonvoyage-runtime-log-sustained-snapshot-$suffix"
log_volume="bonvoyage-runtime-log-sustained-sink-$suffix"
secret_volume="${snapshot_volume}-secrets"
upstream="bonvoyage-runtime-log-sustained-upstream-$suffix"
gateway_prefix="bonvoyage-runtime-log-sustained-gateway-$suffix"
load="bonvoyage-runtime-log-sustained-load-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-runtime-log-sustained.XXXXXX")"
evidence="$work_dir/evidence"
network_created=0 snapshot_created=0 log_created=0 upstream_started=0
gateway_started=0 load_started=0 gateway=""

cleanup() {
  status="$?"
  trap - EXIT INT TERM
  if [ "$status" -ne 0 ] && [ "$gateway_started" -eq 1 ]; then
    docker logs --tail 120 "$gateway" >"$evidence/gateway.failure.log" 2>&1 || :
    cat "$evidence/gateway.failure.log" >&2 || :
  fi
  if [ "$status" -ne 0 ] && [ "$retain" = 1 ] && [ -d "$evidence" ]; then
    failure_dir="$PWD/benchmarks/results/verification/runtime-log-sustained-$suffix-failed"
    mkdir -p "$failure_dir"
    cp -R "$evidence/." "$failure_dir/"
    (
      cd "$failure_dir"
      find . -type f ! -name checksums.sha256 -print | LC_ALL=C sort \
        | xargs shasum -a 256
    ) >"$failure_dir/checksums.sha256"
    echo "retained_failed_evidence=$failure_dir" >&2
  fi
  if [ "$load_started" -eq 1 ]; then
    docker rm --force "$load" >/dev/null 2>&1 || :
  fi
  if [ "$gateway_started" -eq 1 ]; then
    docker rm --force "$gateway" >/dev/null 2>&1 || :
  fi
  if [ "$upstream_started" -eq 1 ]; then
    docker rm --force "$upstream" >/dev/null 2>&1 || :
  fi
  if [ "$network_created" -eq 1 ]; then
    docker network rm "$network" >/dev/null 2>&1 || :
  fi
  if [ "$snapshot_created" -eq 1 ]; then
    docker volume rm "$snapshot_volume" >/dev/null 2>&1 || :
  fi
  if [ "$log_created" -eq 1 ]; then
    docker volume rm "$log_volume" >/dev/null 2>&1 || :
  fi
  bv_remove_fixture_secrets "$secret_volume" "$work_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  rm -rf "$work_dir"
  exit "$status"
}
trap cleanup EXIT INT TERM

command -v openssl >/dev/null 2>&1
command -v python3 >/dev/null 2>&1
test -f "$PWD/tests/fixtures/phase3-http2.yaml"
test -f "$PWD/tests/fixtures/runtime-log-service/runtime_log_sustained_analyze.py"
mkdir "$work_dir/client" "$evidence"
git rev-parse HEAD >"$evidence/source-commit.txt"
git status --porcelain=v1 --untracked-files=all >"$evidence/source-status.txt"
git diff --binary HEAD >"$evidence/source-diff.patch"

python3 -c 'import json,sys; keys=("platform","environment","repetitions","cost_requests","cost_qps","warmup_requests","pressure_seconds","pressure_qps","recovery_requests","recovery_qps","poll_seconds","alert_hold_seconds","settle_seconds","fd_growth_limit","gateway_cpuset","support_cpuset","load_cpuset"); print(json.dumps(dict(zip(keys,sys.argv[1:])),sort_keys=True))' \
  "$platform" "$environment" "$repetitions" "$cost_requests" "$cost_qps" "$warmup_requests" "$pressure_seconds" \
  "$pressure_qps" "$recovery_requests" "$recovery_qps" "$poll_seconds" \
  "$alert_hold_seconds" "$settle_seconds" "$fd_growth_limit" "$gateway_cpuset" \
  "$support_cpuset" "$load_cpuset" \
  >"$evidence/plan.json"
uname -srm >"$evidence/host-kernel.txt"
docker version --format '{{.Server.Version}} {{.Server.Os}} {{.Server.Arch}}' \
  >"$evidence/docker-server.txt"
if command -v lscpu >/dev/null 2>&1; then
  lscpu --json >"$evidence/host-cpu.json"
fi

docker_run_gateway() {
  if [ -n "$gateway_cpuset" ]; then
    docker run --cpuset-cpus "$gateway_cpuset" "$@"
  else
    docker run "$@"
  fi
}

docker_run_support() {
  if [ -n "$support_cpuset" ]; then
    docker run --cpuset-cpus "$support_cpuset" "$@"
  else
    docker run "$@"
  fi
}

docker_run_load() {
  if [ -n "$load_cpuset" ]; then
    docker run --cpuset-cpus "$load_cpuset" "$@"
  else
    docker run "$@"
  fi
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage HTTP2 Test CA" \
  -keyout "$work_dir/ca-key.pem" -out "$work_dir/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=api.example.test" \
  -keyout "$work_dir/server-key.pem" -out "$work_dir/server.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:api.example.test' \
  'extendedKeyUsage=serverAuth' \
  'keyUsage=digitalSignature,keyEncipherment' >"$work_dir/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work_dir/server.csr" \
  -CA "$work_dir/ca.pem" -CAkey "$work_dir/ca-key.pem" -CAcreateserial \
  -extfile "$work_dir/server-ext.cnf" -out "$work_dir/server-chain.pem" >/dev/null 2>&1
cp "$work_dir/ca.pem" "$work_dir/client/ca.pem"
# The load generator runs unprivileged on native Linux. Only the public CA
# certificate is exposed through this bind mount; private keys stay mode 0600.
chmod 0755 "$work_dir/client"
chmod 0644 "$work_dir/client/ca.pem"

docker network create "$network" >/dev/null
network_created=1
docker volume create "$snapshot_volume" >/dev/null
snapshot_created=1
docker volume create "$log_volume" >/dev/null
log_created=1
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem

docker_run_support --rm --pull never --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-http2.yaml:/fixture/config.yaml:ro" \
  --volume "$snapshot_volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /fixture/config.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >/dev/null

docker_run_support --detach --pull never --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --volume "$log_volume:/runtime-log" \
  --volume "$PWD/tests/fixtures/runtime-log-service:/fixture:ro" \
  --volume "$work_dir/client:/tls:ro" \
  "$upstream_image" >/dev/null
upstream_started=1
docker exec --detach "$upstream" python /fixture/unix_receiver.py serve
attempt=0
until docker exec "$upstream" python /fixture/unix_receiver.py control status \
    >"$evidence/receiver-start.json" 2>/dev/null; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 30 ] || { echo "private Unix receiver did not start" >&2; exit 1; }
  sleep 0.1
done

receiver_status() {
  output="$1"
  docker exec "$upstream" python /fixture/unix_receiver.py control status >"$output"
}

receiver_command() {
  command="$1" output="$2"
  docker exec "$upstream" python /fixture/unix_receiver.py control "$command" >"$output"
}

capture_metrics() {
  output="$1"
  docker exec "$upstream" python /fixture/http2_pressure_analyze.py capture \
    --gateway api.example.test >"$output"
}

capture_process() {
  output="$1"
  docker_run_support --rm --pull never --platform "$platform" \
    --network none --pid "container:$gateway" --cap-drop ALL \
    --user 65532:65532 --security-opt no-new-privileges \
    --volume "$PWD/tests/fixtures/runtime-log-service:/fixture:ro" \
    --entrypoint python "$upstream_image" \
    /fixture/runtime_log_sustained_analyze.py process \
    >"$output"
}

wait_drained() {
  output="$1"
  attempt=0
  while [ "$attempt" -lt 100 ]; do
    capture_metrics "$output"
    if python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); raise SystemExit(0 if m["queue_depth"]==0 and m["sink_healthy"]==1 else 1)' "$output"; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  echo "runtime logger did not drain" >&2
  exit 1
}

wait_quiescent() {
  output="$1"
  attempt=0
  while [ "$attempt" -lt 100 ]; do
    capture_metrics "$output"
    if python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); names=("active_requests","active_connections","active_http2_connections","active_upstream_requests"); raise SystemExit(0 if all(m[name] == 0 for name in names) else 1)' "$output"; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  echo "gateway did not become request-quiescent" >&2
  exit 1
}

run_oha_count() {
  output="$1" count="$2" qps="$3"
  docker_run_load --rm --pull never --platform "$platform" \
    --network "$network" --volume "$work_dir/client:/tls:ro" "$oha_image" \
    -n "$count" -q "$qps" --latency-correction -c 4 -p 8 --no-tui \
    --output-format json --http-version 2 --disable-compression \
    --cacert /tls/ca.pem https://api.example.test:8443/payload/1024 >"$output"
}

start_gateway() {
  label="$1" level="$2"
  gateway="$gateway_prefix-$label"
  docker_run_gateway --detach --pull never --platform "$platform" --name "$gateway" \
    --cpus 1 --memory 512m --pids-limit 256 --security-opt no-new-privileges \
    --network "$network" --network-alias api.example.test \
    --volume "$snapshot_volume:/snapshot:ro" \
    --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
    --volume "$log_volume:/runtime-log" \
    "$gateway_image" --snapshot /snapshot/snapshot.pb \
    --secrets-directory /etc/bonvoyage/secrets \
    --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
    --runtime-log-transport unix --runtime-log-socket /runtime-log/logger.sock \
    --smp 1 --memory 256M --overprovisioned \
    --logger-log-level "bonvoyage-gateway=$level" >/dev/null
  gateway_started=1
  bv_wait_gateway_ready "$gateway" "$upstream" "http://api.example.test:9901/health/ready"
  docker exec "$upstream" python -c '
import socket, ssl
context = ssl.create_default_context(cafile="/tls/ca.pem")
context.set_alpn_protocols(["h2", "http/1.1"])
with socket.create_connection(("api.example.test", 8443), timeout=3) as raw:
    with context.wrap_socket(raw, server_hostname="api.example.test") as secure:
        assert secure.selected_alpn_protocol() == "h2"
'
}

stop_gateway() {
  docker stop --time 8 "$gateway" >/dev/null
  test "$(docker inspect --type container --format '{{.State.ExitCode}}' "$gateway")" = 0
  test "$(docker inspect --type container --format '{{.RestartCount}}' "$gateway")" = 0
  docker rm "$gateway" >/dev/null
  gateway_started=0
  gateway=""
}

run_cost_sample() {
  pair="$1" mode="$2" order="$3"
  prefix="$evidence/cost-$(printf '%02d' "$pair")-$mode"
  start_gateway "cost-$(printf '%02d' "$pair")-$mode" "$mode"
  run_oha_count "$prefix.warmup.oha.json" "$warmup_requests" "$cost_qps"
  wait_drained "$prefix.before.metrics.json"
  receiver_status "$prefix.before.receiver.json"
  capture_process "$prefix.before.process.json"
  run_oha_count "$prefix.oha.json" "$cost_requests" "$cost_qps"
  wait_drained "$prefix.after.metrics.json"
  capture_process "$prefix.after.process.json"
  receiver_status "$prefix.after.receiver.json"
  if ! python3 tests/fixtures/runtime-log-service/runtime_log_sustained_analyze.py sample \
      --mode "$mode" --pair "$pair" --order "$order" --requests "$cost_requests" \
      --before-process "$prefix.before.process.json" \
      --after-process "$prefix.after.process.json" \
      --before-metrics "$prefix.before.metrics.json" \
      --after-metrics "$prefix.after.metrics.json" \
      --before-receiver "$prefix.before.receiver.json" \
      --after-receiver "$prefix.after.receiver.json" \
      --oha "$prefix.oha.json" >"$prefix.sample.json"; then
    echo "cost sample failed: pair=$pair mode=$mode order=$order" >&2
    cat "$prefix.before.metrics.json" >&2
    cat "$prefix.after.metrics.json" >&2
    return 1
  fi
  stop_gateway
}

pair=1
while [ "$pair" -le "$repetitions" ]; do
  if [ $((pair % 2)) -eq 1 ]; then
    run_cost_sample "$pair" info 1
    run_cost_sample "$pair" debug 2
  else
    run_cost_sample "$pair" debug 1
    run_cost_sample "$pair" info 2
  fi
  pair=$((pair + 1))
done

receiver_status "$evidence/pressure-receiver-start.json"
start_gateway pressure debug
run_oha_count "$evidence/pressure-warmup.oha.json" "$warmup_requests" "$cost_qps"
wait_drained "$evidence/pressure-before.metrics.json"
capture_process "$evidence/pressure-before.process.json"
pressure_pid="$(docker inspect --type container --format '{{.State.Pid}}' "$gateway")"
receiver_command pause "$evidence/pressure-receiver-pause.json"

docker_run_load --detach --pull never --platform "$platform" --name "$load" \
  --network "$network" --volume "$work_dir/client:/tls:ro" "$oha_image" \
  -z "${pressure_seconds}s" -q "$pressure_qps" --latency-correction \
  -c 4 -p 8 --no-tui --output-format json --http-version 2 \
  --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/payload/1024 >/dev/null
load_started=1
sample=0
while [ "$(docker inspect --type container --format '{{.State.Running}}' "$load")" = true ]; do
  sample=$((sample + 1))
  capture_metrics "$evidence/pressure-timeline-$(printf '%03d' "$sample").json"
  test "$pressure_pid" = "$(docker inspect --type container --format '{{.State.Pid}}' "$gateway")"
  test "$(docker inspect --type container --format '{{.RestartCount}}' "$gateway")" = 0
  sleep "$poll_seconds"
done
test "$(docker wait "$load")" = 0
docker logs "$load" >"$evidence/pressure.oha.json"
docker rm "$load" >/dev/null
load_started=0
capture_metrics "$evidence/pressure-paused.metrics.json"
receiver_command resume "$evidence/pressure-receiver-resume.json"
wait_drained "$evidence/pressure-drained.metrics.json"
run_oha_count "$evidence/recovery.oha.json" "$recovery_requests" "$recovery_qps"
wait_drained "$evidence/pressure-recovered.metrics.json"
wait_quiescent "$evidence/pressure-quiescent.metrics.json"
capture_process "$evidence/pressure-after.process.json"
sleep "$settle_seconds"
capture_process "$evidence/pressure-settled.process.json"
pressure_pid_after="$(docker inspect --type container --format '{{.State.Pid}}' "$gateway")"
restart_count="$(docker inspect --type container --format '{{.RestartCount}}' "$gateway")"
docker stop --time 8 "$gateway" >/dev/null
exit_code="$(docker inspect --type container --format '{{.State.ExitCode}}' "$gateway")"
python3 -c 'import json,sys; print(json.dumps({"pid_before":int(sys.argv[1]),"pid_after":int(sys.argv[2]),"restart_count":int(sys.argv[3]),"exit_code":int(sys.argv[4])},sort_keys=True))' \
  "$pressure_pid" "$pressure_pid_after" "$restart_count" "$exit_code" \
  >"$evidence/pressure-lifecycle.json"
test "$pressure_pid" = "$pressure_pid_after"
test "$restart_count" = 0
test "$exit_code" = 0
docker rm "$gateway" >/dev/null
gateway_started=0
gateway=""

previous=-1 stable=0 attempt=0
while [ "$attempt" -lt 60 ] && [ "$stable" -lt 3 ]; do
  receiver_status "$evidence/pressure-receiver-final.json"
  current="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["received"])' "$evidence/pressure-receiver-final.json")"
  if [ "$current" = "$previous" ]; then stable=$((stable + 1)); else stable=0; fi
  previous="$current"
  attempt=$((attempt + 1))
  sleep 0.1
done
[ "$stable" -ge 3 ] || { echo "receiver did not stabilize after shutdown" >&2; exit 1; }

docker cp "$upstream:/runtime-log/records.jsonl" "$evidence/records.jsonl"
python3 tests/fixtures/runtime-log-service/runtime_log_sustained_analyze.py report \
  --directory "$evidence" --records "$evidence/records.jsonl" \
  --repetitions "$repetitions" --pressure-seconds "$pressure_seconds" \
  --pressure-qps "$pressure_qps" --recovery-requests "$recovery_requests" \
  --alert-hold-seconds "$alert_hold_seconds" --fd-growth "$fd_growth_limit" \
  --environment "$environment" \
  >"$evidence/report.json"
cat "$evidence/report.json"

if [ "$retain" = 1 ]; then
  results_dir="$PWD/benchmarks/results/verification/runtime-log-sustained-$suffix"
  mkdir "$results_dir"
  cp "$evidence/"* "$results_dir/"
  mkdir "$results_dir/source"
  cp scripts/phase3-runtime-log-sustained-pressure.sh "$results_dir/source/"
  cp scripts/test-fixture-secrets.sh "$results_dir/source/"
  cp tests/fixtures/runtime-log-service/http2_pressure_analyze.py "$results_dir/source/"
  cp tests/fixtures/runtime-log-service/runtime_log_sustained_analyze.py "$results_dir/source/"
  for source in scripts/phase3-runtime-log-sustained-pressure.sh scripts/test-fixture-secrets.sh tests/fixtures/runtime-log-service/http2_pressure_analyze.py tests/fixtures/runtime-log-service/runtime_log_sustained_analyze.py; do
    shasum -a 256 "$source"
  done >"$results_dir/source-checksums.txt"
  docker image inspect "$gateway_image" --format '{{.Id}}' >"$results_dir/gateway-image-id.txt"
  docker image inspect "$compiler_image" --format '{{.Id}}' >"$results_dir/compiler-image-id.txt"
  docker image inspect "$upstream_image" --format '{{.Id}}' >"$results_dir/upstream-image-id.txt"
  (
    cd "$results_dir"
    find . -type f ! -name checksums.sha256 -print | LC_ALL=C sort \
      | xargs shasum -a 256
  ) >"$work_dir/checksums.sha256"
  mv "$work_dir/checksums.sha256" "$results_dir/checksums.sha256"
  echo "retained_evidence=$results_dir"
fi
