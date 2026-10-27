#!/bin/sh
set -eu

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

umask 077

gateway_image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-runtime-log-integration:20260916-final}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/arm64}"
shutdown_mode="${BONVOYAGE_RUNTIME_LOG_SHUTDOWN_MODE:-recovered}"
case "$shutdown_mode" in
  recovered|stalled) ;;
  *) echo "BONVOYAGE_RUNTIME_LOG_SHUTDOWN_MODE must be recovered or stalled" >&2; exit 1 ;;
esac
suffix="$(date -u +%Y%m%dT%H%M%SZ)-$$"
network="bonvoyage-runtime-log-h2-$suffix"
snapshot_volume="bonvoyage-runtime-log-h2-snapshot-$suffix"
log_volume="bonvoyage-runtime-log-h2-sink-$suffix"
secret_volume="${snapshot_volume}-secrets"
gateway="bonvoyage-runtime-log-h2-gateway-$suffix"
upstream="bonvoyage-runtime-log-h2-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-runtime-log-h2.XXXXXX")"
network_created=0 snapshot_created=0 log_created=0 upstream_started=0 gateway_started=0

cleanup() {
  status="$?"
  trap - EXIT INT TERM
  if [ "$status" -ne 0 ] && [ "$gateway_started" -eq 1 ]; then
    docker logs --tail 80 "$gateway" >&2 || :
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
mkdir "$work_dir/client" "$work_dir/evidence"
git rev-parse HEAD >"$work_dir/evidence/source-commit.txt"
git status --porcelain >"$work_dir/evidence/source-status.txt"

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

docker network create "$network" >/dev/null
network_created=1
docker volume create "$snapshot_volume" >/dev/null
snapshot_created=1
docker volume create "$log_volume" >/dev/null
log_created=1
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem

docker run --rm --pull never --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-http2.yaml:/fixture/config.yaml:ro" \
  --volume "$snapshot_volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /fixture/config.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >/dev/null

docker run --detach --pull never --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --volume "$log_volume:/runtime-log" \
  --volume "$PWD/tests/fixtures/runtime-log-service:/fixture:ro" \
  --volume "$work_dir/client:/tls:ro" \
  --volume "$work_dir/evidence:/evidence:ro" \
  "$upstream_image" >/dev/null
upstream_started=1
docker exec --detach "$upstream" python /fixture/unix_receiver.py serve
attempt=0
until docker exec "$upstream" python /fixture/unix_receiver.py control status \
    >"$work_dir/evidence/receiver-start.json" 2>/dev/null; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 30 ] || { echo "private Unix receiver did not start" >&2; exit 1; }
  sleep 0.1
done

docker run --detach --pull never --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test \
  --volume "$snapshot_volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
  --volume "$log_volume:/runtime-log" \
  "$gateway_image" --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --runtime-log-transport unix --runtime-log-socket /runtime-log/logger.sock \
  --smp 1 --memory 256M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug >/dev/null
gateway_started=1
bv_wait_gateway_ready "$gateway" "$upstream" "http://$gateway:9901/health/ready"
gateway_pid="$(docker inspect --type container --format '{{.State.Pid}}' "$gateway")"

docker exec "$upstream" python -c '
import socket, ssl
context = ssl.create_default_context(cafile="/tls/ca.pem")
context.set_alpn_protocols(["h2", "http/1.1"])
with socket.create_connection(("api.example.test", 8443), timeout=3) as raw:
    with context.wrap_socket(raw, server_hostname="api.example.test") as secure:
        assert secure.selected_alpn_protocol() == "h2"
'

run_oha() {
  phase="$1" count="$2"
  docker run --rm --pull never --platform "$platform" \
    --user "$(id -u):$(id -g)" --network "$network" \
    --volume "$work_dir/client:/tls:ro" "$oha_image" \
    -n "$count" -c 2 -p 4 --no-tui --output-format json \
    --http-version 2 --disable-compression --cacert /tls/ca.pem \
    https://api.example.test:8443/payload/1024 \
    >"$work_dir/evidence/$phase.oha.json"
}

capture_metrics() {
  phase="$1"
  docker exec "$upstream" python /fixture/http2_pressure_analyze.py capture \
    --gateway "$gateway" >"$work_dir/evidence/$phase.metrics.json"
}

wait_metrics() {
  phase="$1" test_code="$2"
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    capture_metrics "$phase"
    if python3 -c "$test_code" "$work_dir/evidence/$phase.metrics.json" \
        "$work_dir/evidence/healthy.metrics.json" \
        "$work_dir/evidence/paused.metrics.json"; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.2
  done
  echo "runtime logger metrics did not reach $phase state" >&2
  exit 1
}

run_oha healthy 32
wait_metrics healthy 'import json,sys; m=json.load(open(sys.argv[1])); sys.exit(0 if m["queue_depth"]==0 and m["sink_healthy"]==1 else 1)'
docker exec "$upstream" python /fixture/unix_receiver.py control pause \
  >"$work_dir/evidence/receiver-pause.json"
run_oha paused 64
wait_metrics paused 'import json,sys; m=json.load(open(sys.argv[1])); h=json.load(open(sys.argv[2])); sys.exit(0 if m["queue_depth"]>0 and m["sink_healthy"]==0 and m["would_block_events_total"]>h["would_block_events_total"] else 1)'

if [ "$shutdown_mode" = stalled ]; then
  started_ns="$(python3 -c 'import time; print(time.monotonic_ns())')"
  docker stop --time 8 "$gateway" >/dev/null
  finished_ns="$(python3 -c 'import time; print(time.monotonic_ns())')"
  exit_code="$(docker inspect --type container --format '{{.State.ExitCode}}' "$gateway")"
  restart_count="$(docker inspect --type container --format '{{.RestartCount}}' "$gateway")"
  python3 -c 'import json,sys; start,end,pid,restarts,code=map(int,sys.argv[1:]); print(json.dumps({"elapsed_ms": round((end-start)/1000000, 3), "limit_ms": 8000, "gateway_pid": pid, "restart_count": restarts, "exit_code": code}, sort_keys=True))' \
    "$started_ns" "$finished_ns" "$gateway_pid" "$restart_count" "$exit_code" \
    >"$work_dir/evidence/shutdown.json"
  test "$restart_count" = 0
  test "$exit_code" = 0
  docker exec "$upstream" python /fixture/unix_receiver.py control resume \
    >"$work_dir/evidence/receiver-resume-after-shutdown.json"
  previous=-1
  stable=0
  attempt=0
  while [ "$attempt" -lt 30 ] && [ "$stable" -lt 3 ]; do
    docker exec "$upstream" python /fixture/unix_receiver.py control status \
      >"$work_dir/evidence/receiver-after-shutdown.json"
    current="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["received"])' \
      "$work_dir/evidence/receiver-after-shutdown.json")"
    if [ "$current" = "$previous" ]; then stable=$((stable + 1)); else stable=0; fi
    previous="$current"
    attempt=$((attempt + 1))
    sleep 0.1
  done
  [ "$stable" -ge 3 ] || { echo "receiver did not become stable after gateway exit" >&2; exit 1; }
  docker exec "$upstream" python /fixture/http2_pressure_analyze.py analyze-stalled \
    >"$work_dir/evidence/report.json"
  cat "$work_dir/evidence/report.json"
  echo "gateway_pid=$gateway_pid restart_count=0 exit_code=0 shutdown_mode=stalled"
else
docker exec "$upstream" python /fixture/unix_receiver.py control resume \
  >"$work_dir/evidence/receiver-resume.json"
wait_metrics recovered 'import json,sys; m=json.load(open(sys.argv[1])); p=json.load(open(sys.argv[3])); sys.exit(0 if m["queue_depth"]==0 and m["sink_healthy"]==1 and m["records_sent_total"]>p["records_sent_total"] else 1)'
run_oha recovered 32
wait_metrics before-stop 'import json,sys; m=json.load(open(sys.argv[1])); sys.exit(0 if m["queue_depth"]==0 and m["sink_healthy"]==1 else 1)'

test "$gateway_pid" = "$(docker inspect --type container --format '{{.State.Pid}}' "$gateway")"
test "$(docker inspect --type container --format '{{.RestartCount}}' "$gateway")" = 0
docker stop --time 8 "$gateway" >/dev/null
test "$(docker inspect --type container --format '{{.State.ExitCode}}' "$gateway")" = 0
attempt=0
while [ "$attempt" -lt 30 ]; do
  docker exec "$upstream" python /fixture/unix_receiver.py control status \
    >"$work_dir/evidence/receiver-final.json"
  if python3 -c 'import json,sys; x=json.load(open(sys.argv[1])); e=x["events"]; sys.exit(0 if e.get("dataplane_stopped")==1 and e.get("runtime_log_final")==1 else 1)' \
      "$work_dir/evidence/receiver-final.json"; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.2
done
[ "$attempt" -lt 30 ] || { echo "stop/final receiver events did not arrive" >&2; exit 1; }
docker exec "$upstream" python /fixture/http2_pressure_analyze.py analyze \
  >"$work_dir/evidence/report.json"
cat "$work_dir/evidence/report.json"
echo "gateway_pid=$gateway_pid restart_count=0 exit_code=0"
fi

if [ "${BONVOYAGE_RETAIN_RUNTIME_LOG_HTTP2_EVIDENCE:-0}" = 1 ]; then
  results_dir="$PWD/benchmarks/results/verification/runtime-log-http2-$shutdown_mode-$suffix"
  mkdir "$results_dir"
  cp "$work_dir/evidence/"*.json "$results_dir/"
  cp "$work_dir/evidence/source-commit.txt" "$results_dir/"
  cp "$work_dir/evidence/source-status.txt" "$results_dir/"
  mkdir "$results_dir/source"
  cp scripts/phase3-runtime-log-http2-pressure.sh scripts/test-fixture-secrets.sh \
    tests/fixtures/runtime-log-service/http2_pressure_analyze.py "$results_dir/source/"
  for source in scripts/phase3-runtime-log-http2-pressure.sh scripts/test-fixture-secrets.sh tests/fixtures/runtime-log-service/http2_pressure_analyze.py; do
    shasum -a 256 "$source"
  done >"$results_dir/source-checksums.txt"
  docker image inspect "$gateway_image" --format '{{.Id}}' >"$results_dir/gateway-image-id.txt"
  (
    cd "$results_dir"
    shasum -a 256 ./*.json ./*.txt >checksums.sha256
  )
  echo "retained_evidence=$results_dir"
fi
