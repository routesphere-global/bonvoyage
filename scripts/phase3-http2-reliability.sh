#!/bin/sh
set -eu

umask 077

script_dir="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
repo_root="$(CDPATH='' cd "$script_dir/.." && pwd)"
cd "$repo_root"

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
fixture="$repo_root/tests/fixtures/phase3-http2.yaml"

stream_seconds="${BONVOYAGE_HTTP2_RELIABILITY_SECONDS:-60}"
connection_cycles="${BONVOYAGE_HTTP2_CONNECTION_CYCLES:-25}"
connection_requests="${BONVOYAGE_HTTP2_CONNECTION_REQUESTS:-8}"
minimum_streams="${BONVOYAGE_HTTP2_MIN_STREAMS:-100}"
drain_timeout_seconds="${BONVOYAGE_HTTP2_DRAIN_TIMEOUT_SECONDS:-20}"
rss_settle_seconds="${BONVOYAGE_HTTP2_RSS_SETTLE_SECONDS:-3}"
rss_max_growth_bytes="${BONVOYAGE_HTTP2_RSS_MAX_GROWTH_BYTES:-16777216}"
rss_max_growth_percent="${BONVOYAGE_HTTP2_RSS_MAX_GROWTH_PERCENT:-20}"

started_at="$(date -u +%Y%m%dT%H%M%SZ)"
suffix="$$"
network="bonvoyage-http2-reliability-$suffix"
volume="bonvoyage-http2-reliability-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-http2-reliability-gateway-$suffix"
upstream="bonvoyage-http2-reliability-upstream-$suffix"
disconnect_client="bonvoyage-http2-disconnect-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-http2-reliability.XXXXXX")"
evidence_root="${BONVOYAGE_HTTP2_RELIABILITY_EVIDENCE_ROOT:-$repo_root/benchmarks/results/verification}"
evidence_dir="${BONVOYAGE_HTTP2_RELIABILITY_EVIDENCE_DIR:-$evidence_root/http2-reliability-$started_at-$suffix}"

metric_prefix="bonvoyage_bonvoyage_gateway_"
active_connections_metric="${metric_prefix}active_connections"
active_http2_connections_metric="${metric_prefix}active_http2_connections"
active_http2_streams_metric="${metric_prefix}active_http2_streams"
http2_connections_metric="${metric_prefix}http2_connections_total"
http2_streams_metric="${metric_prefix}http2_streams_total"
http2_cancellations_metric="${metric_prefix}http2_request_cancellations_total"
request_timeouts_metric="${metric_prefix}request_timeouts_total"

checksum_tool=""
dataplane_image_id=""
compiler_image_id=""
upstream_image_id=""
oha_image_id=""
evidence_ready=0

fail() {
  message="$1"
  printf 'FAIL: %s\n' "$message" >&2
  if [ "$evidence_ready" -eq 1 ]; then
    printf '%s\n' "$message" >"$evidence_dir/failure.txt"
  fi
  exit 1
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

capture_container_evidence() {
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

  if [ "$evidence_ready" -eq 1 ]; then
    capture_container_evidence "$disconnect_client" forced-disconnect-client
    capture_container_evidence "$gateway" gateway
    capture_container_evidence "$upstream" upstream

    if [ "$status" -ne 0 ]; then
      printf 'outcome=FAIL\nexit_code=%s\n' "$status" \
        >"$evidence_dir/run-status.env"
    elif [ ! -f "$evidence_dir/run-status.env" ]; then
      printf 'outcome=PASS\nexit_code=0\n' >"$evidence_dir/run-status.env"
    fi

    if ! write_checksums; then
      printf 'FAIL: could not create or verify the retained evidence manifest\n' >&2
      printf 'outcome=FAIL\nexit_code=1\n' >"$evidence_dir/run-status.env"
      status=1
      write_checksums >/dev/null 2>&1 || true
    fi
  fi

  docker rm --force "$gateway" "$upstream" "$disconnect_client" \
    >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$work_dir/secrets" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  rm -rf "$work_dir"

  if [ "$status" -eq 0 ]; then
    printf 'BonVoyage downstream HTTP/2 lifecycle qualification passed\n'
  else
    printf 'BonVoyage downstream HTTP/2 lifecycle qualification failed\n' >&2
  fi
  if [ "$evidence_ready" -eq 1 ]; then
    printf 'Evidence retained at %s\n' "$evidence_dir"
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command_name in awk date docker find git openssl sort; do
  command -v "$command_name" >/dev/null 2>&1 \
    || fail "required command is unavailable: $command_name"
done
if command -v sha256sum >/dev/null 2>&1; then
  checksum_tool="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  checksum_tool="shasum"
else
  fail "either sha256sum or shasum is required"
fi

require_positive_integer BONVOYAGE_HTTP2_RELIABILITY_SECONDS "$stream_seconds"
require_positive_integer BONVOYAGE_HTTP2_CONNECTION_CYCLES "$connection_cycles"
require_positive_integer BONVOYAGE_HTTP2_CONNECTION_REQUESTS "$connection_requests"
require_positive_integer BONVOYAGE_HTTP2_MIN_STREAMS "$minimum_streams"
require_positive_integer BONVOYAGE_HTTP2_DRAIN_TIMEOUT_SECONDS "$drain_timeout_seconds"
require_nonnegative_integer BONVOYAGE_HTTP2_RSS_SETTLE_SECONDS "$rss_settle_seconds"
require_positive_integer BONVOYAGE_HTTP2_RSS_MAX_GROWTH_BYTES "$rss_max_growth_bytes"
require_nonnegative_integer BONVOYAGE_HTTP2_RSS_MAX_GROWTH_PERCENT "$rss_max_growth_percent"

[ -f "$fixture" ] || fail "HTTP/2 fixture is missing: $fixture"
case "$oha_image" in
  *@sha256:*) ;;
  *) fail "BONVOYAGE_OHA_IMAGE must use an immutable sha256 digest" ;;
esac

if [ -e "$evidence_dir" ]; then
  fail "evidence directory already exists: $evidence_dir"
fi
mkdir -p "$evidence_dir" || fail "could not create evidence directory: $evidence_dir"
evidence_dir="$(CDPATH='' cd "$evidence_dir" && pwd)"
evidence_ready=1
mkdir -p "$work_dir/secrets" "$work_dir/client"

docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"
dataplane_image_id="$(docker image inspect --format '{{.Id}}' "$image")" \
  || fail "dataplane image is unavailable: $image"
compiler_image_id="$(docker image inspect --format '{{.Id}}' "$compiler_image")" \
  || fail "snapshot compiler image is unavailable: $compiler_image"
upstream_image_id="$(docker image inspect --format '{{.Id}}' "$upstream_image")" \
  || fail "controlled upstream image is unavailable: $upstream_image"
oha_image_id="$(docker image inspect --format '{{.Id}}' "$oha_image")" \
  || fail "pinned oha image is unavailable: $oha_image"

# Preserve the exact source inputs and immutable local image identities used.
cp "$fixture" "$evidence_dir/phase3-http2.yaml"
cp "$script_dir/phase3-http2-reliability.sh" "$evidence_dir/harness.sh"
cp "$script_dir/test-fixture-secrets.sh" "$evidence_dir/test-fixture-secrets.sh"
docker image inspect \
  "$dataplane_image_id" "$compiler_image_id" "$upstream_image_id" "$oha_image_id" \
  >"$evidence_dir/images.inspect.json"
docker run --rm --platform "$platform" --network none "$oha_image_id" --version \
  >"$evidence_dir/oha-version.txt" 2>&1 \
  || fail "could not execute the pinned oha image"

{
  printf 'started_at_utc=%s\n' "$started_at"
  printf 'git_commit=%s\n' "$(git rev-parse HEAD)"
  printf 'git_status_begin\n'
  git status --short
  printf 'git_status_end\n'
  printf 'platform=%s\n' "$platform"
  printf 'fixture_sha256=%s\n' "$(checksum_value "$fixture")"
  printf 'fixture_helper_sha256=%s\n' "$(checksum_value "$script_dir/test-fixture-secrets.sh")"
  printf 'dataplane_image_ref=%s\n' "$image"
  printf 'dataplane_image_id=%s\n' "$dataplane_image_id"
  printf 'compiler_image_ref=%s\n' "$compiler_image"
  printf 'compiler_image_id=%s\n' "$compiler_image_id"
  printf 'upstream_image_ref=%s\n' "$upstream_image"
  printf 'upstream_image_id=%s\n' "$upstream_image_id"
  printf 'oha_image_ref=%s\n' "$oha_image"
  printf 'oha_image_id=%s\n' "$oha_image_id"
  printf 'stream_seconds=%s\n' "$stream_seconds"
  printf 'connection_cycles=%s\n' "$connection_cycles"
  printf 'connection_requests=%s\n' "$connection_requests"
  printf 'minimum_streams=%s\n' "$minimum_streams"
  printf 'drain_timeout_seconds=%s\n' "$drain_timeout_seconds"
  printf 'rss_settle_seconds=%s\n' "$rss_settle_seconds"
  printf 'rss_max_growth_bytes=%s\n' "$rss_max_growth_bytes"
  printf 'rss_max_growth_percent=%s\n' "$rss_max_growth_percent"
  printf 'host=%s\n' "$(uname -a)"
  docker version
} >"$evidence_dir/environment.txt" 2>&1

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage HTTP2 Reliability CA" \
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
openssl x509 -in "$work_dir/secrets/server-chain.pem" -noout \
  -fingerprint -sha256 -serial -dates -subject \
  >"$evidence_dir/ephemeral-certificate.txt"

docker network create --internal "$network" >/dev/null \
  || fail "could not create the isolated Docker network"
docker volume create "$volume" >/dev/null \
  || fail "could not create the snapshot volume"

docker run --rm --platform "$platform" --network none --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$fixture:/etc/bonvoyage/http2.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image_id" -input /etc/bonvoyage/http2.yaml \
  -output /var/lib/bonvoyage/snapshot.pb \
  >"$evidence_dir/snapshot-compiler.log" 2>&1 \
  || fail "snapshot compilation failed"

# Copy the immutable snapshot through stdout so retained files stay user-owned.
docker run --rm --platform "$platform" --network none --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$volume:/snapshot:ro" --entrypoint python "$upstream_image_id" \
  -c 'import sys; sys.stdout.buffer.write(open("/snapshot/snapshot.pb", "rb").read())' \
  >"$evidence_dir/snapshot.pb" \
  || fail "could not retain the compiled snapshot"

docker run --detach --platform "$platform" --name "$upstream" \
  --user "$(id -u):$(id -g)" \
  --network "$network" --network-alias upstream --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$evidence_dir:/evidence:ro" "$upstream_image_id" >/dev/null \
  || fail "could not start the controlled upstream"

attempt=0
until docker exec "$upstream" python -c \
  'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:8081/healthz", timeout=1).status == 200' \
  >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 30 ] || fail "controlled upstream did not become healthy"
  sleep 1
done
docker exec "$upstream" python -c '
import server
assert server.ControlledThreadingHTTPServer.request_queue_size >= 128
print(f"request_queue_size={server.ControlledThreadingHTTPServer.request_queue_size}")
' >"$evidence_dir/upstream-capacity-check.txt" 2>&1 \
  || fail "controlled upstream listen backlog is below the qualification floor"

docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test --dns-search . --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
  "$dataplane_image_id" --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 256M --overprovisioned \
  --logger-log-level bonvoyage-gateway=info >/dev/null \
  || fail "could not start the BonVoyage dataplane"

bv_wait_gateway_ready "$gateway" "$upstream" "http://$gateway:9901/health/ready"

capture_metrics() {
  filename="$1"
  docker exec "$upstream" python -c '
import sys
import urllib.request
body = urllib.request.urlopen(sys.argv[1], timeout=5).read()
sys.stdout.buffer.write(body)
' "http://$gateway:9090/metrics" >"$evidence_dir/$filename"
}

metric_total() {
  metric_name="$1"
  docker exec "$upstream" python -c '
import sys
import urllib.request
name = sys.argv[2]
metrics = urllib.request.urlopen(sys.argv[1], timeout=5).read().decode()
total = sum(
    float(line.split()[-1])
    for line in metrics.splitlines()
    if line.startswith(name + "{") or line.startswith(name + " ")
)
print(int(total))
' "http://$gateway:9090/metrics" "$metric_name"
}

active_values() {
  docker exec "$upstream" python -c '
import sys
import urllib.request
metrics = urllib.request.urlopen(sys.argv[1], timeout=5).read().decode()

def total(name):
    return int(sum(
        float(line.split()[-1])
        for line in metrics.splitlines()
        if line.startswith(name + "{") or line.startswith(name + " ")
    ))

print("%d %d %d" % tuple(total(name) for name in sys.argv[2:5]))
' "http://$gateway:9090/metrics" \
    "$active_http2_connections_metric" "$active_http2_streams_metric" \
    "$active_connections_metric"
}

parse_active_values() {
  case "$1" in
    *' '*' '*) ;;
    *) return 1 ;;
  esac
  parsed_http2_connections="${1%% *}"
  parsed_remainder="${1#* }"
  parsed_http2_streams="${parsed_remainder%% *}"
  parsed_connections="${parsed_remainder#* }"
  case "$parsed_connections" in
    *' '*) return 1 ;;
  esac
  case "$parsed_http2_connections:$parsed_http2_streams:$parsed_connections" in
    *[!0-9:]*|:*|*::*) return 1 ;;
  esac
}

measure_rss_kib() {
  # Docker requires PID to be present in custom ps output on some engines.
  docker top "$gateway" -eo pid,rss 2>/dev/null \
    | awk '
        NR > 1 && $2 ~ /^[0-9]+$/ { total += $2; count += 1 }
        END {
          if (count == 0) exit 1
          printf "%.0f\n", total
        }
      '
}

record_state() {
  phase="$1"
  index="$2"
  rss="$(measure_rss_kib)" || return 1
  values="$(active_values)" || return 1
  parse_active_values "$values" || return 1
  printf '%s,%s,%s,%s,%s,%s,%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$phase" "$index" "$rss" \
    "$parsed_http2_connections" "$parsed_http2_streams" \
    "$parsed_connections" >>"$evidence_dir/lifecycle-samples.csv"
  printf '%s\n' "$rss"
}

wait_for_drain() {
  phase="$1"
  max_attempts=$((drain_timeout_seconds * 10))
  attempt=0
  while [ "$attempt" -lt "$max_attempts" ]; do
    if values="$(active_values 2>/dev/null)"; then
      parse_active_values "$values" || fail "invalid active metric tuple"
      printf '%s,%s,%s,%s,%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$phase" "$attempt" \
        "$parsed_http2_connections" "$parsed_http2_streams" \
        >>"$evidence_dir/drain-observations.csv"
      if [ "$parsed_http2_connections" -eq 0 ] && \
         [ "$parsed_http2_streams" -eq 0 ]; then
        return 0
      fi
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  fail "$phase did not drain active HTTP/2 connections and streams within ${drain_timeout_seconds}s"
}

wait_for_active_stream() {
  max_attempts=$((drain_timeout_seconds * 10))
  attempt=0
  while [ "$attempt" -lt "$max_attempts" ]; do
    if values="$(active_values 2>/dev/null)"; then
      parse_active_values "$values" || fail "invalid active metric tuple"
      if [ "$parsed_http2_connections" -ge 1 ] && \
         [ "$parsed_http2_streams" -ge 1 ]; then
        return 0
      fi
    fi
    running="$(docker inspect --format '{{.State.Running}}' "$disconnect_client" 2>/dev/null || true)"
    [ "$running" = "true" ] \
      || fail "forced-disconnect client exited before an active HTTP/2 stream was observed"
    attempt=$((attempt + 1))
    sleep 0.1
  done
  fail "forced-disconnect workload did not create an active HTTP/2 stream"
}

run_oha_json() {
  output_name="$1"
  shift
  docker run --rm --platform "$platform" --network "$network" --read-only \
    --user "$(id -u):$(id -g)" \
    --security-opt no-new-privileges:true --cap-drop ALL \
    --volume "$work_dir/client:/tls:ro" "$oha_image_id" "$@" \
    >"$evidence_dir/$output_name"
}

validate_oha_success() {
  filename="$1"
  minimum="$2"
  expected="$3"
  docker exec "$upstream" python -c '
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
distribution = result.get("statusCodeDistribution", {})
successes = int(distribution.get("200", 0))
assert result["summary"]["successRate"] == 1, result["summary"]
assert result["summary"]["requestsPerSec"] > 0, result["summary"]
assert not result.get("errorDistribution"), result.get("errorDistribution")
assert set(distribution) <= {"200"}, distribution
assert successes >= int(sys.argv[2]), (successes, sys.argv[2])
if int(sys.argv[3]) > 0:
    assert successes == int(sys.argv[3]), (successes, sys.argv[3])
print(successes)
' "/evidence/$filename" "$minimum" "$expected"
}

validate_oha_duration() {
  filename="$1"
  minimum="$2"
  maximum_deadline_aborts="$3"
  docker exec "$upstream" python -c '
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
distribution = result.get("statusCodeDistribution", {})
errors = result.get("errorDistribution", {})
successes = int(distribution.get("200", 0))
deadline_aborts = int(errors.get("aborted due to deadline", 0))
assert result["summary"]["successRate"] == 1, result["summary"]
assert result["summary"]["requestsPerSec"] > 0, result["summary"]
assert set(distribution) <= {"200"}, distribution
assert set(errors) <= {"aborted due to deadline"}, errors
assert successes >= int(sys.argv[2]), (successes, sys.argv[2])
assert deadline_aborts <= int(sys.argv[3]), (deadline_aborts, sys.argv[3])
print("%d %d" % (successes, deadline_aborts))
' "/evidence/$filename" "$minimum" "$maximum_deadline_aborts"
}

gateway_identity() {
  docker inspect --format \
    '{{.Id}}|{{.State.Pid}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.State.Running}}' \
    "$gateway"
}

printf 'timestamp_utc,phase,index,rss_kib,active_http2_connections,active_http2_streams,active_connections\n' \
  >"$evidence_dir/lifecycle-samples.csv"
printf 'timestamp_utc,phase,attempt,active_http2_connections,active_http2_streams\n' \
  >"$evidence_dir/drain-observations.csv"

initial_identity="$(gateway_identity)" \
  || fail "could not record the initial gateway process identity"
printf 'initial=%s\n' "$initial_identity" >"$evidence_dir/gateway-identities.txt"

run_oha_json warmup.oha.json \
  -n 128 -c 2 -p 8 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/bonvoyage/ready \
  || fail "HTTP/2 warm-up workload failed"
warmup_successes="$(validate_oha_success warmup.oha.json 128 128)" \
  || fail "HTTP/2 warm-up did not return 128 successful responses"
wait_for_drain warmup
sleep "$rss_settle_seconds"
baseline_rss_kib="$(record_state baseline 0)" \
  || fail "could not capture numeric baseline RSS and lifecycle gauges"
capture_metrics metrics-baseline.prom \
  || fail "could not capture baseline metrics"

streams_before="$(metric_total "$http2_streams_metric")" \
  || fail "could not read the HTTP/2 stream counter before churn"
run_oha_json stream-churn.oha.json \
  -z "${stream_seconds}s" -c 2 -p 16 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/bonvoyage/ready \
  || fail "sustained HTTP/2 stream churn workload failed"
stream_result="$(validate_oha_duration stream-churn.oha.json "$minimum_streams" 32)" \
  || fail "stream churn did not meet its successful-stream floor"
stream_successes="${stream_result%% *}"
stream_deadline_aborts="${stream_result#* }"
wait_for_drain stream-churn
streams_after="$(metric_total "$http2_streams_metric")" \
  || fail "could not read the HTTP/2 stream counter after churn"
stream_delta=$((streams_after - streams_before))
[ "$stream_delta" -ge "$stream_successes" ] \
  || fail "HTTP/2 stream counter delta $stream_delta is below $stream_successes successful churn requests"
record_state after-stream-churn 0 >/dev/null \
  || fail "could not sample state after stream churn"
capture_metrics metrics-after-stream-churn.prom \
  || fail "could not capture metrics after stream churn"

connections_before="$(metric_total "$http2_connections_metric")" \
  || fail "could not read the HTTP/2 connection counter before process churn"
cycle=1
connection_successes=0
while [ "$cycle" -le "$connection_cycles" ]; do
  output_name="$(printf 'connection-churn-%04d.oha.json' "$cycle")"
  run_oha_json "$output_name" \
    -n "$connection_requests" -c 1 -p 4 --no-tui --output-format json \
    --http-version 2 --disable-compression --cacert /tls/ca.pem \
    https://api.example.test:8443/bonvoyage/ready \
    || fail "short-lived HTTP/2 client process failed in cycle $cycle"
  cycle_successes="$(validate_oha_success "$output_name" "$connection_requests" "$connection_requests")" \
    || fail "short-lived HTTP/2 client process returned an invalid result in cycle $cycle"
  connection_successes=$((connection_successes + cycle_successes))
  wait_for_drain "connection-churn-$cycle"
  record_state connection-churn "$cycle" >/dev/null \
    || fail "could not sample state after connection churn cycle $cycle"
  cycle=$((cycle + 1))
done
connections_after="$(metric_total "$http2_connections_metric")" \
  || fail "could not read the HTTP/2 connection counter after process churn"
connection_delta=$((connections_after - connections_before))
[ "$connection_delta" -ge "$connection_cycles" ] \
  || fail "HTTP/2 connection counter delta $connection_delta is below $connection_cycles short-lived processes"
capture_metrics metrics-after-connection-churn.prom \
  || fail "could not capture metrics after connection churn"
timeouts_before_forced="$(metric_total "$request_timeouts_metric")" \
  || fail "could not read the timeout counter before forced disconnect"
cancellations_before_forced="$(metric_total "$http2_cancellations_metric")" \
  || fail "could not read the cancellation counter before forced disconnect"

# oha cannot disable keepalive for HTTP/2. A force-removed client process gives
# us a deterministic connection abort while slow streams are still in flight.
docker run --detach --platform "$platform" --name "$disconnect_client" \
  --user "$(id -u):$(id -g)" \
  --network "$network" --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$work_dir/client:/tls:ro" "$oha_image_id" \
  -n 64 -c 2 -p 8 -t 10s --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/slow/5000 >/dev/null \
  || fail "could not start the forced-disconnect HTTP/2 client"
wait_for_active_stream
docker inspect "$disconnect_client" \
  >"$evidence_dir/forced-disconnect-client-before.inspect.json"
record_state forced-disconnect-active 0 >/dev/null \
  || fail "could not sample active forced-disconnect state"
capture_metrics metrics-forced-disconnect-active.prom \
  || fail "could not capture active forced-disconnect metrics"
docker rm --force "$disconnect_client" >/dev/null \
  || fail "could not force the HTTP/2 client disconnect"
wait_for_drain forced-disconnect
record_state after-forced-disconnect 0 >/dev/null \
  || fail "could not sample state after forced disconnect"
capture_metrics metrics-after-forced-disconnect.prom \
  || fail "could not capture metrics after forced disconnect"
timeouts_after_forced="$(metric_total "$request_timeouts_metric")" \
  || fail "could not read the timeout counter after forced disconnect"
cancellations_after_forced="$(metric_total "$http2_cancellations_metric")" \
  || fail "could not read the cancellation counter after forced disconnect"
[ "$timeouts_after_forced" -eq "$timeouts_before_forced" ] \
  || fail "forced disconnect was incorrectly recorded as a request timeout"
cancellation_delta=$((cancellations_after_forced - cancellations_before_forced))
[ "$cancellation_delta" -ge 1 ] \
  || fail "forced disconnect did not increment the HTTP/2 cancellation counter"

run_oha_json recovery.oha.json \
  -n 32 -c 2 -p 4 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/payload/16 \
  || fail "HTTP/2 recovery workload failed after forced disconnect"
recovery_successes="$(validate_oha_success recovery.oha.json 32 32)" \
  || fail "HTTP/2 recovery did not return 32 successful proxied responses"
wait_for_drain recovery

final_identity="$(gateway_identity)" \
  || fail "gateway stopped before the no-restart recovery check"
printf 'final=%s\n' "$final_identity" >>"$evidence_dir/gateway-identities.txt"
[ "$final_identity" = "$initial_identity" ] \
  || fail "gateway process identity changed during lifecycle qualification"

sleep "$rss_settle_seconds"
final_rss_kib="$(record_state final 0)" \
  || fail "could not capture numeric final RSS and lifecycle gauges"
capture_metrics metrics-final.prom || fail "could not capture final metrics"

rss_absolute_limit_kib=$(((rss_max_growth_bytes + 1023) / 1024))
rss_percent_limit_kib=$(((baseline_rss_kib * rss_max_growth_percent + 99) / 100))
rss_allowed_growth_kib="$rss_absolute_limit_kib"
if [ "$rss_percent_limit_kib" -gt "$rss_allowed_growth_kib" ]; then
  rss_allowed_growth_kib="$rss_percent_limit_kib"
fi
rss_growth_kib=$((final_rss_kib - baseline_rss_kib))
if [ "$rss_growth_kib" -lt 0 ]; then
  rss_growth_kib=0
fi
[ "$rss_growth_kib" -le "$rss_allowed_growth_kib" ] \
  || fail "retained RSS grew ${rss_growth_kib} KiB; configured limit is ${rss_allowed_growth_kib} KiB"

peak_rss_kib="$(awk -F, 'NR > 1 && $4 > peak { peak = $4 } END { print peak + 0 }' \
  "$evidence_dir/lifecycle-samples.csv")"

{
  printf 'outcome: PASS\n'
  printf 'scope: downstream HTTP/2 lifecycle behavior for this configured run\n'
  printf 'warmup_successes: %s\n' "$warmup_successes"
  printf 'stream_churn_seconds: %s\n' "$stream_seconds"
  printf 'stream_churn_successes: %s\n' "$stream_successes"
  printf 'stream_churn_deadline_aborts: %s (bounded to 32 in-flight workers)\n' \
    "$stream_deadline_aborts"
  printf 'validated_stream_counter_delta: %s\n' "$stream_delta"
  printf 'short_lived_client_processes: %s\n' "$connection_cycles"
  printf 'short_lived_process_successes: %s\n' "$connection_successes"
  printf 'accepted_connection_counter_delta: %s\n' "$connection_delta"
  printf 'forced_disconnect: observed active connection and stream, then force-removed client\n'
  printf 'forced_disconnect_cancellations: %s\n' "$cancellation_delta"
  printf 'forced_disconnect_timeout_delta: 0\n'
  printf 'recovery_successes: %s\n' "$recovery_successes"
  printf 'gateway_identity_unchanged: true\n'
  printf 'final_active_http2_connections: 0\n'
  printf 'final_active_http2_streams: 0\n'
  printf 'baseline_rss_kib: %s\n' "$baseline_rss_kib"
  printf 'final_rss_kib: %s\n' "$final_rss_kib"
  printf 'peak_sampled_rss_kib: %s\n' "$peak_rss_kib"
  printf 'retained_rss_growth_kib: %s\n' "$rss_growth_kib"
  printf 'retained_rss_growth_limit_kib: %s\n' "$rss_allowed_growth_kib"
  printf 'claim_limit: this bounded run does not prove indefinite leak freedom or dedicated-host performance\n'
} >"$evidence_dir/summary.txt"
printf 'outcome=PASS\nexit_code=0\n' >"$evidence_dir/run-status.env"
