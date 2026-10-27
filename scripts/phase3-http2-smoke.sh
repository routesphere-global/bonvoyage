#!/bin/sh
set -eu

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

umask 077

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
suffix="$$"
network="bonvoyage-http2-smoke-$suffix"
volume="bonvoyage-http2-snapshot-$suffix"
secret_volume="${volume}-secrets"
access_volume="bonvoyage-http2-access-log-$suffix"
gateway="bonvoyage-http2-gateway-$suffix"
upstream="bonvoyage-http2-upstream-$suffix"
drain_client="bonvoyage-http2-drain-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-http2.XXXXXX")"
retain_access_log_evidence="${BONVOYAGE_RETAIN_ACCESS_LOG_EVIDENCE:-0}"

case "$retain_access_log_evidence" in
  0|1) ;;
  *)
    echo "BONVOYAGE_RETAIN_ACCESS_LOG_EVIDENCE must be 0 or 1" >&2
    exit 1
    ;;
esac

cleanup() {
  status="$?"
  if [ "$status" -ne 0 ] && docker inspect "$gateway" >/dev/null 2>&1; then
    echo "BonVoyage gateway logs after HTTP/2 smoke failure:" >&2
    docker logs "$gateway" >&2 || true
  fi
  docker rm --force "$gateway" "$upstream" "$drain_client" \
    >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" "$access_volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$work_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  rm -rf "$work_dir"
  exit "$status"
}
trap cleanup EXIT INT TERM

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required for the ephemeral HTTP/2 TLS fixture" >&2
  exit 1
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage HTTP2 Test CA" \
  -keyout "$work_dir/ca-key.pem" -out "$work_dir/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=api.example.test" \
  -keyout "$work_dir/server-key.pem" -out "$work_dir/server.csr" \
  >/dev/null 2>&1
printf '%s\n' \
  "subjectAltName=DNS:api.example.test" \
  "extendedKeyUsage=serverAuth" \
  "keyUsage=digitalSignature,keyEncipherment" >"$work_dir/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work_dir/server.csr" \
  -CA "$work_dir/ca.pem" -CAkey "$work_dir/ca-key.pem" -CAcreateserial \
  -extfile "$work_dir/server-ext.cnf" -out "$work_dir/server-chain.pem" \
  >/dev/null 2>&1
chmod 600 "$work_dir"/*-key.pem
dd if=/dev/zero bs=32768 count=1 2>/dev/null | tr '\000' x \
  >"$work_dir/request-body.bin"

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem
docker volume create "$access_volume" >/dev/null
docker run --rm --platform "$platform" \
  --volume "$access_volume:/access" \
  --entrypoint chown "$upstream_image" -R 65532:65532 /access

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-http2.yaml:/etc/bonvoyage/http2.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/http2.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >/dev/null

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --volume "$work_dir:/tls:ro" "$upstream_image" >/dev/null
docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test \
  --volume "$volume:/snapshot:ro" \
  --volume "$access_volume:/var/log/bonvoyage" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$image" \
  --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --access-log-directory /var/log/bonvoyage \
  --access-log-queue-capacity 256 \
  --access-log-max-file-bytes 1048576 \
  --access-log-flush-interval-ms 50 \
  --smp 1 --memory 256M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug >/dev/null

bv_wait_gateway_ready "$gateway" "$upstream" "http://$gateway:9901/health/ready"

h2_debug_request() {
  output="$1"
  path="$2"
  docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" \
    --network "$network" --volume "$work_dir:/tls:ro" "$oha_image" \
    --debug --no-color --http-version 2 --disable-compression --no-tui \
    -n 1 --cacert /tls/ca.pem "https://api.example.test:8443$path" \
    >"$work_dir/$output" 2>&1
}

h2_response_status() {
  sed -n 's/^[[:space:]]*status: \([0-9][0-9]*\),$/\1/p' "$1" | head -n 1
}

h2_upstream_connection() {
  sed -n 's/.*"x-upstream-connection": "\([^"]*\)".*/\1/p' "$1" | head -n 1
}

# Prove exact ALPN selection, malformed-preface containment, and that the
# existing cleartext HTTP/1 listener still serves the same snapshot.
docker exec "$upstream" python -c '
import socket
import ssl
import urllib.request

context = ssl.create_default_context(cafile="/tls/ca.pem")
context.set_alpn_protocols(["h2", "http/1.1"])
with socket.create_connection(("api.example.test", 8443), timeout=10) as raw:
    with context.wrap_socket(raw, server_hostname="api.example.test") as secure:
        assert secure.selected_alpn_protocol() == "h2"
        secure.sendall(b"X")
        try:
            while secure.recv(4096):
                pass
        except (ConnectionResetError, ssl.SSLError):
            pass

wrong_protocol = ssl.create_default_context(cafile="/tls/ca.pem")
wrong_protocol.set_alpn_protocols(["http/1.1"])
try:
    with socket.create_connection(("api.example.test", 8443), timeout=10) as raw:
        with wrong_protocol.wrap_socket(
            raw, server_hostname="api.example.test"
        ) as secure:
            assert secure.selected_alpn_protocol() is None
            secure.sendall(b"GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
            try:
                while secure.recv(4096):
                    pass
            except (ConnectionResetError, ssl.SSLError):
                pass
except ssl.SSLError:
    pass

http1 = urllib.request.Request(
    "http://bonvoyage-http2-gateway-'"$suffix"':8080/bonvoyage/ready",
    headers={"Host": "api.example.test"},
)
with urllib.request.urlopen(http1, timeout=10) as response:
    assert response.status == 200 and response.read() == b"ready\n"
'

# Downstream HTTP/2 uses the same secure-default HTTP/1 upstream policy. Wait
# until the controlled peer has attempted its delayed forged write, then prove
# that a later stream reaches a fresh upstream socket and receives real health.
for variant in bodyless content-length chunked; do
  overrun="$work_dir/delayed-overrun-$variant.txt"
  recovery="$work_dir/delayed-recovery-$variant.txt"
  h2_debug_request "delayed-overrun-$variant.txt" \
    "/response-overrun-delayed/$variant"
  case "$variant" in
    bodyless) expected_status=204 ;;
    *) expected_status=200 ;;
  esac
  test "$(h2_response_status "$overrun")" = "$expected_status"
  first_upstream="$(h2_upstream_connection "$overrun")"
  test -n "$first_upstream"
  sleep 1
  h2_debug_request "delayed-recovery-$variant.txt" "/healthz"
  test "$(h2_response_status "$recovery")" = "200"
  ! grep -Fiq 'x-bonvoyage-forged' "$recovery"
  next_upstream="$(h2_upstream_connection "$recovery")"
  test -n "$next_upstream"
  test "$next_upstream" != "$first_upstream"
  grep -Fq 'body: b"ok\n"' "$recovery"
done

docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  -n 32 -c 1 -p 8 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/bonvoyage/ready \
  >"$work_dir/fixed-response.oha.json"

# 128 KiB exceeds the initial stream window and exercises response DATA resume.
docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  -n 24 -c 2 -p 4 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/payload/131072 \
  >"$work_dir/proxied-response.oha.json"

# Translate decoded HTTP/1.1 upstream chunks into HTTP/2 DATA frames. The
# upstream trailer is validated and intentionally omitted downstream.
docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  -n 16 -c 2 -p 4 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/chunked-with-trailers/131072 \
  >"$work_dir/chunked-response.oha.json"

# Stream a request body through HTTP/2 flow control into the HTTP/1 upstream.
docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  -n 16 -c 2 -p 2 -m POST -D /tls/request-body.bin \
  -T application/octet-stream --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/echo \
  >"$work_dir/proxied-request.oha.json"

docker exec "$upstream" python -c '
import json
for path in (
    "/tls/fixed-response.oha.json",
    "/tls/proxied-response.oha.json",
    "/tls/chunked-response.oha.json",
    "/tls/proxied-request.oha.json",
):
    with open(path, encoding="utf-8") as source:
        result = json.load(source)
    assert result["summary"]["successRate"] == 1, path
    assert result["summary"]["requestsPerSec"] > 0, path
'

docker exec "$upstream" python -c '
import urllib.request
metrics = urllib.request.urlopen(
    "http://bonvoyage-http2-gateway-'"$suffix"':9090/metrics", timeout=10
).read().decode()

def total(name):
    return sum(
        float(line.split()[-1])
        for line in metrics.splitlines()
        if line.startswith(name + "{") or line.startswith(name + " ")
    )

prefix = "bonvoyage_bonvoyage_gateway_"
assert any(
    line.startswith(prefix + "http2_drain_timeouts_total")
    for line in metrics.splitlines()
)
assert total(prefix + "http2_connections_total") >= 3
assert total(prefix + "http2_streams_total") >= 94
assert total(prefix + "http2_protocol_errors_total") >= 1
assert total(prefix + "tls_alpn_rejections_total") >= 1
assert total(prefix + "requests_total") >= 95
assert total(prefix + "response_bytes_total") >= 3 * 1024 * 1024
assert total(prefix + "upstream_chunked_responses_total") >= 16
assert total(prefix + "upstream_response_trailers_dropped_total") >= 16
assert total(prefix + "access_log_enabled") == 1
assert total(prefix + "access_log_sink_healthy") == 1
assert total(prefix + "access_log_records_enqueued_total") >= 95
assert total(prefix + "access_log_records_dropped_total") == 0
assert total(prefix + "access_log_queue_overflows_total") == 0
assert total(prefix + "access_log_write_failures_total") == 0
assert total(prefix + "access_log_capacity_exhaustions_total") == 0
print(metrics, end="")
' >"$work_dir/metrics.prom"

# Keep one stream active while TERM starts graceful listener drain. The
# response must finish on the existing connection before the process exits.
docker run --user "$(id -u):$(id -g)" --detach --platform "$platform" --name "$drain_client" \
  --network "$network" --volume "$work_dir:/tls:ro" "$oha_image" \
  -n 1 -c 1 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/slow/1000 >/dev/null

attempt=0
until docker exec "$upstream" python -c '
import urllib.request
metrics = urllib.request.urlopen(
    "http://bonvoyage-http2-gateway-'"$suffix"':9090/metrics", timeout=1
).read().decode()
name = "bonvoyage_bonvoyage_gateway_active_http2_streams"
total = sum(
    float(line.split()[-1])
    for line in metrics.splitlines()
    if line.startswith(name + "{") or line.startswith(name + " ")
)
assert total >= 1
' >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "HTTP/2 drain stream did not become active" >&2
    exit 1
  fi
  sleep 0.1
done

docker stop --signal TERM --time 20 "$gateway" >/dev/null
exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
test "$exit_code" -eq 0
test "$(docker wait "$drain_client")" -eq 0
docker logs "$drain_client" >"$work_dir/drain-response.oha.json" 2>/dev/null
docker exec "$upstream" python -c '
import json
with open("/tls/drain-response.oha.json", encoding="utf-8") as source:
    result = json.load(source)
assert result["summary"]["successRate"] == 1, result
assert result["statusCodeDistribution"].get("200") == 1, result
'
docker logs "$gateway" >"$work_dir/gateway.log" 2>&1

docker run --rm --platform "$platform" \
  --volume "$access_volume:/access:ro" \
  --entrypoint python "$upstream_image" -c '
import collections
import glob
import json

expected = {
    "schema",
    "timestamp_unix_us",
    "snapshot_generation",
    "shard",
    "listener",
    "route",
    "cluster",
    "protocol",
    "method",
    "action",
    "status",
    "completion",
    "duration_us",
    "request_body_bytes",
    "response_body_bytes",
}
forbidden = {
    "authority",
    "host",
    "client_ip",
    "forwarded_for",
    "request_path",
    "query",
    "user_id",
    "tenant_id",
    "api_key",
    "jwt",
    "cookie",
    "headers",
    "request_body",
    "response_body",
}
records = []
raw = ""
paths = sorted(glob.glob("/access/*.jsonl"))
assert paths, "access-log sink did not create a JSONL segment"
for path in paths:
    with open(path, encoding="utf-8") as source:
        for line in source:
            raw += line
            value = json.loads(line)
            assert set(value) == expected, value
            assert value["schema"] == "bonvoyage.access.v1", value
            assert forbidden.isdisjoint(value), value
            records.append(value)

assert len(records) == 96, len(records)
protocols = collections.Counter(value["protocol"] for value in records)
actions = collections.Counter(value["action"] for value in records)
completions = collections.Counter(value["completion"] for value in records)
statuses = collections.Counter(str(value["status"]) for value in records)
assert protocols == {"http1": 1, "http2": 95}, protocols
assert actions == {"fixed_response": 33, "proxy": 63}, actions
assert completions == {"complete": 96}, completions
assert statuses == {"200": 95, "204": 1}, statuses
assert any(value["request_body_bytes"] == 32768 for value in records)
assert any(value["response_body_bytes"] == 131072 for value in records)
for marker in (
    "api.example.test",
    "/bonvoyage/ready",
    "/payload/131072",
    "203.0.113.77",
    "authorization",
    "cookie",
):
    assert marker not in raw.lower(), marker

summary = {
    "actions": dict(sorted(actions.items())),
    "completions": dict(sorted(completions.items())),
    "forbidden_fields_present": [],
    "protocols": dict(sorted(protocols.items())),
    "records": len(records),
    "request_body_bytes_max": max(value["request_body_bytes"] for value in records),
    "response_body_bytes_max": max(value["response_body_bytes"] for value in records),
    "schema": "bonvoyage.access.v1",
    "statuses": dict(sorted(statuses.items())),
}
print(json.dumps(summary, indent=2, sort_keys=True))
' >"$work_dir/access-log-validation.json"
# Docker copies these private segments as the host caller, not container root.
docker cp "$gateway:/var/log/bonvoyage/." "$work_dir/"

if [ "$retain_access_log_evidence" -eq 1 ]; then
  captured_at="$(date -u +%Y%m%dT%H%M%SZ)"
  run_id="access-log-$captured_at"
  evidence_root="${BONVOYAGE_HTTP2_SMOKE_EVIDENCE_ROOT:-$PWD/benchmarks/results/verification}"
  evidence_dir="$evidence_root/$run_id"
  test ! -e "$evidence_dir"
  mkdir -p "$evidence_dir"
  cp "$work_dir"/*.json "$work_dir"/*.jsonl "$work_dir/metrics.prom" \
    "$work_dir/gateway.log" "$evidence_dir/"
  source_commit="$(git rev-parse HEAD)"
  if [ -z "$(git status --porcelain)" ]; then
    source_dirty=false
  else
    source_dirty=true
  fi
  dataplane_image_id="$(docker image inspect --format '{{.Id}}' "$image")"
  cat >"$evidence_dir/metadata.txt" <<EOF
captured_at_utc=$captured_at
run_id=$run_id
source_commit=$source_commit
source_dirty=$source_dirty
platform=$platform
dataplane_image_id=$dataplane_image_id
schema=bonvoyage.access.v1
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
performance_claim_authorized=false
EOF
  cat >"$evidence_dir/README.md" <<'EOF'
# Phase 3 bounded access-log evidence

Local engineering evidence for the bounded asynchronous access-log checkpoint.
The retained mixed-protocol workload contains one HTTP/1.1 and 95 HTTP/2
completed records, raw delivery metrics, load-generator outputs, gateway logs,
image identity, and a privacy/schema validation summary. It is not dedicated
performance evidence and does not authorize customer or marketing claims.
EOF
  cat >"$evidence_dir/source-files.txt" <<'EOF'
Makefile
dataplane/CMakeLists.txt
dataplane/include/bonvoyage/runtime/access_log.hh
dataplane/include/bonvoyage/runtime/gateway.hh
dataplane/src/access_log.cc
dataplane/src/gateway.cc
dataplane/src/main.cc
dataplane/tests/access_log_runtime_test.cc
dataplane/tests/access_log_test.cc
deploy/docker/bonvoyage/Dockerfile
observability/grafana/dashboards/bonvoyage-decision-console.json
observability/logging/events.yaml
observability/prometheus/rules/bonvoyage-alerts.yml
observability/prometheus/rules/bonvoyage-recording-rules.yml
observability/telemetry-contract.yaml
scripts/phase3-http2-smoke.sh
scripts/test-fixture-secrets.sh
tests/fixtures/phase3-http2.yaml
website/scripts/validate-project.cjs
EOF
  while IFS= read -r source_file; do
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$source_file"
    else
      shasum -a 256 "$source_file"
    fi
  done <"$evidence_dir/source-files.txt" \
    >"$evidence_dir/source-checksums.sha256"
  checksum_manifest="$work_dir/checksums.sha256.tmp"
  (
    cd "$evidence_dir"
    find . -type f ! -name checksums.sha256 -print | LC_ALL=C sort |
      while IFS= read -r path; do
        if command -v sha256sum >/dev/null 2>&1; then
          sha256sum "${path#./}"
        else
          shasum -a 256 "${path#./}"
        fi
      done >"$checksum_manifest"
  )
  mv "$checksum_manifest" "$evidence_dir/checksums.sha256"
  printf '%s\n' "$run_id" \
    >"$evidence_root/current-access-log.txt.tmp"
  mv "$evidence_root/current-access-log.txt.tmp" \
    "$evidence_root/current-access-log.txt"
  echo "Retained bounded access-log evidence: $evidence_dir"
fi
echo "BonVoyage downstream HTTP/2 integration smoke passed"
