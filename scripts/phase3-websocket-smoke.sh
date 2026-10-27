#!/bin/sh
set -eu

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="websocket-smoke-$timestamp"
suffix="$$"
network="bonvoyage-websocket-$suffix"
volume="bonvoyage-websocket-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-websocket-gateway-$suffix"
upstream="bonvoyage-websocket-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-websocket.XXXXXX")"
stage_dir="$work_dir/evidence"
ready_file="$work_dir/drain-client-ready.txt"
output_root="${BONVOYAGE_WEBSOCKET_EVIDENCE_ROOT:-benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"
: >"$ready_file"
chmod 755 "$work_dir"
chmod 666 "$ready_file"

cleanup() {
  status="$?"
  if [ -d "$stage_dir" ]; then
    capture_metrics "$stage_dir/failure-metrics.prom" 2>/dev/null || true
    docker inspect "$gateway" >"$stage_dir/failure-gateway.inspect.json" \
      2>/dev/null || true
    docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1 || true
    docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1 || true
  fi
  docker rm --force "$gateway" "$upstream" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$work_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  if [ "$status" -eq 0 ]; then
    rm -rf "$work_dir"
  else
    echo "WebSocket smoke failed; temporary evidence: $stage_dir" >&2
    sed -n '1,240p' "$stage_dir/gateway.log" >&2 || true
    sed -n '1,200p' "$stage_dir/upstream.log" >&2 || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

for command_name in date docker git grep mktemp openssl python3 sed sleep uname; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name is required" >&2
    exit 1
  }
done

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

capture_metrics() {
  destination="$1"
  docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-websocket-gateway-'"$suffix"':9090/metrics",
    timeout=5,
).read().decode(), end="")
' >"$destination"
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage WebSocket Test CA" \
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

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-websocket.yaml:/etc/bonvoyage/websocket.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/websocket.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --entrypoint python \
  --volume "$PWD/scripts/phase3-websocket-upstream.py:/websocket-upstream.py:ro" \
  --volume "$PWD/scripts/phase3-websocket-client.py:/websocket-client.py:ro" \
  --volume "$work_dir:/evidence" \
  "$upstream_image" /websocket-upstream.py >/dev/null

attempt=0
until docker exec "$upstream" python -c \
  'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:8081/healthz", timeout=1).status == 200' \
  >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "controlled WebSocket upstream did not become ready" >&2
    exit 1
  fi
  sleep 1
done

docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$image" \
  --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 256M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug >/dev/null

bv_wait_gateway_ready "$gateway" "$upstream" "http://$gateway:9901/health/ready"

docker exec "$upstream" python /websocket-client.py suite \
  "$gateway" /evidence/ca.pem >"$stage_dir/client-results.json"

capture_metrics "$stage_dir/metrics.prom"
python3 - "$stage_dir/metrics.prom" >"$stage_dir/metrics-validation.txt" <<'PY'
import sys

metrics = open(sys.argv[1], encoding="utf-8").read()

def total(suffix):
    result = 0.0
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        if name.split("{", 1)[0] == "bonvoyage_bonvoyage_gateway_" + suffix:
            result += float(raw)
    return result

expected = {
    "websocket_handshake_attempts_total": 17,
    "websocket_handshake_successes_total": 6,
    "websocket_handshake_rejections_total": 5,
    "websocket_upstream_handshake_failures_total": 4,
    "websocket_connections_total": 6,
    "websocket_idle_timeouts_total": 1,
    "websocket_drain_terminations_total": 0,
    "route_overload_rejections_total": 1,
    "request_timeouts_total": 1,
    "upstream_failures_total": 4,
    "upstream_passive_failures_total": 4,
    "active_websocket_connections": 0,
    "active_route_requests": 0,
    "active_upstream_requests": 0,
}
for name, wanted in expected.items():
    actual = total(name)
    assert actual == wanted, (name, actual, wanted)
assert total("websocket_downstream_bytes_total") > 0
assert total("websocket_upstream_bytes_total") > 0
print("WebSocket counters, byte transfer, timeouts, and final gauges passed")
PY

docker exec "$upstream" python /websocket-client.py hold \
  "$gateway" /evidence/drain-client-ready.txt \
  >"$stage_dir/drain-client.json" &
drain_client_pid="$!"
attempt=0
until grep -qx 'ready' "$ready_file"; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ]; then
    echo "drain client did not establish its WebSocket tunnel" >&2
    exit 1
  fi
  sleep 0.1
done

capture_metrics "$stage_dir/pre-drain-metrics.prom"
python3 - "$stage_dir/pre-drain-metrics.prom" \
  >"$stage_dir/pre-drain-validation.txt" <<'PY'
import sys

metrics = open(sys.argv[1], encoding="utf-8").read()

def total(suffix):
    result = 0.0
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        if name.split("{", 1)[0] == "bonvoyage_bonvoyage_gateway_" + suffix:
            result += float(raw)
    return result

assert total("websocket_handshake_attempts_total") == 18
assert total("websocket_handshake_successes_total") == 7
assert total("websocket_connections_total") == 7
assert total("active_websocket_connections") == 1
assert total("active_route_requests") == 1
assert total("active_upstream_requests") == 1
print("one tunnel held every expected bounded admission gauge before drain")
PY

docker kill --signal=TERM "$gateway" >/dev/null
attempt=0
while [ "$(docker inspect --format '{{.State.Running}}' "$gateway")" = "true" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ]; then
    echo "gateway did not complete coordinated drain within 10 seconds" >&2
    exit 1
  fi
  sleep 0.1
done
wait "$drain_client_pid"
docker inspect --format '{{.State.ExitCode}}' "$gateway" \
  >"$stage_dir/gateway-exit-code.txt"
grep -qx '0' "$stage_dir/gateway-exit-code.txt"

docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1
docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1

python3 - "$stage_dir/upstream.log" \
  >"$stage_dir/upstream-validation.txt" <<'PY'
import json
import sys

records = []
for line in open(sys.argv[1], encoding="utf-8"):
    if line.startswith("REQUEST "):
        records.append(json.loads(line.removeprefix("REQUEST ")))

echo = [record for record in records if record["target"].startswith("/echo?")]
assert len(echo) == 3, echo
assert {record["target"] for record in echo} == {
    "/echo?source=clear",
    "/echo?source=tls",
    "/echo?source=recovery",
}
for record in echo:
    headers = record["headers"]
    assert headers["host"] == "ws.internal.test"
    assert headers["x-route-action"] == "websocket"
    assert headers["x-forwarded-host"] == "api.example.test"
    assert "x-forwarded-for" in headers
    expected_proto = "https" if record["target"].endswith("tls") else "http"
    assert headers["x-forwarded-proto"] == expected_proto
print("controlled upstream observed exact rewrite, transform, identity, and TLS scheme behavior")
PY

source_commit="$(git rev-parse HEAD)"
if [ -z "$(git status --porcelain)" ]; then source_dirty=false; else source_dirty=true; fi
runtime_image_id="$(docker image inspect "$image" --format '{{.Id}}')"
cat >"$stage_dir/metadata.txt" <<EOF
captured_at_utc=$timestamp
run_id=$run_id
source_commit=$source_commit
source_dirty=$source_dirty
host=$(uname -s) $(uname -r) $(uname -m)
platform=$platform
runtime_image=$image
runtime_image_id=$runtime_image_id
gateway_shards=1
protocols=cleartext-http1,tls-http1
websocket_version=13
maximum_tunnel_read_bytes=65536
route_idle_timeout_ms=1000,5000,10000
request_timeout_ms=1200
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<'EOF'
# Phase 3 bounded HTTP/1.1 WebSocket evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway completed RFC 6455 handshakes over cleartext and TLS HTTP/1.1, preserved bytes arriving immediately after each HTTP header boundary, and tunneled text, binary, and close frames without cross-shard ownership. The route retained endpoint selection, cluster admission, route concurrency, trusted forwarding identity, static rewrite, header transformation, TLS verification, idle closure, and fixed-cardinality metrics for the tunnel lifetime.

Malformed client handshakes, duplicate security fields, a non-WebSocket route upgrade, invalid upstream proof/subprotocol/extension/framing, a stalled upstream handshake, and a concurrent tunnel beyond the route limit were all rejected. A valid non-101 upstream response remained an ordinary HTTP response. The process recovered from rejection and idle closure without restart, then terminated an active tunnel and exited cleanly during coordinated drain.

The tunnel is intentionally opaque after a validated handshake. BonVoyage does not parse application frames, enforce message-size policy, terminate negotiated extensions, or support HTTP/2 extended CONNECT in this checkpoint. This run establishes local correctness and bounded resource ownership; it does not qualify dedicated-host throughput, long connection churn/RSS, multi-shard saturation, or publishable feature cost.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
api/gen/go/bonvoyage/v1/config.pb.go
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
control-plane/internal/snapshot/snapshot_test.go
dataplane/CMakeLists.txt
dataplane/include/bonvoyage/http/websocket_protocol.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/gateway.cc
dataplane/src/http1_validation.cc
dataplane/src/runtime_snapshot.cc
dataplane/src/websocket_protocol.cc
dataplane/tests/http1_validation_test.cc
dataplane/tests/runtime_snapshot_test.cc
dataplane/tests/websocket_protocol_test.cc
scripts/phase3-websocket-client.py
scripts/phase3-websocket-smoke.sh
scripts/test-fixture-secrets.sh
scripts/phase3-websocket-upstream.py
tests/fixtures/phase3-websocket.yaml
EOF
while IFS= read -r source_file; do hash_file "$source_file"; done \
  <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md client-results.json \
    compiler.txt drain-client.json gateway-exit-code.txt gateway.inspect.json \
    gateway.log metadata.txt metrics-validation.txt metrics.prom \
    pre-drain-metrics.prom pre-drain-validation.txt \
    runtime-image.inspect.json source-checksums.sha256 upstream.log \
    upstream-validation.txt; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-websocket-smoke.txt.tmp"
mv "$output_root/current-websocket-smoke.txt.tmp" \
  "$output_root/current-websocket-smoke.txt"

printf 'WebSocket integration passed: %s\n' "$output_dir"
cat "$output_dir/client-results.json"
cat "$output_dir/metrics-validation.txt"
cat "$output_dir/pre-drain-validation.txt"
cat "$output_dir/drain-client.json"
cat "$output_dir/upstream-validation.txt"
