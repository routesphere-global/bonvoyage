#!/bin/sh
set -eu

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
http1_upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
http2_upstream_image="${BONVOYAGE_HTTP2_UPSTREAM_IMAGE:-bonvoyage-upstream-http2:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="upstream-http2-live-$timestamp"
suffix="$$"
network="bonvoyage-upstream-http2-$suffix"
volume="bonvoyage-upstream-http2-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-upstream-http2-gateway-$suffix"
http1_upstream="bonvoyage-upstream-http1-alpn-$suffix"
http2_upstream="bonvoyage-upstream-http2-server-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-upstream-http2.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_UPSTREAM_HTTP2_EVIDENCE_ROOT:-benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"

cleanup() {
  status="$?"
  if docker inspect "$gateway" >/dev/null 2>&1; then
    docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1 || true
  fi
  if docker inspect "$http2_upstream" >/dev/null 2>&1; then
    docker logs "$http2_upstream" >"$stage_dir/upstream-http2.log" 2>&1 || true
  fi
  if docker inspect "$http1_upstream" >/dev/null 2>&1; then
    docker logs "$http1_upstream" >"$stage_dir/upstream-http1.log" 2>&1 || true
  fi
  docker rm --force "$gateway" "$http1_upstream" "$http2_upstream" \
    >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$work_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  if [ "$status" -eq 0 ]; then
    rm -rf "$work_dir"
  else
    echo "upstream HTTP/2 smoke failed; temporary evidence: $stage_dir" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

for command_name in date docker git mktemp openssl uname; do
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

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage Live Upstream HTTP2 Test CA" \
  -keyout "$work_dir/ca-key.pem" -out "$work_dir/ca.pem" >/dev/null 2>&1
cp "$work_dir/ca.pem" "$work_dir/upstream-ca.pem"

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

openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=upstream-h2.example.test" \
  -keyout "$work_dir/upstream-key.pem" -out "$work_dir/upstream.csr" \
  >/dev/null 2>&1
printf '%s\n' \
  "subjectAltName=DNS:upstream-h2.example.test,DNS:upstream-h1.example.test" \
  "extendedKeyUsage=serverAuth" \
  "keyUsage=digitalSignature,keyEncipherment" >"$work_dir/upstream-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work_dir/upstream.csr" \
  -CA "$work_dir/ca.pem" -CAkey "$work_dir/ca-key.pem" -CAcreateserial \
  -extfile "$work_dir/upstream-ext.cnf" -out "$work_dir/upstream-chain.pem" \
  >/dev/null 2>&1
chmod 600 "$work_dir"/*-key.pem
dd if=/dev/zero bs=131072 count=1 2>/dev/null | tr '\000' x \
  >"$work_dir/request-body.bin"

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$http1_upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker buildx build --platform "$platform" --load --tag "$http2_upstream_image" \
  --file tests/fixtures/upstream-http2/Dockerfile \
  tests/fixtures/upstream-http2
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$http1_upstream_image" "$platform" \
  server-chain.pem server-key.pem upstream-ca.pem

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-upstream-http2.yaml:/etc/bonvoyage/upstream-http2.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/upstream-http2.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$http2_upstream" \
  --network "$network" --network-alias upstream-h2.example.test \
  --volume "$work_dir:/tls:ro" \
  --env BONVOYAGE_UPSTREAM_TLS_CERTIFICATE=/tls/upstream-chain.pem \
  --env BONVOYAGE_UPSTREAM_TLS_PRIVATE_KEY=/tls/upstream-key.pem \
  "$http2_upstream_image" >/dev/null
docker run --detach --platform "$platform" --name "$http1_upstream" \
  --network "$network" --network-alias upstream-h1.example.test \
  --volume "$work_dir:/tls:ro" \
  --env BONVOYAGE_UPSTREAM_TLS_CERTIFICATE=/tls/upstream-chain.pem \
  --env BONVOYAGE_UPSTREAM_TLS_PRIVATE_KEY=/tls/upstream-key.pem \
  "$http1_upstream_image" >/dev/null
docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test \
  --network-alias wrong-alpn.example.test \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$image" \
  --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 320M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug >/dev/null

bv_wait_gateway_ready "$gateway" "$http1_upstream" "http://$gateway:9901/health/ready"

docker exec "$http1_upstream" python -c '
import http.client
import json

gateway = "bonvoyage-upstream-http2-gateway-'"$suffix"'"

def request(path, method="GET", body=None, host="api.example.test"):
    connection = http.client.HTTPConnection(gateway, 8080, timeout=15)
    connection.request(method, path, body=body, headers={"Host": host})
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    return response.status, payload

status, body = request("/protocol")
details = json.loads(body)
assert status == 200, (status, body)
assert details == {"alpn": "h2", "protocol": "HTTP/2.0"}, details

payload = b"request-stream-" * 8192
status, body = request("/echo", method="POST", body=payload)
assert status == 200 and body == payload, (status, len(body))

status, body = request("/stream/131072")
assert status == 200 and body == b"x" * 131072, (status, len(body))

status, body = request("/trailers")
assert status == 200 and body == b"trailer-body\n", (status, body)

status, body = request(
    "/healthz", host="wrong-alpn.example.test"
)
assert status == 502 and b"upstream_failure" in body, (status, body)
' >"$stage_dir/http1-functional.txt"

docker exec "$http1_upstream" python -c '
import http.client
import socket
import time

gateway = "bonvoyage-upstream-http2-gateway-'"$suffix"'"
connection = socket.create_connection((gateway, 8080), timeout=5)
connection.sendall(
    b"POST /echo HTTP/1.1\r\n"
    b"Host: api.example.test\r\n"
    b"Content-Length: 1048576\r\n"
    b"Connection: close\r\n\r\n"
    b"deliberately-truncated-request-body"
)
time.sleep(0.1)
connection.close()

for attempt in range(20):
    try:
        healthy = http.client.HTTPConnection(gateway, 8080, timeout=2)
        healthy.request("GET", "/healthz", headers={"Host": "api.example.test"})
        response = healthy.getresponse()
        body = response.read()
        healthy.close()
        assert response.status == 200 and body == b"ok\n", (
            response.status,
            body,
        )
        print(f"pool_recovered_after_attempts={attempt}")
        break
    except (AssertionError, OSError):
        if attempt == 19:
            raise
        time.sleep(0.1)
' >"$stage_dir/cancellation-recovery.txt"

docker run --rm --platform "$platform" --network "$network" "$oha_image" \
  -n 48 -c 16 --no-tui --output-format json \
  --http-version 1.1 --disable-compression \
  http://api.example.test:8080/slow/100 \
  >"$stage_dir/multiplexing.oha.json"

docker exec "$http1_upstream" python -c '
import urllib.request
request = urllib.request.Request(
    "http://bonvoyage-upstream-http2-gateway-'"$suffix"':8080/stats",
    headers={"Host": "api.example.test"},
)
with urllib.request.urlopen(request, timeout=10) as response:
    print(response.read().decode(), end="")
' >"$stage_dir/upstream-observations.json"

docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  -n 12 -c 2 -p 4 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/stream/131072 \
  >"$stage_dir/http2-response.oha.json"
docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  -n 8 -c 2 -p 2 -m POST -D /tls/request-body.bin \
  -T application/octet-stream --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/echo \
  >"$stage_dir/http2-request.oha.json"

docker exec "$http1_upstream" python -c '
import json

for path in (
    "/tls/evidence/multiplexing.oha.json",
    "/tls/evidence/http2-response.oha.json",
    "/tls/evidence/http2-request.oha.json",
):
    with open(path, encoding="utf-8") as source:
        result = json.load(source)
    assert result["summary"]["successRate"] == 1, (path, result)
    assert result["summary"]["requestsPerSec"] > 0, (path, result)

with open("/tls/evidence/upstream-observations.json", encoding="utf-8") as source:
    observations = json.load(source)
assert observations["unique_connections"] == 1, observations
assert observations["maximum_concurrent"] >= 2, observations
print(json.dumps(observations, sort_keys=True))
' >"$stage_dir/functional-validation.txt"

docker exec "$http1_upstream" python -c '
import http.client
connection = http.client.HTTPConnection(
    "bonvoyage-upstream-http2-gateway-'"$suffix"'", 8080, timeout=10
)
connection.request("GET", "/shutdown", headers={"Host": "api.example.test"})
response = connection.getresponse()
body = response.read()
connection.close()
assert response.status == 200 and body == b"draining\n", (response.status, body)
' >"$stage_dir/goaway-trigger.txt"

attempt=0
while [ "$(docker inspect --format '{{.State.Running}}' "$http2_upstream")" = true ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 50 ]; then
    echo "controlled HTTP/2 upstream did not finish graceful drain" >&2
    exit 1
  fi
  sleep 0.1
done
docker start "$http2_upstream" >/dev/null

attempt=0
until docker exec "$http1_upstream" python -c '
import http.client
connection = http.client.HTTPConnection(
    "bonvoyage-upstream-http2-gateway-'"$suffix"'", 8080, timeout=2
)
connection.request("GET", "/healthz", headers={"Host": "api.example.test"})
response = connection.getresponse()
body = response.read()
connection.close()
assert response.status == 200 and body == b"ok\n", (response.status, body)
' >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 40 ]; then
    echo "BonVoyage did not recover its upstream HTTP/2 pool" >&2
    exit 1
  fi
  sleep 0.25
done
printf 'recovered_after_attempts=%s\n' "$attempt" \
  >"$stage_dir/recovery-validation.txt"

docker exec "$http1_upstream" python -c '
import urllib.request
metrics = urllib.request.urlopen(
    "http://bonvoyage-upstream-http2-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode()
print(metrics, end="")
' >"$stage_dir/metrics.prom"

docker exec "$http1_upstream" python -c '
metrics = open("/tls/evidence/metrics.prom", encoding="utf-8").read()

def total(name):
    return sum(
        float(line.split()[-1])
        for line in metrics.splitlines()
        if line.startswith(name + "{") or line.startswith(name + " ")
    )

prefix = "bonvoyage_bonvoyage_gateway_"
assert total(prefix + "upstream_http2_connections_total") >= 2
assert total(prefix + "upstream_http2_connection_failures_total") >= 1
assert total(prefix + "upstream_http2_streams_total") >= 70
assert total(prefix + "upstream_http2_goaways_total") >= 1
assert total(prefix + "upstream_http2_response_trailers_total") >= 1
assert total(prefix + "upstream_http2_stream_delimited_responses_total") >= 13
assert total(prefix + "upstream_response_trailers_dropped_total") >= 1
assert total(prefix + "upstream_tls_handshake_failures_total") >= 1
assert total(prefix + "active_health_successes_total") >= 1
assert prefix + "active_upstream_http2_connections" in metrics
assert prefix + "active_upstream_http2_streams" in metrics
print("live upstream HTTP/2 metrics validated")
' >"$stage_dir/metrics-validation.txt"

docker stop --signal TERM --time 20 "$gateway" >/dev/null
exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
test "$exit_code" -eq 0
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1 || true
docker logs "$http2_upstream" >"$stage_dir/upstream-http2.log" 2>&1 || true
docker logs "$http1_upstream" >"$stage_dir/upstream-http1.log" 2>&1 || true
docker image inspect "$image" >"$stage_dir/dataplane-image-inspect.json"
docker image inspect "$compiler_image" >"$stage_dir/compiler-image-inspect.json"
docker image inspect "$http1_upstream_image" \
  >"$stage_dir/http1-upstream-image-inspect.json"
docker image inspect "$http2_upstream_image" \
  >"$stage_dir/http2-upstream-image-inspect.json"
docker image inspect "$oha_image" >"$stage_dir/load-generator-image-inspect.json"
docker version >"$stage_dir/docker-version.txt"

git_commit="$(git rev-parse HEAD)"
git status --short >"$stage_dir/git-status.txt"
if [ ! -s "$stage_dir/git-status.txt" ]; then
  source_dirty=false
else
  source_dirty=true
fi
dataplane_image_id="$(docker image inspect --format '{{.Id}}' "$image")"
compiler_image_id="$(docker image inspect --format '{{.Id}}' "$compiler_image")"
http2_fixture_image_id="$(docker image inspect --format '{{.Id}}' "$http2_upstream_image")"
cat >"$stage_dir/metadata.txt" <<EOF
run_id=$run_id
timestamp_utc=$timestamp
git_commit=$git_commit
source_dirty=$source_dirty
platform=$platform
host_kernel=$(uname -sr)
dataplane_image=$image
dataplane_image_id=$dataplane_image_id
compiler_image=$compiler_image
compiler_image_id=$compiler_image_id
http2_fixture_image=$http2_upstream_image
http2_fixture_image_id=$http2_fixture_image_id
scope=live TLS upstream HTTP/2 functional integration
publishable_benchmark=false
EOF

for input in \
  Makefile \
  dataplane/CMakeLists.txt \
  dataplane/include/bonvoyage/runtime/upstream_http2_client.hh \
  dataplane/src/gateway.cc \
  dataplane/src/runtime_snapshot.cc \
  dataplane/src/upstream_http2_client.cc \
  deploy/docker/bonvoyage/Dockerfile \
  scripts/phase3-upstream-http2-smoke.sh \
  scripts/test-fixture-secrets.sh \
  tests/fixtures/phase3-upstream-http2.yaml \
  tests/fixtures/upstream-http2/Dockerfile \
  tests/fixtures/upstream-http2/main.go; do
  hash_file "$input"
done >"$stage_dir/input-checksums.txt"
printf 'outcome=PASS\ngateway_exit_code=%s\n' "$exit_code" \
  >"$stage_dir/run-status.env"

mkdir -p "$output_dir"
for artifact in \
  cancellation-recovery.txt compiler-image-inspect.json compiler.txt \
  dataplane-image-inspect.json docker-version.txt functional-validation.txt \
  gateway.log git-status.txt goaway-trigger.txt \
  http1-upstream-image-inspect.json http2-upstream-image-inspect.json \
  http1-functional.txt http2-request.oha.json http2-response.oha.json \
  input-checksums.txt load-generator-image-inspect.json metadata.txt \
  metrics-validation.txt metrics.prom multiplexing.oha.json \
  recovery-validation.txt run-status.env upstream-http1.log \
  upstream-http2.log upstream-observations.json; do
  if [ -f "$stage_dir/$artifact" ]; then
    cp "$stage_dir/$artifact" "$output_dir/$artifact"
  fi
done

echo "BonVoyage live upstream HTTP/2 integration smoke passed"
echo "Evidence: $output_dir"
