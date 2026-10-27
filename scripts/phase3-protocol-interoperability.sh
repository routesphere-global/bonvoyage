#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
grpc_image="${BONVOYAGE_GRPC_FIXTURE_IMAGE:-bonvoyage-grpc-unary-fixture:dev}"
client_image="${BONVOYAGE_INTEROP_CLIENT_IMAGE:-bonvoyage-protocol-interop-client:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
case "$platform" in
  linux/amd64)
    curl_platform_digest="sha256:5a91ea0c9c3ee27b4abe657b68cf6bf0676afa13b236b3bda34283cb3924d4f6"
    ;;
  linux/arm64 | linux/arm64/v8)
    curl_platform_digest="sha256:b949ec80877077def1544f0727d3e3101dd687fe20a5bf74997e557f7e3ac961"
    ;;
  *)
    if [ -z "${BONVOYAGE_CURL_IMAGE:-}" ]; then
      echo "BONVOYAGE_CURL_IMAGE is required for unsupported platform: $platform" >&2
      exit 2
    fi
    curl_platform_digest="override"
    ;;
esac
curl_image="${BONVOYAGE_CURL_IMAGE:-curlimages/curl:8.16.0@$curl_platform_digest}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="protocol-interoperability-$timestamp"
suffix="$$"
network="bonvoyage-protocol-interop-$suffix"
volume="bonvoyage-protocol-interop-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-protocol-interop-gateway-$suffix"
http_upstream="bonvoyage-protocol-interop-http-$suffix"
websocket_upstream="bonvoyage-protocol-interop-websocket-$suffix"
grpc_upstream="bonvoyage-protocol-interop-grpc-$suffix"
probe="bonvoyage-protocol-interop-probe-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-protocol-interop.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_PROTOCOL_INTEROPERABILITY_EVIDENCE_ROOT:-benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"
chmod 755 "$work_dir"

fail() {
  echo "protocol interoperability gate failed: $*" >&2
  exit 1
}

capture_logs() {
  for container_name in "$gateway" "$http_upstream" "$websocket_upstream" \
    "$grpc_upstream" "$probe"; do
    if docker inspect "$container_name" >/dev/null 2>&1; then
      docker logs "$container_name" >"$stage_dir/$container_name.log" 2>&1 \
        || true
    fi
  done
}

cleanup() {
  status="$?"
  capture_logs
  docker rm --force "$gateway" "$http_upstream" "$websocket_upstream" \
    "$grpc_upstream" "$probe" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$work_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  if [ "$status" -eq 0 ]; then
    rm -rf "$work_dir"
    printf '%s\n' "protocol interoperability gate passed: $output_dir"
  else
    echo "temporary interoperability evidence: $stage_dir" >&2
    sed -n '1,240p' "$stage_dir/$gateway.log" >&2 || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

for command_name in date docker git grep mktemp openssl python3 sed sleep uname; do
  command -v "$command_name" >/dev/null 2>&1 \
    || fail "$command_name is required"
done

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

wait_for_http() {
  url="$1"
  expected_status="$2"
  attempt=0
  until docker exec "$probe" python -c '
import sys
import urllib.request
response = urllib.request.urlopen(sys.argv[1], timeout=1)
assert response.status == int(sys.argv[2]), response.status
' "$url" "$expected_status" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 40 ]; then
      fail "endpoint did not become ready: $url"
    fi
    sleep 1
  done
}

run_curl() {
  name="$1"
  protocol_flag="$2"
  url="$3"
  shift 3
  docker run --rm --pull never --platform "$platform" --network "$network" \
    --volume "$work_dir:/secrets:ro" "$curl_image" \
    --silent --show-error --fail-with-body "$protocol_flag" \
    --output /dev/null \
    --write-out '{"http_version":"%{http_version}","response_code":%{response_code},"remote_ip":"%{remote_ip}","size_download":%{size_download},"ssl_verify_result":%{ssl_verify_result}}\n' \
    "$@" "$url" >"$stage_dir/$name.json"
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage Protocol Interoperability Test CA" \
  -keyout "$work_dir/ca-key.pem" -out "$work_dir/ca.pem" >/dev/null 2>&1
cp "$work_dir/ca.pem" "$work_dir/upstream-ca.pem"

openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=api-http2.example.test" \
  -keyout "$work_dir/server-key.pem" -out "$work_dir/server.csr" \
  >/dev/null 2>&1
printf '%s\n' \
  "subjectAltName=DNS:api-http1.example.test,DNS:api-http2.example.test" \
  "extendedKeyUsage=serverAuth" \
  "keyUsage=digitalSignature,keyEncipherment" >"$work_dir/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work_dir/server.csr" \
  -CA "$work_dir/ca.pem" -CAkey "$work_dir/ca-key.pem" -CAcreateserial \
  -extfile "$work_dir/server-ext.cnf" -out "$work_dir/server-chain.pem" \
  >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=upstream-grpc.example.test" \
  -keyout "$work_dir/upstream-key.pem" -out "$work_dir/upstream.csr" \
  >/dev/null 2>&1
printf '%s\n' \
  "subjectAltName=DNS:upstream-grpc.example.test" \
  "extendedKeyUsage=serverAuth" \
  "keyUsage=digitalSignature,keyEncipherment" >"$work_dir/upstream-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work_dir/upstream.csr" \
  -CA "$work_dir/ca.pem" -CAkey "$work_dir/ca-key.pem" -CAcreateserial \
  -extfile "$work_dir/upstream-ext.cnf" -out "$work_dir/upstream-chain.pem" \
  >/dev/null 2>&1
chmod 600 "$work_dir"/*-key.pem
chmod 644 "$work_dir/ca.pem" "$work_dir/upstream-ca.pem" \
  "$work_dir/server-chain.pem" "$work_dir/upstream-chain.pem"

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker buildx build --platform "$platform" --load --tag "$grpc_image" \
  --file tests/fixtures/grpc-unary/Dockerfile tests/fixtures/grpc-unary
docker buildx build --platform "$platform" --load --tag "$client_image" \
  --file tests/fixtures/protocol-interoperability/Dockerfile \
  tests/fixtures/protocol-interoperability

if ! docker image inspect "$curl_image" >/dev/null 2>&1; then
  docker pull --platform "$platform" "$curl_image"
fi

docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null

bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem upstream-ca.pem

docker run --rm --platform "$platform" \
  --volume "$repo_root/tests/fixtures/phase3-protocol-interoperability.yaml:/etc/bonvoyage/interoperability.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" "$compiler_image" \
  -input /etc/bonvoyage/interoperability.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$http_upstream" \
  --network "$network" --network-alias http-upstream \
  "$upstream_image" >/dev/null
docker run --detach --platform "$platform" --name "$websocket_upstream" \
  --network "$network" --network-alias websocket-upstream \
  --entrypoint python \
  --volume "$repo_root/scripts/phase3-websocket-upstream.py:/websocket-upstream.py:ro" \
  "$upstream_image" /websocket-upstream.py >/dev/null
docker run --detach --platform "$platform" --name "$grpc_upstream" \
  --network "$network" --network-alias upstream-grpc.example.test \
  --volume "$work_dir:/secrets:ro" "$grpc_image" server \
  --certificate /secrets/upstream-chain.pem \
  --key /secrets/upstream-key.pem >/dev/null
docker run --detach --platform "$platform" --name "$probe" \
  --network "$network" "$upstream_image" >/dev/null

wait_for_http "http://$http_upstream:8081/healthz" 200
wait_for_http "http://$websocket_upstream:8081/healthz" 200
wait_for_http "http://$grpc_upstream:8081/healthz" 204

docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api-http1.example.test \
  --network-alias api-http2.example.test \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$image" \
  --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 512M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug >/dev/null

bv_wait_gateway_ready "$gateway" "$probe" "http://$gateway:9901/health/ready"
gateway_pid_before="$(docker inspect --format '{{.State.Pid}}' "$gateway")"

docker run --rm --pull never --platform "$platform" --network none \
  "$curl_image" --version >"$stage_dir/curl-version.txt"
docker run --rm --platform "$platform" --network none \
  "$client_image" versions >"$stage_dir/python-client-versions.json"

run_curl curl-http1-clear --http1.1 \
  http://api-http1.example.test:8080/payload/256
run_curl curl-http1-tls --http1.1 \
  https://api-http1.example.test:9443/payload/256 \
  --cacert /secrets/ca.pem
run_curl curl-http2-tls --http2 \
  https://api-http2.example.test:8443/payload/256 \
  --cacert /secrets/ca.pem

set +e
docker run --rm --pull never --platform "$platform" --network "$network" \
  --volume "$work_dir:/secrets:ro" "$curl_image" \
  --silent --show-error --http2 --cacert /secrets/ca.pem \
  --connect-to wrong.example.test:8443:api-http2.example.test:8443 \
  https://wrong.example.test:8443/ready \
  >"$stage_dir/curl-wrong-host.stdout.txt" \
  2>"$stage_dir/curl-wrong-host.stderr.txt"
curl_tls_status="$?"
set -e
printf '%s\n' "$curl_tls_status" >"$stage_dir/curl-wrong-host-exit-status.txt"
test "$curl_tls_status" -eq 60 \
  || fail "curl did not reject the wrong certificate hostname with exit 60"

docker run --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/secrets:ro" "$grpc_image" client \
  --target api-http2.example.test:8443 --ca /secrets/ca.pem \
  --server-name api-http2.example.test --case success \
  >"$stage_dir/grpc-go-success.json"
docker run --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/secrets:ro" "$client_image" grpc \
  --target api-http2.example.test:8443 --ca /secrets/ca.pem \
  --server-name api-http2.example.test >"$stage_dir/grpc-python.json"
docker run --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/secrets:ro" "$client_image" grpc-tls-negative \
  --target api-http2.example.test:8443 --ca /secrets/ca.pem \
  >"$stage_dir/grpc-python-wrong-host.json"
docker run --rm --platform "$platform" --network "$network" \
  "$client_image" websocket \
  --uri ws://api-http1.example.test:8080/socket \
  >"$stage_dir/websockets-clear.json"
docker run --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/secrets:ro" "$client_image" websocket \
  --uri wss://api-http1.example.test:9443/socket --ca /secrets/ca.pem \
  >"$stage_dir/websockets-tls.json"

sleep 1
docker exec "$probe" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-protocol-interop-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/metrics.prom"
docker exec "$probe" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-protocol-interop-grpc-'"$suffix"':8081/observations",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/grpc-upstream-observations.json"

python3 - "$stage_dir" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

def load(name):
    with (root / name).open(encoding="utf-8") as source:
        return json.load(source)

expected_curl = {
    "curl-http1-clear.json": "1.1",
    "curl-http1-tls.json": "1.1",
    "curl-http2-tls.json": "2",
}
for name, protocol in expected_curl.items():
    result = load(name)
    assert result["response_code"] == 200, (name, result)
    assert result["http_version"] == protocol, (name, result)
    assert result["size_download"] == 256, (name, result)
    assert result["ssl_verify_result"] == 0, (name, result)

grpc_python = load("grpc-python.json")
assert grpc_python["success_payload"] == "echo:python", grpc_python
assert grpc_python["application_error"] == "INVALID_ARGUMENT", grpc_python
assert grpc_python["large_response_bytes"] == 131072, grpc_python
assert grpc_python["recovery"] == "passed", grpc_python
assert load("grpc-go-success.json")["case"] == "success"
assert load("grpc-python-wrong-host.json")["result"] == (
    "expected hostname rejection"
)

for name, transport in (
    ("websockets-clear.json", "cleartext"),
    ("websockets-tls.json", "tls"),
):
    result = load(name)
    assert result["transport"] == transport, (name, result)
    assert result["subprotocol"] == "chat", (name, result)
    assert result["ping_pong"] == "passed", (name, result)
    assert result["text_echo"] == "python-text", (name, result)

metrics = (root / "metrics.prom").read_text(encoding="utf-8")

def total(suffix):
    result = 0.0
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        if name.split("{", 1)[0] == "bonvoyage_bonvoyage_gateway_" + suffix:
            result += float(raw)
    return result

minimums = {
    "requests_total": 10,
    "http2_streams_total": 6,
    "grpc_requests_total": 5,
    "grpc_successes_total": 4,
    "websocket_connections_total": 2,
}
for name, minimum in minimums.items():
    actual = total(name)
    assert actual >= minimum, (name, actual, minimum)
assert total("grpc_application_errors_total") == 1
for name in (
    "active_connections",
    "active_http2_connections",
    "active_http2_streams",
    "active_route_requests",
    "active_upstream_requests",
    "active_upstream_http2_streams",
    "active_websocket_connections",
):
    assert total(name) == 0, (name, total(name))

observations = load("grpc-upstream-observations.json")
assert observations["requests"] >= 5, observations
assert observations["active"] == 0, observations

summary = {
    "classification": "local engineering evidence",
    "clients": {
        "grpc_go": "passed",
        "grpc_python": "passed",
        "libcurl_http1_clear": "passed",
        "libcurl_http1_tls": "passed",
        "libcurl_http2_tls": "passed",
        "python_websockets_clear": "passed",
        "python_websockets_tls": "passed",
    },
    "final_active_gauges": "zero",
    "hostname_negative_tests": {
        "curl": "passed",
        "grpc_python": "passed",
    },
    "marketing_use_authorized": False,
    "publishable": False,
    "result": "PASS",
}
(root / "summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

gateway_pid_after="$(docker inspect --format '{{.State.Pid}}' "$gateway")"
test "$gateway_pid_before" = "$gateway_pid_after" \
  || fail "gateway process changed during interoperability recovery"

docker stop --signal TERM --time 20 "$gateway" >/dev/null
gateway_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
test "$gateway_exit_code" -eq 0 || fail "gateway did not stop cleanly"
capture_logs
if grep -Eiq 'AddressSanitizer|UndefinedBehaviorSanitizer|Segmentation fault|assertion failed|terminate called|stack overflow' \
  "$stage_dir/$gateway.log" "$stage_dir/$http_upstream.log" \
  "$stage_dir/$websocket_upstream.log" "$stage_dir/$grpc_upstream.log"; then
  fail "runtime failure signature found in interoperability logs"
fi

for inspected_image in "$image" "$compiler_image" "$upstream_image" \
  "$grpc_image" "$client_image" "$curl_image"; do
  safe_name="$(printf '%s' "$inspected_image" | sed 's/[^A-Za-z0-9_.-]/_/g')"
  docker image inspect "$inspected_image" \
    >"$stage_dir/image-$safe_name.inspect.json"
done
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker inspect "$http_upstream" >"$stage_dir/http-upstream.inspect.json"
docker inspect "$websocket_upstream" \
  >"$stage_dir/websocket-upstream.inspect.json"
docker inspect "$grpc_upstream" >"$stage_dir/grpc-upstream.inspect.json"
docker version >"$stage_dir/docker-version.txt"

source_commit="$(git rev-parse HEAD)"
if [ -z "$(git status --porcelain)" ]; then
  source_dirty=false
else
  source_dirty=true
fi
cat >"$stage_dir/metadata.txt" <<EOF
captured_at_utc=$timestamp
run_id=$run_id
source_commit=$source_commit
source_dirty=$source_dirty
host=$(uname -s) $(uname -r) $(uname -m)
platform=$platform
gateway_shards=1
curl_image=$curl_image
curl_image_id=$(docker image inspect "$curl_image" --format '{{.Id}}')
python_client_image=$client_image
python_client_image_id=$(docker image inspect "$client_image" --format '{{.Id}}')
protocols=http1-clear,http1-tls,http2-tls,grpc-unary-tls,websocket-clear,websocket-tls
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
deploy/docker/bonvoyage/Dockerfile
deploy/docker/control-plane/Dockerfile
deploy/docker/upstream/Dockerfile
scripts/phase3-protocol-interoperability.sh
scripts/test-fixture-secrets.sh
scripts/phase3-websocket-upstream.py
tests/fixtures/grpc-unary/Dockerfile
tests/fixtures/grpc-unary/go.mod
tests/fixtures/grpc-unary/go.sum
tests/fixtures/grpc-unary/main.go
tests/fixtures/phase3-protocol-interoperability.yaml
tests/fixtures/protocol-interoperability/Dockerfile
tests/fixtures/protocol-interoperability/client.py
tests/fixtures/protocol-interoperability/requirements.txt
EOF
while IFS= read -r source_file; do
  hash_file "$source_file"
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"

cat >"$stage_dir/README.md" <<'EOF'
# Phase 3 protocol interoperability evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, competitive, customer-facing, billing, or production-readiness claims.

One unchanged single-shard BonVoyage process passed a bounded client matrix across cleartext HTTP/1.1, CA-verified TLS HTTP/1.1, CA-verified TLS HTTP/2, unary gRPC, and RFC 6455 WebSocket routes. The independent clients were pinned libcurl, gRPC Python, and Python websockets; the existing grpc-go client provided the second gRPC SDK result. Both TLS stacks rejected a wrong hostname, client and server metadata survived gRPC proxying, WebSocket text/binary/ping/subprotocol behavior passed over cleartext and TLS, recovery required no restart, final active gauges were zero, and SIGTERM exited zero.

The complete machine-readable outcome is in `summary.json`. Raw client outputs, versions, upstream observations, metrics, container and image inspection, logs, Git state, source checksums, and evidence checksums are retained alongside it.

This checkpoint does not qualify streaming gRPC, gRPC-Web, HTTP/2 extended CONNECT, browser/CDN behavior, external proxy chains, third-party upstream servers, multi-hour stability, dedicated-host cost, saturation, or publishable performance.
EOF

mkdir -p "$output_dir"
cp -R "$stage_dir"/. "$output_dir"/
checksum_manifest="$work_dir/checksums.sha256"
(
  cd "$output_dir"
  find . -type f ! -name checksums.sha256 -print | LC_ALL=C sort | \
    while IFS= read -r evidence_file; do
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$evidence_file"
      else
        shasum -a 256 "$evidence_file"
      fi
    done >"$checksum_manifest"
)
mv "$checksum_manifest" "$output_dir/checksums.sha256"
printf '%s\n' "$run_id" \
  >"$output_root/current-protocol-interoperability.txt"

trap - EXIT INT TERM
cleanup
