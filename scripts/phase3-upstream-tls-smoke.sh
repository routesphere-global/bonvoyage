#!/bin/sh
set -eu

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
suffix="$$"
network="bonvoyage-upstream-tls-$suffix"
volume="bonvoyage-upstream-tls-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-upstream-tls-gateway-$suffix"
tls_upstream="bonvoyage-tls-upstream-$suffix"
mtls_upstream="bonvoyage-mtls-upstream-$suffix"
stall_upstream="bonvoyage-stall-upstream-$suffix"
invalid_gateway="bonvoyage-invalid-upstream-tls-$suffix"
tls_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-upstream-tls.XXXXXX")"

cleanup() {
  status="$?"
  if [ "$status" -ne 0 ] && docker inspect "$gateway" >/dev/null 2>&1; then
    echo "BonVoyage gateway logs after upstream TLS smoke failure:" >&2
    docker logs "$gateway" >&2 || true
  fi
  if [ "$status" -ne 0 ] && docker inspect "$tls_upstream" >/dev/null 2>&1; then
    echo "Controlled TLS upstream logs:" >&2
    docker logs "$tls_upstream" >&2 || true
  fi
  if [ "$status" -ne 0 ] && docker inspect "$mtls_upstream" >/dev/null 2>&1; then
    echo "Controlled mTLS upstream logs:" >&2
    docker logs "$mtls_upstream" >&2 || true
  fi
  docker rm --force "$gateway" "$tls_upstream" "$mtls_upstream" \
    "$stall_upstream" \
    "$invalid_gateway" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$tls_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  rm -rf "$tls_dir"
  exit "$status"
}
trap cleanup EXIT INT TERM

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required for the ephemeral upstream TLS fixtures" >&2
  exit 1
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage Upstream Test CA" \
  -keyout "$tls_dir/ca-key.pem" -out "$tls_dir/upstream-ca.pem" \
  >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=upstream-tls.example.test" \
  -keyout "$tls_dir/upstream-key.pem" -out "$tls_dir/upstream.csr" \
  >/dev/null 2>&1
printf '%s\n' \
  "subjectAltName=DNS:upstream-tls.example.test,DNS:upstream-mtls.example.test" \
  "extendedKeyUsage=serverAuth" \
  "keyUsage=digitalSignature,keyEncipherment" >"$tls_dir/upstream-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$tls_dir/upstream.csr" \
  -CA "$tls_dir/upstream-ca.pem" -CAkey "$tls_dir/ca-key.pem" \
  -CAcreateserial -extfile "$tls_dir/upstream-ext.cnf" \
  -out "$tls_dir/upstream-chain.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=bonvoyage-gateway" \
  -keyout "$tls_dir/gateway-client-key.pem" \
  -out "$tls_dir/gateway-client.csr" >/dev/null 2>&1
printf '%s\n' \
  "extendedKeyUsage=clientAuth" \
  "keyUsage=digitalSignature" >"$tls_dir/gateway-client-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$tls_dir/gateway-client.csr" \
  -CA "$tls_dir/upstream-ca.pem" -CAkey "$tls_dir/ca-key.pem" \
  -CAcreateserial -extfile "$tls_dir/gateway-client-ext.cnf" \
  -out "$tls_dir/gateway-client.pem" >/dev/null 2>&1
chmod 600 "$tls_dir"/*-key.pem

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$tls_dir" "$upstream_image" "$platform" \
  upstream-ca.pem gateway-client.pem gateway-client-key.pem

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-upstream-tls.yaml:/etc/bonvoyage/upstream-tls.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/upstream-tls.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >/dev/null

docker run --detach --platform "$platform" --name "$tls_upstream" \
  --network "$network" --network-alias upstream-tls.example.test \
  --volume "$tls_dir:/tls:ro" \
  --env BONVOYAGE_UPSTREAM_TLS_CERTIFICATE=/tls/upstream-chain.pem \
  --env BONVOYAGE_UPSTREAM_TLS_PRIVATE_KEY=/tls/upstream-key.pem \
  "$upstream_image" >/dev/null
docker run --detach --platform "$platform" --name "$mtls_upstream" \
  --network "$network" --network-alias upstream-mtls.example.test \
  --volume "$tls_dir:/tls:ro" \
  --env BONVOYAGE_UPSTREAM_TLS_CERTIFICATE=/tls/upstream-chain.pem \
  --env BONVOYAGE_UPSTREAM_TLS_PRIVATE_KEY=/tls/upstream-key.pem \
  --env BONVOYAGE_UPSTREAM_TLS_CLIENT_CA=/tls/upstream-ca.pem \
  "$upstream_image" >/dev/null
docker run --detach --platform "$platform" --name "$stall_upstream" \
  --network "$network" --network-alias upstream-stall.example.test \
  --entrypoint python "$upstream_image" -c '
import socket
import time
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 8081))
server.listen()
while True:
    connection, _ = server.accept()
    time.sleep(10)
    connection.close()
' >/dev/null
docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias gateway \
  --network-alias tls.client.example.test \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$image" \
  --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 256M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug >/dev/null

bv_wait_gateway_ready "$gateway" "$tls_upstream" "http://gateway:9901/health/ready"

docker exec "$tls_upstream" python -c '
import http.client
import json
import time

def request(host, path):
    connection = http.client.HTTPConnection("gateway", 8080, timeout=10)
    connection.request("GET", path, headers={"Host": host})
    response = connection.getresponse()
    body = response.read()
    connection.close()
    return response.status, body

status, body = request("tls.client.example.test", "/payload/256")
assert status == 200 and body == b"x" * 256, (status, body)
status, body = request("tls.client.example.test", "/tls-info")
details = json.loads(body)
assert status == 200, (status, body)
assert details["tls_version"] in ("TLSv1.2", "TLSv1.3"), details
assert details["alpn"] == "http/1.1", details
assert details["client_certificate"] is False, details

status, body = request("mtls.client.example.test", "/tls-info")
details = json.loads(body)
assert status == 200, (status, body)
assert details["tls_version"] in ("TLSv1.2", "TLSv1.3"), details
assert details["alpn"] == "http/1.1", details
assert details["client_certificate"] is True, details

status, body = request("wrong-name.client.example.test", "/payload/16")
assert status == 502 and b"upstream_failure" in body, (status, body)
status, body = request("missing-client.client.example.test", "/payload/16")
assert status == 502 and b"upstream_failure" in body, (status, body)
started = time.monotonic()
status, body = request("timeout.client.example.test", "/payload/16")
elapsed = time.monotonic() - started
assert status == 504 and b"upstream_connect_timeout" in body, (status, body)
assert elapsed < 3.0, elapsed
print(f"Stalled upstream TLS handshake: status={status} elapsed={elapsed:.3f}s")
status, body = request("tls.client.example.test", "/payload/16")
assert status == 200 and body == b"x" * 16, (status, body)

# A delayed overrun sent in a later TLS record must not become the response to
# the next downstream request. The default retires each upstream HTTP/1
# connection, even when a peer advertises keep-alive.
cases = (
    ("/response-overrun-delayed/bodyless", 204, b""),
    ("/response-overrun-delayed/content-length", 200, b"ok"),
    ("/response-overrun-delayed/chunked", 200, b"ok"),
)
for path, expected_status, expected_body in cases:
    connection = http.client.HTTPConnection("gateway", 8080, timeout=10)
    connection.request("GET", path, headers={"Host": "tls.client.example.test"})
    response = connection.getresponse()
    assert response.status == expected_status, (path, response.status)
    assert response.read() == expected_body, path
    first_upstream = response.getheader("x-upstream-connection")
    assert first_upstream, path
    connection.request(
        "GET", "/healthz", headers={"Host": "tls.client.example.test"}
    )
    recovered = connection.getresponse()
    assert recovered.status == 200, (path, recovered.status)
    assert recovered.read() == b"ok\n", path
    assert recovered.getheader("x-bonvoyage-forged") is None, path
    assert recovered.getheader("x-upstream-connection") != first_upstream, path
    connection.close()
'

docker exec "$tls_upstream" python -c '
import urllib.request

metrics = urllib.request.urlopen(
    "http://gateway:9090/metrics", timeout=10
).read().decode()

def total(name):
    return sum(
        float(line.split()[-1])
        for line in metrics.splitlines()
        if line.startswith(name + "{") or line.startswith(name + " ")
    )

prefix = "bonvoyage_bonvoyage_gateway_"
assert total(prefix + "upstream_tls_handshakes_total") >= 2
assert total(prefix + "upstream_tls_handshake_failures_total") >= 2
assert total(prefix + "upstream_tls_handshake_timeouts_total") >= 1
assert prefix + "active_upstream_tls_handshakes" in metrics
'

# Functional load confirms that repeated single-use upstream TLS connections
# stay healthy under concurrency. This is not retained or publishable benchmark
# evidence and does not quantify the secure default's handshake cost.
docker run --rm --platform "$platform" --network "$network" "$oha_image" \
  -z 5s -c 32 --no-tui --output-format json \
  --http-version 1.1 --disable-compression \
  http://tls.client.example.test:8080/payload/256 \
  >"$tls_dir/upstream-tls.oha.json"
docker exec "$tls_upstream" python -c '
import json
with open("/tls/upstream-tls.oha.json", encoding="utf-8") as source:
    result = json.load(source)
assert result["summary"]["requestsPerSec"] > 0
assert result["summary"]["successRate"] == 1
'

printf '%s\n' "not a certificate" >"$tls_dir/upstream-ca.pem"
bv_stage_fixture_secrets --refresh "$secret_volume" "$tls_dir" "$upstream_image" "$platform" \
  upstream-ca.pem gateway-client.pem gateway-client-key.pem
docker run --detach --name "$invalid_gateway" --platform "$platform" \
  --network "$network" --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$image" \
  --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-port 0 --metrics-port 0 \
  --smp 1 --memory 256M --overprovisioned >/dev/null
attempt=0
while [ "$(docker inspect --format '{{.State.Running}}' "$invalid_gateway")" = true ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 10 ]; then
    echo "BonVoyage accepted a malformed upstream trust bundle" >&2
    exit 1
  fi
  sleep 1
done
invalid_status="$(docker inspect --format '{{.State.ExitCode}}' "$invalid_gateway")"
test "$invalid_status" -ne 0

docker stop --signal TERM --time 15 "$gateway" >/dev/null
exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
test "$exit_code" -eq 0
echo "BonVoyage upstream TLS and mTLS smoke passed"
