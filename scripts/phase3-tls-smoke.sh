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
network="bonvoyage-tls-smoke-$suffix"
volume="bonvoyage-tls-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-tls-gateway-$suffix"
upstream="bonvoyage-tls-upstream-$suffix"
invalid_gateway="bonvoyage-invalid-tls-$suffix"
tls_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-tls.XXXXXX")"

cleanup() {
  status="$?"
  if [ "$status" -ne 0 ] && docker inspect "$gateway" >/dev/null 2>&1; then
    echo "BonVoyage gateway logs after TLS smoke failure:" >&2
    docker logs "$gateway" >&2 || true
    echo "BonVoyage metrics after TLS smoke failure:" >&2
    docker exec "$upstream" python -c '
import signal, urllib.request
signal.alarm(3)
print(urllib.request.urlopen(
    "http://bonvoyage-tls-gateway-'"$suffix"':9090/metrics", timeout=10
).read().decode())
' >&2 || true
  fi
  docker rm --force "$gateway" "$upstream" "$invalid_gateway" \
    >/dev/null 2>&1 || true
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
  echo "openssl is required for the ephemeral TLS fixtures" >&2
  exit 1
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage Test CA" \
  -keyout "$tls_dir/ca-key.pem" -out "$tls_dir/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=api.example.test" \
  -keyout "$tls_dir/server-key.pem" -out "$tls_dir/server.csr" \
  >/dev/null 2>&1
printf '%s\n' \
  "subjectAltName=DNS:api.example.test" \
  "extendedKeyUsage=serverAuth" \
  "keyUsage=digitalSignature,keyEncipherment" >"$tls_dir/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$tls_dir/server.csr" \
  -CA "$tls_dir/ca.pem" -CAkey "$tls_dir/ca-key.pem" -CAcreateserial \
  -extfile "$tls_dir/server-ext.cnf" -out "$tls_dir/server-chain.pem" \
  >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=phase3-client" \
  -keyout "$tls_dir/client-key.pem" -out "$tls_dir/client.csr" \
  >/dev/null 2>&1
printf '%s\n' \
  "extendedKeyUsage=clientAuth" \
  "keyUsage=digitalSignature" >"$tls_dir/client-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$tls_dir/client.csr" \
  -CA "$tls_dir/ca.pem" -CAkey "$tls_dir/ca-key.pem" -CAcreateserial \
  -extfile "$tls_dir/client-ext.cnf" -out "$tls_dir/client.pem" \
  >/dev/null 2>&1
cp "$tls_dir/ca.pem" "$tls_dir/client-ca.pem"
chmod 600 "$tls_dir"/*-key.pem

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$tls_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem client-ca.pem

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-tls.yaml:/etc/bonvoyage/tls.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/tls.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >/dev/null

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --volume "$tls_dir:/tls:ro" "$upstream_image" >/dev/null
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

docker exec "$upstream" python -c '
import http.client
import socket
import ssl
import time

def context(client=False, check_hostname=True):
    value = ssl.create_default_context(cafile="/tls/ca.pem")
    value.minimum_version = ssl.TLSVersion.TLSv1_2
    value.check_hostname = check_hostname
    value.set_alpn_protocols(["h2", "http/1.1"])
    if client:
        value.load_cert_chain("/tls/client.pem", "/tls/client-key.pem")
    return value

regular = http.client.HTTPSConnection(
    "api.example.test", 8443, context=context(), timeout=10)
regular.request("GET", "/bonvoyage/ready")
response = regular.getresponse()
assert response.status == 200 and response.read() == b"ready\n"
assert regular.sock.version() in ("TLSv1.2", "TLSv1.3")
assert regular.sock.selected_alpn_protocol() == "http/1.1"
regular.request("GET", "/forwarded-proto")
response = regular.getresponse()
assert response.status == 200 and response.read() == b"https"
regular.close()

# A client omitting SNI uses the listener certificate and HTTP Host routing.
with socket.create_connection(("api.example.test", 8443), timeout=10) as raw:
    no_sni_context = context(check_hostname=False)
    with no_sni_context.wrap_socket(raw) as secure:
        secure.sendall(b"GET /bonvoyage/ready HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n")
        assert b"HTTP/1.1 200 OK" in secure.recv(4096)

mismatch = http.client.HTTPSConnection(
    "api.example.test", 8443, context=context(), timeout=10)
mismatch.request("GET", "/bonvoyage/ready", headers={"Host": "other.example.test"})
response = mismatch.getresponse()
assert response.status == 421
response.read()
mismatch.close()

unknown_context = context(check_hostname=False)
with socket.create_connection(("api.example.test", 8443), timeout=10) as raw:
    with unknown_context.wrap_socket(raw, server_hostname="unknown.example.test") as secure:
        secure.sendall(b"GET /bonvoyage/ready HTTP/1.1\r\nHost: unknown.example.test\r\nConnection: close\r\n\r\n")
        assert secure.recv(4096) == b""

without_client = context()
rejected = False
try:
    with socket.create_connection(("api.example.test", 9443), timeout=10) as raw:
        with without_client.wrap_socket(raw, server_hostname="api.example.test") as secure:
            secure.sendall(b"GET /bonvoyage/ready HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n")
            rejected = secure.recv(4096) == b""
except (ConnectionError, OSError, ssl.SSLError):
    rejected = True
assert rejected

mutual = http.client.HTTPSConnection(
    "api.example.test", 9443, context=context(client=True), timeout=10)
mutual.request("GET", "/bonvoyage/ready")
response = mutual.getresponse()
assert response.status == 200 and response.read() == b"ready\n"
assert mutual.sock.selected_alpn_protocol() == "http/1.1"
mutual.close()

# A TCP client that never starts TLS must be closed by the fixed handshake
# deadline, not by the additional Seastar TLS graceful-close timeout.
started = time.monotonic()
closed = False
with socket.create_connection(("api.example.test", 8443), timeout=10) as raw:
    raw.settimeout(14)
    try:
        closed = raw.recv(1) == b""
    except (ConnectionError, OSError):
        closed = True
elapsed = time.monotonic() - started
assert closed and elapsed < 14, (closed, elapsed)
print(f"Stalled downstream TLS handshake: closed elapsed={elapsed:.3f}s")
'

docker exec "$upstream" python -c '
import urllib.request
metrics = urllib.request.urlopen(
    "http://bonvoyage-tls-gateway-'"$suffix"':9090/metrics", timeout=10
).read().decode()

def total(name):
    return sum(
        float(line.split()[-1])
        for line in metrics.splitlines()
        if line.startswith(name + "{") or line.startswith(name + " ")
    )

prefix = "bonvoyage_bonvoyage_gateway_"
assert total(prefix + "tls_handshakes_total") >= 1
assert total(prefix + "tls_handshake_failures_total") >= 1
assert total(prefix + "tls_handshake_timeouts_total") >= 1
assert total(prefix + "tls_sni_rejections_total") >= 1
'

# Exercise repeated HTTPS requests before the dedicated-host performance run.
# This is a functional load assertion, not retained or publishable evidence.
docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$tls_dir:/tls:ro" "$oha_image" \
  -z 5s -c 32 --no-tui --output-format json \
  --http-version 1.1 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/payload/256 >"$tls_dir/https.oha.json"
docker exec "$upstream" python -c '
import json
with open("/tls/https.oha.json", encoding="utf-8") as source:
    result = json.load(source)
assert result["summary"]["requestsPerSec"] > 0
assert result["summary"]["successRate"] == 1
'

printf '%s\n' "not a certificate" >"$tls_dir/server-chain.pem"
bv_stage_fixture_secrets --refresh "$secret_volume" "$tls_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem client-ca.pem
set +e
docker run --name "$invalid_gateway" --platform "$platform" \
  --network "$network" --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$image" \
  --snapshot /snapshot/snapshot.pb --admin-port 0 --metrics-port 0 \
  --smp 1 --memory 256M --overprovisioned >/dev/null 2>&1
invalid_status="$?"
set -e
test "$invalid_status" -ne 0

docker stop --signal TERM --time 15 "$gateway" >/dev/null
exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
test "$exit_code" -eq 0
echo "BonVoyage downstream TLS and mTLS smoke passed"
