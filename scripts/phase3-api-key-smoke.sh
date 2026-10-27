#!/bin/sh
set -eu

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="api-key-smoke-$timestamp"
suffix="$$"
network="bonvoyage-api-key-$suffix"
volume="bonvoyage-api-key-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-api-key-gateway-$suffix"
invalid_gateway="bonvoyage-api-key-invalid-$suffix"
upstream="bonvoyage-api-key-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-api-key.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_API_KEY_EVIDENCE_ROOT:-benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"

cleanup() {
  status="$?"
  if [ -d "$stage_dir" ] && docker inspect "$gateway" >/dev/null 2>&1; then
    docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1 || true
  fi
  if [ -d "$stage_dir" ] && docker inspect "$invalid_gateway" >/dev/null 2>&1; then
    docker logs "$invalid_gateway" >"$stage_dir/invalid-startup.log" 2>&1 || true
  fi
  if [ -d "$stage_dir" ] && docker inspect "$upstream" >/dev/null 2>&1; then
    docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1 || true
  fi
  if [ "$status" -ne 0 ]; then
    echo "API-key smoke failed; temporary evidence: $stage_dir" >&2
    if [ -f "$stage_dir/gateway.log" ]; then
      cat "$stage_dir/gateway.log" >&2
    fi
  fi
  docker rm --force "$gateway" "$invalid_gateway" "$upstream" \
    >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$work_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  if [ "$status" -eq 0 ]; then
    rm -rf "$work_dir"
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

for command_name in date docker git grep mktemp openssl uname; do
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
  -subj "/CN=BonVoyage API Key Test CA" \
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

# Credentials are generated for this run and never written to retained evidence.
primary_key="$(openssl rand -hex 16)"
secondary_key="$(openssl rand -hex 16)"
printf '%s\n%s\n' "$primary_key" "$secondary_key" \
  >"$work_dir/phase3-api-keys.txt"
chmod 600 "$work_dir"/*-key.pem "$work_dir/phase3-api-keys.txt"

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem phase3-api-keys.txt

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-api-key.yaml:/etc/bonvoyage/api-key.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/api-key.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --volume "$work_dir:/tls:ro" "$upstream_image" >/dev/null

attempt=0
until docker exec "$upstream" python -c \
  'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:8081/healthz", timeout=1).status == 200' \
  >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "controlled upstream did not become ready" >&2
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

docker exec "$upstream" python -c '
import json
import socket
import urllib.error
import urllib.request

gateway = "bonvoyage-api-key-gateway-'"$suffix"'"
with open("/tls/phase3-api-keys.txt", encoding="ascii") as source:
    primary, secondary = source.read().splitlines()

def request(path, headers=None):
    configured = {"Host": "api.example.test"}
    configured.update(headers or {})
    value = urllib.request.Request(
        f"http://{gateway}:8080{path}", headers=configured
    )
    try:
        with urllib.request.urlopen(value, timeout=5) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()

def raw_request(path, headers):
    lines = [
        f"GET {path} HTTP/1.1",
        "Host: api.example.test",
        *(f"{name}: {value}" for name, value in headers),
        "Connection: close",
        "",
        "",
    ]
    with socket.create_connection((gateway, 8080), timeout=5) as stream:
        stream.sendall("\r\n".join(lines).encode("ascii"))
        response = bytearray()
        while True:
            chunk = stream.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    head, body = bytes(response).split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    response_headers = {}
    for line in lines[1:]:
        name, value = line.split(b":", 1)
        response_headers[name.decode("ascii").lower()] = value.strip().decode("ascii")
    return status, response_headers, body

status, _, body = request("/public")
assert status == 200 and body == b"public ready\n"

failures = []
for headers in ({}, {"X-API-Key": "f" * 32}, {"X-API-Key": "short"}):
    status, response_headers, body = request("/protected-fixed", headers)
    assert status == 401, (status, body)
    assert response_headers["WWW-Authenticate"] == "ApiKey", response_headers
    failures.append(body)
status, response_headers, body = raw_request("/protected-fixed", [
    ("X-API-Key", primary),
    ("X-API-Key", secondary),
])
assert status == 401, (status, body)
assert response_headers["www-authenticate"] == "ApiKey", response_headers
failures.append(body)
assert len(set(failures)) == 1, failures
assert json.loads(failures[0])["error"]["code"] == "unauthorized"

status, _, body = request("/protected-fixed", {"X-API-Key": primary})
assert status == 200 and body == b"protected ready\n"
status, _, body = request("/api-key-observation", {
    "X-API-Key": secondary,
    "X-Request-ID": "http1-preserved",
})
assert status == 200, (status, body)
observation = json.loads(body)
assert observation == {
    "api_key_header_present": False,
    "request_id": "http1-preserved",
}, observation

print(json.dumps({
    "credential_header_forwarded": observation["api_key_header_present"],
    "failure_classes_indistinguishable": True,
    "public_route_without_credentials": True,
    "repeated_field_rejected": True,
    "request_id_preserved": True,
    "valid_credentials_accepted": 2,
}, indent=2, sort_keys=True))
' >"$stage_dir/http1-results.json"

docker exec "$upstream" python -c '
import json
import socket
import ssl

with open("/tls/phase3-api-keys.txt", encoding="ascii") as source:
    primary, secondary = source.read().splitlines()

def integer(value, prefix_bits, first):
    maximum = (1 << prefix_bits) - 1
    if value < maximum:
        return bytes([first | value])
    output = bytearray([first | maximum])
    value -= maximum
    while value >= 128:
        output.append((value % 128) + 128)
        value //= 128
    output.append(value)
    return bytes(output)

def text(value):
    encoded = value.encode("ascii")
    return integer(len(encoded), 7, 0) + encoded

def literal_indexed_name(index, value):
    return integer(index, 4, 0) + text(value)

def literal(name, value):
    return b"\x00" + text(name) + text(value)

def frame(frame_type, flags, stream_id, payload=b""):
    return (
        len(payload).to_bytes(3, "big") + bytes([frame_type, flags])
        + stream_id.to_bytes(4, "big") + payload
    )

def read_exact(stream, amount):
    value = bytearray()
    while len(value) < amount:
        chunk = stream.recv(amount - len(value))
        if not chunk:
            raise AssertionError("HTTP/2 connection ended early")
        value.extend(chunk)
    return bytes(value)

def request(path, extra_headers):
    block = b"".join((
        b"\x82", b"\x87",
        literal_indexed_name(4, path),
        literal_indexed_name(1, "api.example.test"),
        *(literal(name, value) for name, value in extra_headers),
    ))
    context = ssl.create_default_context(cafile="/tls/ca.pem")
    context.set_alpn_protocols(["h2"])
    with socket.create_connection(("api.example.test", 8443), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname="api.example.test") as secure:
            assert secure.selected_alpn_protocol() == "h2"
            secure.sendall(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                + frame(4, 0, 0)
                + frame(1, 5, 1, block)
            )
            body = bytearray()
            while True:
                header = read_exact(secure, 9)
                length = int.from_bytes(header[:3], "big")
                frame_type = header[3]
                flags = header[4]
                stream_id = int.from_bytes(header[5:], "big") & 0x7fffffff
                payload = read_exact(secure, length)
                if frame_type == 4 and flags & 1 == 0:
                    secure.sendall(frame(4, 1, 0))
                if frame_type == 0 and stream_id == 1:
                    body.extend(payload)
                if stream_id == 1 and flags & 1:
                    return bytes(body)

assert request("/public", []) == b"public ready\n"
failure_bodies = [
    request("/protected-fixed", []),
    request("/protected-fixed", [("x-api-key", "f" * 32)]),
    request("/protected-fixed", [("x-api-key", "short")]),
    request("/protected-fixed", [
        ("x-api-key", primary),
        ("x-api-key", secondary),
    ]),
]
assert len(set(failure_bodies)) == 1, failure_bodies
assert json.loads(failure_bodies[0])["error"]["code"] == "unauthorized"
assert request(
    "/protected-fixed", [("x-api-key", secondary)]
) == b"protected ready\n"
observation = json.loads(request("/api-key-observation", [
    ("x-api-key", primary),
    ("x-request-id", "http2-preserved"),
]))
assert observation == {
    "api_key_header_present": False,
    "request_id": "http2-preserved",
}, observation

print(json.dumps({
    "credential_header_forwarded": observation["api_key_header_present"],
    "failure_classes_indistinguishable": True,
    "public_route_without_credentials": True,
    "repeated_field_rejected": True,
    "request_id_preserved": True,
    "valid_credentials_accepted": 2,
}, indent=2, sort_keys=True))
' >"$stage_dir/http2-results.json"

# Capture the HTTP/2 status and challenge without placing a credential in output.
docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  --debug --no-color --http-version 2 --disable-compression \
  --cacert /tls/ca.pem \
  https://api.example.test:8443/protected-fixed \
  >"$stage_dir/http2-missing-response.txt" 2>&1
grep -Eiq 'status[^0-9]*401|401 Unauthorized' \
  "$stage_dir/http2-missing-response.txt"
grep -Eiq 'www-authenticate[^A-Za-z]+ApiKey' \
  "$stage_dir/http2-missing-response.txt"

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-api-key-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$upstream" python -c '
import urllib.request

metrics = urllib.request.urlopen(
    "http://bonvoyage-api-key-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode()

def total(suffix):
    value = 0.0
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        if name.split("{", 1)[0] == "bonvoyage_bonvoyage_gateway_" + suffix:
            value += float(raw)
    return value

assert total("api_key_auth_successes_total") == 4
assert total("api_key_auth_rejections_total") == 9
assert total("responses_4xx_total") == 9
assert total("upstream_failures_total") == 0
assert total("active_upstream_requests") == 0
print("API-key metrics and final gauges passed")
' >"$stage_dir/metrics-validation.txt"

docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1
docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1

# A malformed credential file must terminate startup before any listener opens.
printf '%s\n' short >"$work_dir/phase3-api-keys.txt"
bv_stage_fixture_secrets --refresh "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem phase3-api-keys.txt
docker run --detach --platform "$platform" --name "$invalid_gateway" \
  --network "$network" \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$image" \
  --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 256M --overprovisioned \
  >"$stage_dir/invalid-container-id.txt"
attempt=0
while [ "$(docker inspect --format '{{.State.Running}}' "$invalid_gateway")" = true ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 50 ]; then
    echo "gateway remained running with an invalid API-key secret" >&2
    exit 1
  fi
  sleep 0.1
done
invalid_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$invalid_gateway")"
test "$invalid_exit_code" -ne 0
docker logs "$invalid_gateway" >"$stage_dir/invalid-startup.log" 2>&1
printf 'invalid_secret_exit_code=%s\nlistener_started=false\n' \
  "$invalid_exit_code" >"$stage_dir/startup-validation.txt"

for log_file in "$stage_dir/gateway.log" "$stage_dir/invalid-startup.log" \
  "$stage_dir/upstream.log"; do
  if grep -Fq "$primary_key" "$log_file" || \
    grep -Fq "$secondary_key" "$log_file"; then
    echo "ephemeral API key appeared in retained logs" >&2
    exit 1
  fi
done

source_commit="$(git rev-parse HEAD)"
if [ -z "$(git status --porcelain)" ]; then
  source_dirty=false
else
  source_dirty=true
fi
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
credential_count=2
credential_minimum_bytes=16
credential_maximum_bytes=128
credential_file_maximum_bytes=16384
credential_count_maximum=64
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 static API-key authentication evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway protected fixed and proxied routes over HTTP/1.1 and TLS HTTP/2. It accepted either configured ephemeral credential, produced indistinguishable failures for missing, unknown, malformed, and repeated credentials, removed the credential header before proxying, preserved an unrelated request header, left an unprotected route accessible, exposed shard-local success/rejection counters, and refused startup with an invalid credential file. Retained output contains no credential value.

This is a correctness and security-boundary record. It does not qualify production secret rotation, distributed credential management, policy cost, multi-shard behavior, or production throughput.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
dataplane/include/bonvoyage/runtime/api_key_auth.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/api_key_auth.cc
dataplane/src/gateway.cc
dataplane/src/runtime_snapshot.cc
dataplane/tests/api_key_auth_test.cc
dataplane/tests/runtime_snapshot_test.cc
deploy/docker/upstream/server.py
scripts/phase3-api-key-smoke.sh
scripts/test-fixture-secrets.sh
tests/fixtures/phase3-api-key.yaml
EOF
while IFS= read -r source_file; do
  hash_file "$source_file"
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md compiler.txt gateway.inspect.json \
    gateway.log http1-results.json http2-missing-response.txt \
    http2-results.json invalid-container-id.txt invalid-startup.log \
    metadata.txt metrics-validation.txt metrics.prom \
    runtime-image.inspect.json source-checksums.sha256 \
    startup-validation.txt upstream.log; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-api-key-smoke.txt.tmp"
mv "$output_root/current-api-key-smoke.txt.tmp" \
  "$output_root/current-api-key-smoke.txt"

printf 'API-key authentication integration passed: %s\n' "$output_dir"
cat "$output_dir/http1-results.json"
cat "$output_dir/http2-results.json"
cat "$output_dir/metrics-validation.txt"
cat "$output_dir/startup-validation.txt"
