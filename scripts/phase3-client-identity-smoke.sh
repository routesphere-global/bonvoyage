#!/bin/sh
set -eu

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="client-identity-smoke-$timestamp"
suffix="$$"
network="bonvoyage-client-identity-$suffix"
volume="bonvoyage-client-identity-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-client-identity-gateway-$suffix"
upstream="bonvoyage-client-identity-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-client-identity.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_CLIENT_IDENTITY_EVIDENCE_ROOT:-benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"

cleanup() {
  status="$?"
  if [ -d "$stage_dir" ] && docker inspect "$gateway" >/dev/null 2>&1; then
    docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1 || true
  fi
  if [ -d "$stage_dir" ] && docker inspect "$upstream" >/dev/null 2>&1; then
    docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1 || true
  fi
  if [ "$status" -ne 0 ]; then
    echo "client identity smoke failed; temporary evidence: $stage_dir" >&2
    if [ -f "$stage_dir/gateway.log" ]; then
      cat "$stage_dir/gateway.log" >&2
    fi
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
  -subj "/CN=BonVoyage Client Identity Test CA" \
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
  --volume "$PWD/tests/fixtures/phase3-client-identity.yaml:/etc/bonvoyage/client-identity.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/client-identity.yaml \
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
import ipaddress
import json
import socket
import urllib.error
import urllib.request

gateway = "bonvoyage-client-identity-gateway-'"$suffix"'"
identity_names = {
    "forwarded", "x-forwarded-host", "x-forwarded-port", "x-real-ip",
    "true-client-ip", "client-ip", "cf-connecting-ip",
}

def request(port, headers, expected=200):
    configured = {"Host": "api.example.test"}
    configured.update(headers)
    value = urllib.request.Request(
        f"http://{gateway}:{port}/client-identity", headers=configured
    )
    try:
        with urllib.request.urlopen(value, timeout=5) as response:
            status = response.status
            body = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read()
    assert status == expected, (status, body)
    return json.loads(body)

def raw_request(port, headers, expected=200):
    lines = [
        "GET /client-identity HTTP/1.1",
        "Host: api.example.test",
        *(f"{name}: {value}" for name, value in headers),
        "Connection: close",
        "",
        "",
    ]
    with socket.create_connection((gateway, port), timeout=5) as stream:
        stream.sendall("\r\n".join(lines).encode("ascii"))
        response = bytearray()
        while True:
            chunk = stream.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    head, body = bytes(response).split(b"\r\n\r\n", 1)
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    assert status == expected, (status, body)
    return json.loads(body)

spoofed = {
    "X-Forwarded-For": "203.0.113.77",
    "Forwarded": "for=203.0.113.77;proto=https",
    "X-Forwarded-Host": "spoofed.example",
    "X-Forwarded-Port": "443",
    "X-Real-IP": "203.0.113.77",
    "True-Client-IP": "203.0.113.77",
    "Client-IP": "203.0.113.77",
    "CF-Connecting-IP": "203.0.113.77",
    "X-Request-ID": "untrusted-preserved",
}
untrusted = request(8080, spoofed)
assert untrusted["x-forwarded-for"] != ["203.0.113.77"], untrusted
assert len(untrusted["x-forwarded-for"]) == 1, untrusted
ipaddress.ip_address(untrusted["x-forwarded-for"][0])
assert untrusted["x-forwarded-proto"] == ["http"], untrusted
assert untrusted["x-request-id"] == ["untrusted-preserved"], untrusted
assert all(untrusted[name] == [] for name in identity_names), untrusted

trusted = request(8081, {
    **spoofed,
    "X-Forwarded-For": "203.0.113.9, 10.20.30.40",
    "X-Request-ID": "trusted-preserved",
})
assert trusted["x-forwarded-for"] == ["203.0.113.9"], trusted
assert trusted["x-forwarded-proto"] == ["http"], trusted
assert trusted["x-request-id"] == ["trusted-preserved"], trusted
assert all(trusted[name] == [] for name in identity_names), trusted

direct = request(8081, {"X-Request-ID": "direct-preserved"})
assert len(direct["x-forwarded-for"]) == 1, direct
ipaddress.ip_address(direct["x-forwarded-for"][0])

invalid = request(8081, {"X-Forwarded-For": "unknown"}, 400)
assert invalid["error"]["code"] == "invalid_forwarded_for", invalid

repeated = raw_request(8081, [
    ("X-Forwarded-For", "203.0.113.12"),
    ("X-Forwarded-For", "10.20.30.60"),
])
assert repeated["x-forwarded-for"] == ["203.0.113.12"], repeated

print(json.dumps({
    "trusted_effective_client": trusted["x-forwarded-for"][0],
    "untrusted_effective_client": untrusted["x-forwarded-for"][0],
    "sanitized_identity_headers": sorted(identity_names),
    "unrelated_header_preserved": True,
    "invalid_chain_status": 400,
    "repeated_field_lines_normalized": True,
}, indent=2, sort_keys=True))
' >"$stage_dir/http1-results.json"

docker exec "$upstream" python -c '
import json
import socket
import ssl

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
    length = len(payload)
    return (
        length.to_bytes(3, "big") + bytes([frame_type, flags])
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

def request(extra_headers):
    block = b"".join((
        b"\x82", b"\x87",
        literal_indexed_name(4, "/client-identity"),
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

identity_names = {
    "forwarded", "x-forwarded-host", "x-forwarded-port", "x-real-ip",
    "true-client-ip", "client-ip", "cf-connecting-ip",
}
valid = json.loads(request([
    ("x-forwarded-for", "203.0.113.10, 10.20.30.50"),
    ("forwarded", "for=192.0.2.1"),
    ("x-real-ip", "192.0.2.1"),
    ("cf-connecting-ip", "192.0.2.1"),
    ("x-request-id", "http2-preserved"),
]))
assert valid["x-forwarded-for"] == ["203.0.113.10"], valid
assert valid["x-forwarded-proto"] == ["https"], valid
assert valid["x-request-id"] == ["http2-preserved"], valid
assert all(valid[name] == [] for name in identity_names), valid

invalid = json.loads(request([("x-forwarded-for", "unknown")]))
assert invalid["error"]["code"] == "invalid_forwarded_for", invalid
repeated = json.loads(request([
    ("x-forwarded-for", "203.0.113.11"),
    ("x-forwarded-for", "10.20.30.60"),
]))
assert repeated["x-forwarded-for"] == ["203.0.113.11"], repeated

print(json.dumps({
    "trusted_effective_client": valid["x-forwarded-for"][0],
    "forwarded_proto": valid["x-forwarded-proto"][0],
    "unrelated_header_preserved": True,
    "malformed_chain_rejected": True,
    "repeated_field_lines_normalized": True,
}, indent=2, sort_keys=True))
' >"$stage_dir/http2-results.json"

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-client-identity-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$upstream" python -c '
import urllib.request

metrics = urllib.request.urlopen(
    "http://bonvoyage-client-identity-gateway-'"$suffix"':9090/metrics",
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

assert total("trusted_proxy_client_ip_resolutions_total") == 4
assert total("forwarded_header_rejections_total") == 2
assert total("upstream_failures_total") == 0
assert total("active_upstream_requests") == 0
print("client identity metrics and final gauges passed")
' >"$stage_dir/metrics-validation.txt"

docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1
docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1

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
trusted_proxy_cidr_count=3
maximum_forwarded_for_hops=32
maximum_forwarded_for_bytes=2048
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 trusted proxy and client identity evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway ignored spoofed forwarding identity from an untrusted HTTP/1.1 peer, resolved strict trusted proxy chains over HTTP/1.1 and TLS HTTP/2, normalized repeated field lines in wire order, removed inbound identity headers, emitted canonical X-Forwarded-For and X-Forwarded-Proto fields, preserved an unrelated request header, and rejected malformed trusted chains without a restart.

This is a correctness and security-boundary record. It does not qualify policy cost, multi-shard behavior, proxy interoperability, or production throughput.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
dataplane/include/bonvoyage/runtime/client_identity.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/client_identity.cc
dataplane/src/gateway.cc
dataplane/src/runtime_snapshot.cc
dataplane/tests/client_identity_test.cc
dataplane/tests/runtime_snapshot_test.cc
deploy/docker/upstream/server.py
scripts/phase3-client-identity-smoke.sh
scripts/test-fixture-secrets.sh
tests/fixtures/phase3-client-identity.yaml
EOF
while IFS= read -r source_file; do
  hash_file "$source_file"
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md compiler.txt gateway.inspect.json \
    gateway.log http1-results.json http2-results.json metadata.txt \
    metrics-validation.txt metrics.prom runtime-image.inspect.json \
    source-checksums.sha256 upstream.log; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-client-identity-smoke.txt.tmp"
mv "$output_root/current-client-identity-smoke.txt.tmp" \
  "$output_root/current-client-identity-smoke.txt"

printf 'Client identity integration passed: %s\n' "$output_dir"
cat "$output_dir/http1-results.json"
cat "$output_dir/http2-results.json"
cat "$output_dir/metrics-validation.txt"
