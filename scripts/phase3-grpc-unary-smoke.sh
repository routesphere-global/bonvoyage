#!/bin/sh
set -eu

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
fixture_image="${BONVOYAGE_GRPC_FIXTURE_IMAGE:-bonvoyage-grpc-unary-fixture:dev}"
probe_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="grpc-unary-live-$timestamp"
suffix="$$"
network="bonvoyage-grpc-unary-$suffix"
volume="bonvoyage-grpc-unary-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-grpc-unary-gateway-$suffix"
upstream="bonvoyage-grpc-unary-upstream-$suffix"
probe="bonvoyage-grpc-unary-probe-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-grpc-unary.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_GRPC_EVIDENCE_ROOT:-benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"

cleanup() {
  status="$?"
  if [ -d "$stage_dir" ]; then
    if docker inspect "$gateway" >/dev/null 2>&1; then
      docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1 || true
    fi
    if docker inspect "$upstream" >/dev/null 2>&1; then
      docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1 || true
    fi
  fi
  docker rm --force "$gateway" "$upstream" "$probe" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$work_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  if [ "$status" -eq 0 ]; then
    rm -rf "$work_dir"
  else
    echo "native gRPC unary smoke failed; temporary evidence: $stage_dir" >&2
    sed -n '1,200p' "$stage_dir/gateway.log" >&2 || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

for command_name in date docker git grep mktemp openssl sed uname; do
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

run_client() {
  test_case="$1"
  docker run --rm --platform "$platform" --network "$network" \
    --volume "$work_dir:/secrets:ro" "$fixture_image" client \
    --target api.example.test:8443 \
    --ca /secrets/ca.pem \
    --server-name api.example.test \
    --case "$test_case" >"$stage_dir/client-$test_case.json"
}

capture_observations() {
  output="$1"
  docker exec "$probe" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-grpc-unary-upstream-'"$suffix"':8081/observations",
    timeout=5,
).read().decode(), end="")
' >"$stage_dir/$output"
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage Native gRPC Test CA" \
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

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$fixture_image" \
  --file tests/fixtures/grpc-unary/Dockerfile tests/fixtures/grpc-unary
docker buildx build --platform "$platform" --load --tag "$probe_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$probe_image" "$platform" \
  server-chain.pem server-key.pem upstream-ca.pem

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-grpc-unary.yaml:/etc/bonvoyage/grpc-unary.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/grpc-unary.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream-grpc.example.test \
  --volume "$work_dir:/secrets:ro" "$fixture_image" server \
  --certificate /secrets/upstream-chain.pem \
  --key /secrets/upstream-key.pem >/dev/null
docker run --detach --platform "$platform" --name "$probe" \
  --network "$network" --volume "$stage_dir:/evidence" \
  "$probe_image" >/dev/null

attempt=0
until docker exec "$probe" python -c '
import urllib.request
assert urllib.request.urlopen(
    "http://bonvoyage-grpc-unary-upstream-'"$suffix"':8081/healthz",
    timeout=1,
).status == 204
' >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "controlled gRPC upstream did not become ready" >&2
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
  --smp 1 --memory 512M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug >/dev/null

bv_wait_gateway_ready "$gateway" "$probe" "http://$gateway:9901/health/ready"

run_client success
capture_observations observations-success.json
run_client error
run_client deadline
sleep 1
capture_observations observations-deadline.json
run_client cancel
sleep 1
run_client large
run_client concurrent
capture_observations observations-concurrent.json
run_client raw-multiple
run_client raw-truncated
run_client raw-timeout
run_client raw-missing-te
run_client success
sleep 1
capture_observations observations-final.json

docker exec "$probe" python -c '
import json

def load(name):
    with open("/evidence/" + name, encoding="utf-8") as source:
        return json.load(source)

success = load("observations-success.json")
assert success["last_ascii_values"] == ["alpha"], success
assert success["last_cookie_values"] == ["session=abc; theme=dark"], success
assert success["last_binary_values_base64"] == ["AQID"], success

deadline = load("observations-deadline.json")
assert 0 <= deadline["last_deadline_millis"] <= 150, deadline
assert deadline["cancellations"] >= 1, deadline

concurrent = load("observations-concurrent.json")
assert concurrent["maximum_concurrent"] == 16, concurrent

final = load("observations-final.json")
assert final["requests"] >= 22, final
assert final["successes"] >= 19, final
assert final["application_errors"] == 1, final
assert final["cancellations"] >= 2, final
assert final["maximum_concurrent"] == 16, final
assert final["active"] == 0, final
assert final["last_cookie_values"] == ["session=abc; theme=dark"], final

for name in (
    "client-success.json",
    "client-error.json",
    "client-deadline.json",
    "client-cancel.json",
    "client-large.json",
    "client-concurrent.json",
    "client-raw-multiple.json",
    "client-raw-truncated.json",
    "client-raw-timeout.json",
    "client-raw-missing-te.json",
):
    load(name)

assert load("client-concurrent.json")["successful_requests"] == 16
assert load("client-large.json")["response_bytes"] == 131072
print(json.dumps(final, sort_keys=True))
' >"$stage_dir/functional-validation.txt"

docker exec "$probe" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-grpc-unary-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$probe" python -c '
metrics = open("/evidence/metrics.prom", encoding="utf-8").read()

def total(suffix):
    result = 0.0
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        if name.split("{", 1)[0] == "bonvoyage_bonvoyage_gateway_" + suffix:
            result += float(raw)
    return result

assert total("grpc_requests_total") >= 26
assert total("grpc_successes_total") >= 19
assert total("grpc_application_errors_total") == 1
assert total("grpc_local_errors_total") >= 4
assert total("grpc_protocol_rejections_total") >= 4
assert total("grpc_deadlines_propagated_total") >= 22
assert total("grpc_response_trailers_forwarded_total") >= 20
assert total("grpc_trailing_metadata_fields_total") >= 61
assert total("upstream_http2_streams_total") >= 22
assert total("upstream_http2_request_cancellations_total") >= 2
assert total("active_upstream_http2_streams") == 0
assert total("active_http2_streams") == 0
print("native gRPC unary metrics and final gauges passed")
' >"$stage_dir/metrics-validation.txt"

docker stop --signal TERM --time 20 "$gateway" >/dev/null
gateway_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
test "$gateway_exit_code" -eq 0
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1
docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1
if grep -Eiq 'AddressSanitizer|UndefinedBehaviorSanitizer|Segmentation fault|assertion failed|terminate called|stack overflow' \
  "$stage_dir/gateway.log" "$stage_dir/upstream.log"; then
  echo "runtime failure signature found in native gRPC logs" >&2
  exit 1
fi

docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker image inspect "$compiler_image" >"$stage_dir/compiler-image.inspect.json"
docker image inspect "$fixture_image" >"$stage_dir/fixture-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker inspect "$upstream" >"$stage_dir/upstream.inspect.json"
docker version >"$stage_dir/docker-version.txt"

source_commit="$(git rev-parse HEAD)"
if [ -z "$(git status --porcelain)" ]; then source_dirty=false; else source_dirty=true; fi
runtime_image_id="$(docker image inspect "$image" --format '{{.Id}}')"
fixture_image_id="$(docker image inspect "$fixture_image" --format '{{.Id}}')"
cat >"$stage_dir/metadata.txt" <<EOF
captured_at_utc=$timestamp
run_id=$run_id
source_commit=$source_commit
source_dirty=$source_dirty
host=$(uname -s) $(uname -r) $(uname -m)
platform=$platform
runtime_image=$image
runtime_image_id=$runtime_image_id
fixture_image=$fixture_image
fixture_image_id=$fixture_image_id
gateway_shards=1
downstream_protocol=tls-http2
upstream_protocol=tls-http2
rpc_cardinality=unary-one-request-one-response
maximum_upstream_streams_per_connection=32
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 native gRPC unary evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, competitive, or performance claims.

The live one-shard gateway transparently proxied a real unary gRPC method over downstream and upstream TLS HTTP/2. The gate verified protobuf payload delivery, initial and trailing metadata, binary and repeated metadata, application status and status details, adjusted deadlines, downstream cancellation, a 128 KiB response, 16 concurrent streams on one upstream connection, malformed unary envelopes, malformed timeout and TE contracts, graceful shutdown, and successful recovery without a gateway restart.

This record proves local correctness, bounded protocol validation, cancellation propagation, and fixture interoperability with grpc-go. It does not qualify streaming RPCs, gRPC-Web, third-party language matrices, multi-shard scaling, dedicated-host cost, saturation, production throughput, or publishable claims.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
Makefile
dataplane/CMakeLists.txt
dataplane/include/bonvoyage/http/grpc_protocol.hh
dataplane/include/bonvoyage/http/http2_session.hh
dataplane/src/gateway.cc
dataplane/src/grpc_protocol.cc
dataplane/src/http2_client_session.cc
dataplane/src/http2_session.cc
dataplane/src/upstream_http2_client.cc
dataplane/tests/grpc_protocol_test.cc
dataplane/tests/http2_session_test.cc
deploy/docker/bonvoyage/Dockerfile
scripts/phase3-grpc-unary-smoke.sh
scripts/test-fixture-secrets.sh
tests/fixtures/grpc-unary/Dockerfile
tests/fixtures/grpc-unary/go.mod
tests/fixtures/grpc-unary/go.sum
tests/fixtures/grpc-unary/main.go
tests/fixtures/phase3-grpc-unary.yaml
EOF
while IFS= read -r source_file; do hash_file "$source_file"; done \
  <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"
printf 'outcome=PASS\ngateway_exit_code=%s\n' "$gateway_exit_code" \
  >"$stage_dir/run-status.env"

(
  cd "$stage_dir"
  for evidence_file in README.md client-*.json compiler-image.inspect.json \
    compiler.txt docker-version.txt fixture-image.inspect.json \
    functional-validation.txt gateway.inspect.json gateway.log metadata.txt \
    metrics-validation.txt metrics.prom observations-*.json run-status.env \
    runtime-image.inspect.json source-checksums.sha256 upstream.inspect.json \
    upstream.log; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-grpc-unary.txt.tmp"
mv "$output_root/current-grpc-unary.txt.tmp" \
  "$output_root/current-grpc-unary.txt"

printf 'native gRPC unary integration passed: %s\n' "$output_dir"
cat "$output_dir/functional-validation.txt"
cat "$output_dir/metrics-validation.txt"
