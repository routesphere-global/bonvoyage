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
run_id="header-transformations-smoke-$timestamp"
suffix="$$"
network="bonvoyage-header-transformations-$suffix"
volume="bonvoyage-header-transformations-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-header-transformations-gateway-$suffix"
upstream="bonvoyage-header-transformations-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-header-transformations.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_HEADER_TRANSFORMATIONS_EVIDENCE_ROOT:-benchmarks/results/verification}"
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
    echo "header transformation smoke failed; temporary evidence: $stage_dir" >&2
    sed -n '1,200p' "$stage_dir/gateway.log" >&2 || true
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

h2_request() {
  output="$1"
  shift
  raw_output="$work_dir/$output.raw"
  docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
    --volume "$work_dir:/tls:ro" "$oha_image" \
    --debug --no-color --http-version 2 --disable-compression --no-tui -n 1 \
    --cacert /tls/ca.pem "$@" >"$raw_output" 2>&1
  sed "s/$api_key/[REDACTED]/g" "$raw_output" >"$stage_dir/$output"
  rm "$raw_output"
}

assert_h2_status() {
  file="$1"
  status="$2"
  grep -Eiq "status[^0-9]*$status|HTTP/2(\.0)?[[:space:]]+$status" \
    "$stage_dir/$file"
}

assert_h2_header() {
  file="$1"
  name="$2"
  value="$3"
  grep -Fiq "\"$name\": \"$value\"" "$stage_dir/$file" || \
    grep -Fiq "$name: $value" "$stage_dir/$file"
}

assert_h2_no_header() {
  file="$1"
  name="$2"
  if grep -Eiq "\"${name}\"[[:space:]]*:|${name}[[:space:]]*:" \
    "$stage_dir/$file"; then
    echo "$file unexpectedly contained $name" >&2
    exit 1
  fi
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage Header Transformation Test CA" \
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
api_key="$(openssl rand -hex 16)"
printf '%s\n' "$api_key" \
  >"$work_dir/phase3-header-transformations-api-keys.txt"
chmod 600 "$work_dir"/*-key.pem \
  "$work_dir/phase3-header-transformations-api-keys.txt"

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem phase3-header-transformations-api-keys.txt

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-header-transformations.yaml:/etc/bonvoyage/header-transformations.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/header-transformations.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --entrypoint python \
  --volume "$PWD/scripts/phase3-header-transformations-upstream.py:/header-transformations-upstream.py:ro" \
  --volume "$PWD/scripts/phase3-header-transformations-client.py:/header-transformations-client.py:ro" \
  "$upstream_image" /header-transformations-upstream.py >/dev/null

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

docker exec "$upstream" python /header-transformations-client.py \
  "bonvoyage-header-transformations-gateway-$suffix" "$api_key" \
  >"$stage_dir/http1-results.json"

h2_request http2-valid.txt \
  -H "x-api-key: $api_key" \
  -H "origin: https://app.example.com" \
  -H "x-request-set: client-set" \
  -H "x-request-append: client-append" \
  -H "x-request-remove: client-remove" \
  -H "x-client-protocol: h2" \
  https://api.example.test:8443/headers
assert_h2_status http2-valid.txt 200
assert_h2_header http2-valid.txt x-response-set gateway-set
assert_h2_header http2-valid.txt x-response-append \
  'upstream-append, gateway-append'
assert_h2_header http2-valid.txt x-response-added gateway-added
assert_h2_header http2-valid.txt x-response-unchanged upstream-keep
assert_h2_no_header http2-valid.txt x-response-remove
assert_h2_header http2-valid.txt access-control-allow-origin \
  https://app.example.com
grep -Fq '\"x-request-set\": \"gateway-set\"' "$stage_dir/http2-valid.txt"
grep -Fq '\"x-request-append\": \"client-append, gateway-append\"' \
  "$stage_dir/http2-valid.txt"

h2_request http2-auth-missing.txt \
  -H "x-request-set: client-set" \
  -H "x-request-append: client-append" \
  -H "x-request-remove: client-remove" \
  -H "x-client-protocol: h2" \
  https://api.example.test:8443/headers
assert_h2_status http2-auth-missing.txt 401
grep -Fq unauthorized "$stage_dir/http2-auth-missing.txt"
assert_h2_no_header http2-auth-missing.txt x-response-added

h2_request http2-plain.txt \
  -H "x-request-set: client-set" \
  -H "x-request-append: client-append" \
  -H "x-request-remove: client-remove" \
  -H "x-client-protocol: h2" \
  https://api.example.test:8443/plain
assert_h2_status http2-plain.txt 200
assert_h2_header http2-plain.txt x-response-set upstream-set
assert_h2_header http2-plain.txt x-response-append upstream-append
assert_h2_header http2-plain.txt x-response-remove upstream-remove
assert_h2_no_header http2-plain.txt x-response-added
grep -Fq '\"x-request-set\": \"client-set\"' "$stage_dir/http2-plain.txt"

h2_request http2-request-limit.txt \
  -H "x-request-set: client-set" \
  -H "x-request-append: client-append" \
  -H "x-request-remove: client-remove" \
  -H "x-client-protocol: h2" \
  https://api.example.test:8443/request-limit
assert_h2_status http2-request-limit.txt 431
grep -Fq transformed_request_headers_too_large \
  "$stage_dir/http2-request-limit.txt"

h2_request http2-request-limit-recovery.txt \
  -H "x-request-set: client-set" \
  -H "x-request-append: client-append" \
  -H "x-request-remove: client-remove" \
  -H "x-client-protocol: h2" \
  https://api.example.test:8443/plain
assert_h2_status http2-request-limit-recovery.txt 200
assert_h2_header http2-request-limit-recovery.txt x-response-set upstream-set

h2_request http2-response-limit.txt \
  -H "x-request-set: client-set" \
  -H "x-request-append: client-append" \
  -H "x-request-remove: client-remove" \
  -H "x-client-protocol: h2" \
  https://api.example.test:8443/response-limit
assert_h2_status http2-response-limit.txt 502
grep -Fq upstream_failure "$stage_dir/http2-response-limit.txt"
assert_h2_no_header http2-response-limit.txt x-response-limit-padding

h2_request http2-response-limit-recovery.txt \
  -H "x-request-set: client-set" \
  -H "x-request-append: client-append" \
  -H "x-request-remove: client-remove" \
  -H "x-client-protocol: h2" \
  https://api.example.test:8443/plain
assert_h2_status http2-response-limit-recovery.txt 200
assert_h2_header http2-response-limit-recovery.txt x-response-set upstream-set

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-header-transformations-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$upstream" python -c '
import urllib.request
metrics = urllib.request.urlopen(
    "http://bonvoyage-header-transformations-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode()
def total(suffix):
    result = 0.0
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        if name.split("{", 1)[0] == "bonvoyage_bonvoyage_gateway_" + suffix:
            result += float(raw)
    return result
assert total("requests_total") == 14
assert total("responses_2xx_total") == 8
assert total("responses_4xx_total") == 4
assert total("responses_5xx_total") == 2
assert total("api_key_auth_successes_total") == 2
assert total("api_key_auth_rejections_total") == 2
assert total("cors_actual_allows_total") == 2
assert total("request_header_transformation_applications_total") == 2
assert total("response_header_transformation_applications_total") == 2
assert total("header_transformation_limit_rejections_total") == 4
assert total("upstream_endpoint_selections_total") == 10
assert total("upstream_failures_total") == 2
assert total("route_misses_total") == 0
assert total("active_route_requests") == 0
assert total("active_upstream_requests") == 0
print("header transformation metrics and final gauges passed")
' >"$stage_dir/metrics-validation.txt"

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
assert len(records) == 10
transformed = [record for record in records if record["path"] == "/headers"]
plain = [record for record in records if record["path"] == "/plain"]
response_limit = [
    record for record in records if record["path"] == "/response-limit"
]
request_limit = [
    record for record in records if record["path"] == "/request-limit"
]
assert len(transformed) == 2
assert len(plain) == 6
assert len(response_limit) == 2
assert not request_limit
assert {record["headers"]["x-client-protocol"] for record in transformed} == {"h1", "h2"}
assert [
    record["headers"]["x-client-protocol"] for record in plain
].count("h1") == 3
assert [
    record["headers"]["x-client-protocol"] for record in plain
].count("h2") == 3
assert {
    record["headers"]["x-client-protocol"] for record in response_limit
} == {"h1", "h2"}
for record in transformed:
    headers = record["headers"]
    assert headers["x-request-set"] == "gateway-set"
    assert headers["x-request-append"] == "client-append, gateway-append"
    assert headers["x-request-added"] == "gateway-added"
    assert "x-request-remove" not in headers
    assert "x-api-key" not in headers
    expected_proto = "http" if headers["x-client-protocol"] == "h1" else "https"
    assert headers["x-forwarded-proto"] == expected_proto
for record in plain:
    headers = record["headers"]
    assert headers["x-request-set"] == "client-set"
    assert headers["x-request-append"] == "client-append"
    assert headers["x-request-remove"] == "client-remove"
    assert "x-request-added" not in headers
for record in response_limit:
    headers = record["headers"]
    assert headers["x-request-set"] == "client-set"
    assert headers["x-request-append"] == "client-append"
    assert headers["x-request-remove"] == "client-remove"
    assert "x-request-limit-padding" not in headers
print(
    "controlled upstream observed exact transformed, rejected, and recovery requests"
)
PY

for evidence_file in "$stage_dir"/*; do
  if grep -Fq "$api_key" "$evidence_file"; then
    echo "ephemeral API key appeared in retained evidence $evidence_file" >&2
    exit 1
  fi
done

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
protocols=http1,tls-http2
request_mutations=set,append,remove
response_mutations=set,append,remove
maximum_mutations_per_direction=16
maximum_configured_bytes_per_direction=16384
runtime_header_limit_bytes=1024
transformed_request_limit_status=431
transformed_response_limit_status=502
observed_limit_rejections=4
post_rejection_recovery_requests=4
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<'EOF'
# Phase 3 bounded header transformation evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway applied bounded static set, append, remove, and add behavior to sanitized proxy request and response fields over HTTP/1.1 and TLS HTTP/2. API-key authentication completed before mutation, the credential never reached the controlled upstream or retained evidence, CORS-owned fields remained under the CORS policy, and an unconfigured route stayed unchanged. Post-transformation block expansion beyond the configured 1,024-byte limit returned exact request `431` and response `502` failures in both protocols. Four successful requests after those failures proved process recovery without a restart. Exact fixed-cardinality counters and controlled-upstream isolation passed.

This is local correctness, security-boundary, and protocol-parity evidence. It does not qualify dedicated feature cost, multi-shard saturation, dynamic activation, third-party interoperability, or publishable claims.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
.github/workflows/ci.yml
Makefile
api/gen/go/bonvoyage/v1/config.pb.go
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
control-plane/internal/snapshot/snapshot_test.go
dataplane/CMakeLists.txt
dataplane/include/bonvoyage/runtime/header_transformations.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/gateway.cc
dataplane/src/header_transformations.cc
dataplane/src/runtime_snapshot.cc
dataplane/tests/header_transformations_test.cc
dataplane/tests/runtime_snapshot_test.cc
deploy/docker/bonvoyage/Dockerfile
docs/architecture/decisions/0024-bounded-route-header-transformations.md
scripts/phase3-header-transformations-client.py
scripts/phase3-header-transformations-smoke.sh
scripts/test-fixture-secrets.sh
scripts/phase3-header-transformations-upstream.py
tests/fixtures/phase3-header-transformations.yaml
EOF
while IFS= read -r source_file; do hash_file "$source_file"; done \
  <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md compiler.txt gateway.inspect.json gateway.log \
    http1-results.json http2-auth-missing.txt http2-plain.txt \
    http2-request-limit-recovery.txt http2-request-limit.txt \
    http2-response-limit-recovery.txt http2-response-limit.txt \
    http2-valid.txt \
    metadata.txt metrics-validation.txt metrics.prom \
    runtime-image.inspect.json source-checksums.sha256 upstream.log \
    upstream-validation.txt; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-header-transformations.txt.tmp"
mv "$output_root/current-header-transformations.txt.tmp" \
  "$output_root/current-header-transformations.txt"

printf 'header transformation integration passed: %s\n' "$output_dir"
cat "$output_dir/http1-results.json"
cat "$output_dir/metrics-validation.txt"
cat "$output_dir/upstream-validation.txt"
