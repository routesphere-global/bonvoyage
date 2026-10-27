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
run_id="request-content-smoke-$timestamp"
suffix="$$"
network="bonvoyage-request-content-$suffix"
volume="bonvoyage-request-content-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-request-content-gateway-$suffix"
upstream="bonvoyage-request-content-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-request-content.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_REQUEST_CONTENT_EVIDENCE_ROOT:-benchmarks/results/verification}"
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
    echo "request-content smoke failed; temporary evidence: $stage_dir" >&2
    sed -n '1,200p' "$stage_dir/gateway.log" >&2 || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

for command_name in date docker git grep mktemp openssl python3 sed uname; do
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
  docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
    --volume "$work_dir:/tls:ro" "$oha_image" \
    --debug --no-color --http-version 2 --disable-compression --no-tui -n 1 \
    --cacert /tls/ca.pem "$@" >"$stage_dir/$output" 2>&1
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

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage Request Content Test CA" \
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
printf '%s\n' "$api_key" >"$work_dir/phase3-request-content-api-keys.txt"
chmod 600 "$work_dir"/*-key.pem \
  "$work_dir/phase3-request-content-api-keys.txt"

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem phase3-request-content-api-keys.txt

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-request-content.yaml:/etc/bonvoyage/request-content.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/request-content.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --volume "$work_dir:/tls:ro" \
  --volume "$PWD/scripts/phase3-request-content-client.py:/request-content-client.py:ro" \
  "$upstream_image" >/dev/null

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

docker exec "$upstream" python /request-content-client.py \
  "bonvoyage-request-content-gateway-$suffix" \
  >"$stage_dir/http1-results.json"

h2_request http2-valid.txt -m POST -T application/json -d 12345678 \
  https://api.example.test:8443/content/declared
assert_h2_status http2-valid.txt 200
grep -Fq '12345678' "$stage_dir/http2-valid.txt"

# oha intentionally omits Content-Length for the first pair, exercising
# incremental HTTP/2 DATA enforcement after route selection.
h2_request http2-body-too-large.txt -m POST -T application/json -d 123456789 \
  https://api.example.test:8443/content/declared
assert_h2_status http2-body-too-large.txt 413
grep -Fq 'request_body_too_large' "$stage_dir/http2-body-too-large.txt"

h2_request http2-declared-valid.txt -m POST -T application/json \
  -H "content-length: 8" -d 12345678 \
  https://api.example.test:8443/content/declared
assert_h2_status http2-declared-valid.txt 200
grep -Fq '12345678' "$stage_dir/http2-declared-valid.txt"

h2_request http2-declared-too-large.txt -m POST -T application/json \
  -H "content-length: 9" -d 123456789 \
  https://api.example.test:8443/content/declared
assert_h2_status http2-declared-too-large.txt 413
grep -Fq 'request_body_too_large' "$stage_dir/http2-declared-too-large.txt"

h2_request http2-content-type-required.txt -m POST -d x \
  https://api.example.test:8443/content/declared
assert_h2_status http2-content-type-required.txt 415
grep -Fq 'content_type_required' "$stage_dir/http2-content-type-required.txt"
assert_h2_header http2-content-type-required.txt accept \
  'application/json, application/problem+json'

h2_request http2-unsupported.txt -m POST -T text/plain -d x \
  -H "origin: https://app.example.com" \
  https://api.example.test:8443/content/declared
assert_h2_status http2-unsupported.txt 415
grep -Fq 'unsupported_media_type' "$stage_dir/http2-unsupported.txt"
assert_h2_header http2-unsupported.txt accept \
  'application/json, application/problem+json'
assert_h2_header http2-unsupported.txt access-control-allow-origin \
  https://app.example.com

h2_request http2-malformed.txt -m POST -T 'application/json;' -d x \
  https://api.example.test:8443/content/declared
assert_h2_status http2-malformed.txt 400
grep -Fq 'invalid_content_type' "$stage_dir/http2-malformed.txt"

h2_request http2-type-only.txt -m POST -T application/json -d 123456789 \
  https://api.example.test:8443/content/type-only
assert_h2_status http2-type-only.txt 200
grep -Fq '123456789' "$stage_dir/http2-type-only.txt"

if h2_request http2-content-length-mismatch.txt -m POST -T application/json \
  -H "content-length: 8" -d 123456789 \
  https://api.example.test:8443/content/type-only; then
  echo "HTTP/2 Content-Length mismatch did not reset the malformed stream" >&2
  exit 1
fi
grep -Fq 'Error: http2 error' "$stage_dir/http2-content-length-mismatch.txt"
if grep -Eiq 'status[^0-9]*413|request_body_too_large' \
  "$stage_dir/http2-content-length-mismatch.txt"; then
  echo "HTTP/2 Content-Length mismatch was misclassified as route overage" >&2
  exit 1
fi

h2_request http2-preflight.txt -m OPTIONS \
  -H "origin: https://app.example.com" \
  -H "access-control-request-method: POST" \
  -H "access-control-request-headers: Content-Type" \
  https://api.example.test:8443/content/declared
assert_h2_status http2-preflight.txt 204
assert_h2_header http2-preflight.txt access-control-allow-methods POST

h2_request http2-auth-order-content.txt -m POST -T text/plain -d x \
  https://api.example.test:8443/content/auth-order
assert_h2_status http2-auth-order-content.txt 415
grep -Fq 'unsupported_media_type' "$stage_dir/http2-auth-order-content.txt"

h2_request http2-auth-order-auth.txt -m POST -T application/json -d x \
  https://api.example.test:8443/content/auth-order
assert_h2_status http2-auth-order-auth.txt 401
grep -Fq 'unauthorized' "$stage_dir/http2-auth-order-auth.txt"

h2_request http2-recovery.txt https://api.example.test:8443/public
assert_h2_status http2-recovery.txt 200
grep -Fq 'public ready' "$stage_dir/http2-recovery.txt"

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-request-content-gateway-'"$suffix"':9090/metrics", timeout=10
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$upstream" python -c '
import urllib.request
metrics = urllib.request.urlopen(
    "http://bonvoyage-request-content-gateway-'"$suffix"':9090/metrics", timeout=10
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
assert total("request_content_policy_allows_total") == 11
assert total("request_content_type_rejections_total") == 9
assert total("request_body_limit_rejections_total") == 4
assert total("cors_actual_allows_total") == 2
assert total("cors_preflight_successes_total") == 1
assert total("cors_rejections_total") == 0
assert total("api_key_auth_rejections_total") == 1
assert total("active_upstream_requests") == 0
print("request-content metrics and final gauges passed")
' >"$stage_dir/metrics-validation.txt"

docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1
docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1
test "$(grep -Fc 'POST /content/declared HTTP/1.1" 200' "$stage_dir/upstream.log")" -eq 4
test "$(grep -Fc 'POST /content/size-only HTTP/1.1" 200' "$stage_dir/upstream.log")" -eq 1
test "$(grep -Fc 'POST /content/type-only HTTP/1.1" 200' "$stage_dir/upstream.log")" -eq 3
if grep -Fq '/content/fixed' "$stage_dir/upstream.log" || \
   grep -Fq '/content/auth-order' "$stage_dir/upstream.log"; then
  echo "locally handled route reached the controlled upstream" >&2
  exit 1
fi
for log_file in "$stage_dir/gateway.log" "$stage_dir/upstream.log"; do
  if grep -Fq "$api_key" "$log_file"; then
    echo "ephemeral API key appeared in retained logs" >&2
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
route_maximum_body_bytes=8
global_maximum_body_bytes=64
maximum_configured_content_types=16
maximum_configured_content_type_bytes=128
maximum_wire_content_type_bytes=1024
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 bounded request-content policy evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway enforced exact route body limits and Content-Type allowlists over HTTP/1.1 and TLS HTTP/2. It accepted exact boundaries and legal parameters, rejected declared and chunked overages, rejected missing, unsupported, malformed, repeated, and oversized Content-Type fields, preserved validated CORS fields on gateway errors, evaluated content policy before API-key authentication, bypassed content policy for preflight, and recovered without a restart. Exact metrics and controlled-upstream logs verify policy ownership and rejection order.

This is a correctness and security-boundary record. It does not qualify browser interoperability, decompression policy, payload inspection, multi-shard performance, production throughput, or publishable claims.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
.github/workflows/ci.yml
Makefile
README.md
api/gen/go/bonvoyage/v1/config.pb.go
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
control-plane/internal/snapshot/snapshot_test.go
dataplane/CMakeLists.txt
dataplane/include/bonvoyage/runtime/request_content_policy.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/gateway.cc
dataplane/src/request_content_policy.cc
dataplane/src/runtime_snapshot.cc
dataplane/tests/request_content_policy_test.cc
dataplane/tests/runtime_snapshot_test.cc
deploy/docker/bonvoyage/Dockerfile
deploy/docker/upstream/server.py
docs/architecture/config-snapshots.md
docs/architecture/decisions/0022-bounded-route-request-content-policy.md
docs/architecture/request-lifecycle.md
docs/architecture/security-model.md
docs/architecture/system-model.md
docs/implementation/development-evidence-lineage.md
docs/implementation/phase-3-request-content-policy.md
docs/implementation/phases-and-milestones.md
docs/index.md
docs/requirements/feature-matrix.md
docs/requirements/product-requirements.md
docs/research/simulation-test-catalog.md
docs/research/use-case-development-traceability.md
docs/security/threat-model.md
scripts/build-dataplane-sanitized.sh
scripts/phase3-request-content-client.py
scripts/phase3-request-content-smoke.sh
scripts/test-fixture-secrets.sh
tests/fixtures/phase3-request-content.yaml
website/sidebars.js
EOF
while IFS= read -r source_file; do hash_file "$source_file"; done \
  <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md compiler.txt gateway.inspect.json gateway.log \
    http1-results.json http2-auth-order-auth.txt \
    http2-auth-order-content.txt http2-body-too-large.txt \
    http2-content-length-mismatch.txt http2-content-type-required.txt \
    http2-declared-too-large.txt http2-declared-valid.txt \
    http2-malformed.txt http2-preflight.txt \
    http2-recovery.txt http2-type-only.txt http2-unsupported.txt \
    http2-valid.txt metadata.txt metrics-validation.txt metrics.prom \
    runtime-image.inspect.json source-checksums.sha256 upstream.log; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-request-content.txt.tmp"
mv "$output_root/current-request-content.txt.tmp" \
  "$output_root/current-request-content.txt"

printf 'request-content integration passed: %s\n' "$output_dir"
cat "$output_dir/http1-results.json"
cat "$output_dir/metrics-validation.txt"
