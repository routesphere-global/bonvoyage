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
run_id="cors-smoke-$timestamp"
suffix="$$"
network="bonvoyage-cors-$suffix"
volume="bonvoyage-cors-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-cors-gateway-$suffix"
upstream="bonvoyage-cors-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-cors.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_CORS_EVIDENCE_ROOT:-benchmarks/results/verification}"
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
    echo "CORS smoke failed; temporary evidence: $stage_dir" >&2
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
    grep -Eiq "$name:[[:space:]]*$value" "$stage_dir/$file"
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage CORS Test CA" \
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
printf '%s\n' "$api_key" >"$work_dir/phase3-cors-api-keys.txt"
chmod 600 "$work_dir"/*-key.pem "$work_dir/phase3-cors-api-keys.txt"

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem phase3-cors-api-keys.txt

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-cors.yaml:/etc/bonvoyage/cors.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/cors.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --volume "$work_dir:/tls:ro" \
  --volume "$PWD/scripts/phase3-cors-client.py:/cors-client.py:ro" \
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
  --env ASAN_OPTIONS=halt_on_error=1:abort_on_error=1 \
  --env UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$image" \
  --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 256M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug >/dev/null

bv_wait_gateway_ready "$gateway" "$upstream" "http://$gateway:9901/health/ready"

docker exec "$upstream" python /cors-client.py \
  "bonvoyage-cors-gateway-$suffix" >"$stage_dir/http1-results.json"

h2_request http2-actual.txt \
  -H "origin: https://app.example.com" \
  https://api.example.test:8443/cors/fixed
assert_h2_status http2-actual.txt 200
assert_h2_header http2-actual.txt access-control-allow-origin \
  https://app.example.com
assert_h2_header http2-actual.txt access-control-allow-credentials true

h2_request http2-preflight.txt -m OPTIONS \
  -H "origin: https://app.example.com" \
  -H "access-control-request-method: POST" \
  -H "access-control-request-headers: Authorization, X-Request-Id" \
  https://api.example.test:8443/cors-observation
assert_h2_status http2-preflight.txt 204
assert_h2_header http2-preflight.txt access-control-allow-methods 'GET, POST'
assert_h2_header http2-preflight.txt access-control-max-age 600

h2_request http2-origin-denied.txt \
  -H "origin: https://denied.example.com" \
  https://api.example.test:8443/cors/fixed
assert_h2_status http2-origin-denied.txt 403
grep -Fq 'cors_origin_denied' "$stage_dir/http2-origin-denied.txt"

h2_request http2-headers-denied.txt -m OPTIONS \
  -H "origin: https://app.example.com" \
  -H "access-control-request-method: POST" \
  -H "access-control-request-headers: X-Private" \
  https://api.example.test:8443/cors-observation
assert_h2_status http2-headers-denied.txt 403
grep -Fq 'cors_headers_denied' "$stage_dir/http2-headers-denied.txt"

h2_request http2-auth-preflight.txt -m OPTIONS \
  -H "origin: https://app.example.com" \
  -H "access-control-request-method: GET" \
  https://api.example.test:8443/cors/auth
assert_h2_status http2-auth-preflight.txt 204

h2_request http2-auth-error.txt \
  -H "origin: https://app.example.com" \
  https://api.example.test:8443/cors/auth
assert_h2_status http2-auth-error.txt 401
grep -Fq 'unauthorized' "$stage_dir/http2-auth-error.txt"
assert_h2_header http2-auth-error.txt access-control-allow-origin \
  https://app.example.com

h2_request http2-upstream.txt \
  -H "origin: https://app.example.com" \
  https://api.example.test:8443/cors-observation
assert_h2_status http2-upstream.txt 200
assert_h2_header http2-upstream.txt access-control-allow-origin \
  https://app.example.com
if grep -Fq 'https://upstream.invalid' "$stage_dir/http2-upstream.txt" || \
   grep -Fq 'x-upstream-secret' "$stage_dir/http2-upstream.txt"; then
  echo "conflicting upstream CORS policy reached the HTTP/2 client" >&2
  exit 1
fi

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-cors-gateway-'"$suffix"':9090/metrics", timeout=10
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$upstream" python -c '
import urllib.request
metrics = urllib.request.urlopen(
    "http://bonvoyage-cors-gateway-'"$suffix"':9090/metrics", timeout=10
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
assert total("cors_actual_allows_total") == 19
assert total("cors_preflight_successes_total") == 4
assert total("cors_rejections_total") == 7
assert total("api_key_auth_rejections_total") == 2
assert total("upstream_failures_total") == 8
assert total("active_upstream_requests") == 0
print("CORS metrics and final gauges passed")
' >"$stage_dir/metrics-validation.txt"

docker stop --time 15 "$gateway" >"$stage_dir/shutdown.txt"
test "$(docker inspect --format '{{.State.ExitCode}}' "$gateway")" -eq 0
test "$(docker inspect --format '{{.RestartCount}}' "$gateway")" -eq 0
docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1
docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1
if grep -Eq 'ERROR: AddressSanitizer|runtime error:|LeakSanitizer' \
    "$stage_dir/gateway.log"; then
  echo "sanitizer diagnostic in CORS gateway log" >&2
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
gateway_exit_code=0
gateway_restart_count=0
protocols=http1,tls-http2
maximum_exact_origins=32
maximum_allowed_methods=16
maximum_allowed_or_exposed_headers=32
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 bounded CORS policy evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway enforced exact credentialed and wildcard non-credential CORS policies over HTTP/1.1 and TLS HTTP/2. It answered preflight locally before route authentication, applied method and request-field allowlists, rejected malformed requests and preflight bodies, attached policy fields to successful and gateway-error actual responses, stripped conflicting upstream Access-Control-* fields, preserved ordinary exposed response fields, and exported fixed-cardinality counters. HTTP/1 regressions verify CORS origins after eight upstream connection failures, cleared policy on malformed keep-alive follow-ups, and origin changes/removal on persistent connections. The gateway exited cleanly with no restart or sanitizer diagnostic.

This is a correctness and security-boundary record. It does not qualify browser-vendor interoperability, CDN cache behavior, multi-shard performance, production throughput, or publishable claims.
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
dataplane/include/bonvoyage/runtime/cors_policy.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/cors_policy.cc
dataplane/src/gateway.cc
dataplane/src/runtime_snapshot.cc
dataplane/tests/cors_policy_test.cc
dataplane/tests/listener_lifecycle_test.cc
dataplane/tests/runtime_snapshot_test.cc
deploy/docker/upstream/server.py
deploy/docker/bonvoyage/Dockerfile
docs/architecture/config-snapshots.md
docs/architecture/decisions/0021-bounded-route-level-cors.md
docs/architecture/request-lifecycle.md
docs/architecture/security-model.md
docs/architecture/system-model.md
docs/implementation/development-evidence-lineage.md
docs/implementation/phase-3-cors-policy.md
docs/implementation/phase-3-cors-lifetime-hardening.md
docs/implementation/phases-and-milestones.md
docs/index.md
docs/requirements/feature-matrix.md
docs/requirements/product-requirements.md
docs/research/simulation-test-catalog.md
docs/research/use-case-development-traceability.md
docs/security/threat-model.md
scripts/phase3-cors-client.py
scripts/phase3-cors-smoke.sh
scripts/test-fixture-secrets.sh
scripts/build-dataplane-sanitized.sh
tests/fixtures/phase3-cors.yaml
website/sidebars.js
EOF
while IFS= read -r source_file; do hash_file "$source_file"; done \
  <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md compiler.txt gateway.inspect.json gateway.log \
    http1-results.json http2-actual.txt http2-auth-error.txt \
    http2-auth-preflight.txt http2-headers-denied.txt \
    http2-origin-denied.txt http2-preflight.txt http2-upstream.txt \
    metadata.txt metrics-validation.txt metrics.prom \
    runtime-image.inspect.json shutdown.txt source-checksums.sha256 upstream.log; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-cors.txt.tmp"
mv "$output_root/current-cors.txt.tmp" "$output_root/current-cors.txt"

printf 'CORS integration passed: %s\n' "$output_dir"
cat "$output_dir/http1-results.json"
cat "$output_dir/metrics-validation.txt"
