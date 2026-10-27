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
run_id="redirect-smoke-$timestamp"
suffix="$$"
network="bonvoyage-redirect-$suffix"
volume="bonvoyage-redirect-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-redirect-gateway-$suffix"
upstream="bonvoyage-redirect-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-redirect.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_REDIRECT_EVIDENCE_ROOT:-benchmarks/results/verification}"
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
    echo "redirect smoke failed; temporary evidence: $stage_dir" >&2
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
  -subj "/CN=BonVoyage Redirect Test CA" \
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
printf '%s\n' "$api_key" >"$work_dir/phase3-redirect-api-keys.txt"
chmod 600 "$work_dir"/*-key.pem "$work_dir/phase3-redirect-api-keys.txt"

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem phase3-redirect-api-keys.txt

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-redirect.yaml:/etc/bonvoyage/redirect.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/redirect.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --volume "$work_dir:/tls:ro" \
  --volume "$PWD/scripts/phase3-redirect-client.py:/redirect-client.py:ro" \
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

docker exec "$upstream" python /redirect-client.py \
  "bonvoyage-redirect-gateway-$suffix" "$api_key" \
  >"$stage_dir/http1-results.json"

h2_request http2-relative.txt -m POST -T application/json \
  -H "content-length: 8" -d 12345678 \
  https://api.example.test:8443/redirect/relative
assert_h2_status http2-relative.txt 307
assert_h2_header http2-relative.txt location '/v2/orders?source=legacy'
assert_h2_header http2-relative.txt content-length 0

h2_request http2-body-too-large.txt -m POST -T application/json \
  -H "content-length: 9" -d 123456789 \
  https://api.example.test:8443/redirect/relative
assert_h2_status http2-body-too-large.txt 413
grep -Fq request_body_too_large "$stage_dir/http2-body-too-large.txt"
assert_h2_no_header http2-body-too-large.txt location

h2_request http2-dns.txt https://api.example.test:8443/redirect/dns
assert_h2_status http2-dns.txt 308
assert_h2_header http2-dns.txt location \
  'https://api-v2.example.test:9443/v2/orders?source=legacy'

h2_request http2-ipv4.txt https://api.example.test:8443/redirect/ipv4
assert_h2_status http2-ipv4.txt 302
assert_h2_header http2-ipv4.txt location 'http://192.0.2.10:8080/moved'

h2_request http2-ipv6.txt https://api.example.test:8443/redirect/ipv6
assert_h2_status http2-ipv6.txt 301
assert_h2_header http2-ipv6.txt location \
  'https://[2001:db8::10]:9443/moved/%7Eowner'

h2_request http2-see-other.txt -m POST \
  https://api.example.test:8443/redirect/see-other
assert_h2_status http2-see-other.txt 303
assert_h2_header http2-see-other.txt location /result

h2_request http2-cors.txt -H "origin: https://app.example.com" \
  https://api.example.test:8443/redirect/cors
assert_h2_status http2-cors.txt 307
assert_h2_header http2-cors.txt location /v2/browser
assert_h2_header http2-cors.txt access-control-allow-origin \
  https://app.example.com

h2_request http2-preflight.txt -m OPTIONS \
  -H "origin: https://app.example.com" \
  -H "access-control-request-method: GET" \
  https://api.example.test:8443/redirect/cors
assert_h2_status http2-preflight.txt 204
assert_h2_no_header http2-preflight.txt location
assert_h2_header http2-preflight.txt access-control-allow-methods GET

h2_request http2-auth-missing.txt \
  https://api.example.test:8443/redirect/auth
assert_h2_status http2-auth-missing.txt 401
grep -Fq unauthorized "$stage_dir/http2-auth-missing.txt"
assert_h2_no_header http2-auth-missing.txt location

h2_request http2-auth-valid.txt -H "x-api-key: $api_key" \
  https://api.example.test:8443/redirect/auth
assert_h2_status http2-auth-valid.txt 308
assert_h2_header http2-auth-valid.txt location /v2/private

h2_request http2-fixed-301.txt https://api.example.test:8443/fixed/301
assert_h2_status http2-fixed-301.txt 301
grep -Fq 'fixed three hundred' "$stage_dir/http2-fixed-301.txt"
assert_h2_no_header http2-fixed-301.txt location

h2_request http2-recovery.txt https://api.example.test:8443/identity
assert_h2_status http2-recovery.txt 200

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-redirect-gateway-'"$suffix"':9090/metrics", timeout=10
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$upstream" python -c '
import urllib.request
metrics = urllib.request.urlopen(
    "http://bonvoyage-redirect-gateway-'"$suffix"':9090/metrics", timeout=10
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
assert total("requests_total") == 24
assert total("route_redirects_total") == 14
assert total("responses_2xx_total") == 4
assert total("responses_3xx_total") == 16
assert total("responses_4xx_total") == 4
assert total("responses_5xx_total") == 0
assert total("request_content_policy_allows_total") == 2
assert total("request_body_limit_rejections_total") == 2
assert total("cors_actual_allows_total") == 2
assert total("cors_preflight_successes_total") == 2
assert total("api_key_auth_successes_total") == 2
assert total("api_key_auth_rejections_total") == 2
assert total("upstream_endpoint_selections_total") == 2
assert total("route_misses_total") == 0
assert total("active_route_requests") == 0
assert total("active_upstream_requests") == 0
print("redirect metrics, 3xx classification, and final gauges passed")
' >"$stage_dir/metrics-validation.txt"

docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1
docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1
test "$(grep -Fc 'GET /identity HTTP/1.1" 200' "$stage_dir/upstream.log")" -eq 2
if grep -Fq '/redirect/' "$stage_dir/upstream.log" || \
   grep -Fq '/fixed/301' "$stage_dir/upstream.log"; then
  echo "a locally handled route reached the controlled upstream" >&2
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
redirect_statuses=301,302,303,307,308
maximum_path_bytes=4096
maximum_query_bytes=4096
maximum_location_bytes=8192
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 bounded static route redirect evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway returned prevalidated relative, DNS, IPv4, and IPv6 Locations with all five admitted redirect statuses over HTTP/1.1 and TLS HTTP/2. Route content, CORS, API-key, and admission ordering remained in force; a valid request body was consumed before HTTP/1.1 keep-alive reuse; rejected requests carried no Location; preflight remained a local 204; exact counters classify 3xx independently from 4xx; and controlled-upstream logs prove no redirect or fixed-response request selected an upstream. Both protocols recovered through the same process.

This is correctness, security-boundary, and local recovery evidence. It does not qualify browser or CDN interoperability, cache behavior, redirect-loop governance, dynamic activation, multi-shard performance, or publishable claims.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
.github/workflows/ci.yml
Makefile
api/gen/go/bonvoyage/v1/config.pb.go
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
control-plane/internal/snapshot/snapshot_test.go
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/gateway.cc
dataplane/src/runtime_snapshot.cc
dataplane/tests/runtime_snapshot_test.cc
docs/architecture/decisions/0023-bounded-static-route-redirects.md
scripts/phase3-redirect-client.py
scripts/phase3-redirect-smoke.sh
scripts/test-fixture-secrets.sh
tests/fixtures/phase3-redirect.yaml
EOF
while IFS= read -r source_file; do hash_file "$source_file"; done \
  <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md compiler.txt gateway.inspect.json gateway.log \
    http1-results.json http2-auth-missing.txt http2-auth-valid.txt \
    http2-body-too-large.txt http2-cors.txt http2-dns.txt \
    http2-fixed-301.txt http2-ipv4.txt http2-ipv6.txt \
    http2-preflight.txt http2-recovery.txt http2-relative.txt \
    http2-see-other.txt metadata.txt metrics-validation.txt metrics.prom \
    runtime-image.inspect.json source-checksums.sha256 upstream.log; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-redirect.txt.tmp"
mv "$output_root/current-redirect.txt.tmp" \
  "$output_root/current-redirect.txt"

printf 'redirect integration passed: %s\n' "$output_dir"
cat "$output_dir/http1-results.json"
cat "$output_dir/metrics-validation.txt"
