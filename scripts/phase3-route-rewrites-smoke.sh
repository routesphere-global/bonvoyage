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
run_id="route-rewrites-smoke-$timestamp"
suffix="$$"
network="bonvoyage-route-rewrites-$suffix"
volume="bonvoyage-route-rewrites-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-route-rewrites-gateway-$suffix"
upstream="bonvoyage-route-rewrites-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-route-rewrites.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_ROUTE_REWRITES_EVIDENCE_ROOT:-benchmarks/results/verification}"
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
    echo "route rewrite smoke failed; temporary evidence: $stage_dir" >&2
    sed -n '1,240p' "$stage_dir/gateway.log" >&2 || true
    sed -n '1,240p' "$stage_dir/upstream.log" >&2 || true
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

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage Route Rewrite Test CA" \
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
printf '%s\n' "$api_key" >"$work_dir/phase3-route-rewrites-api-keys.txt"
chmod 600 "$work_dir"/*-key.pem \
  "$work_dir/phase3-route-rewrites-api-keys.txt"

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem phase3-route-rewrites-api-keys.txt

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-route-rewrites.yaml:/etc/bonvoyage/route-rewrites.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/route-rewrites.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --entrypoint python \
  --volume "$PWD/scripts/phase3-route-rewrites-upstream.py:/route-rewrites-upstream.py:ro" \
  --volume "$PWD/scripts/phase3-route-rewrites-client.py:/route-rewrites-client.py:ro" \
  "$upstream_image" /route-rewrites-upstream.py >/dev/null

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

docker exec "$upstream" python /route-rewrites-client.py \
  "bonvoyage-route-rewrites-gateway-$suffix" "$api_key" \
  >"$stage_dir/http1-results.json"

h2_request http2-main.txt \
  -H "x-api-key: $api_key" \
  -H "origin: https://app.example.com" \
  -H "x-client-protocol: h2" \
  -H "x-forwarded-host: spoofed.example" \
  'https://api.example.test:8443/legacy/orders/%2Fopen?cursor=a%2Fb'
assert_h2_status http2-main.txt 200

h2_request http2-auth-missing.txt \
  -H "x-client-protocol: h2" \
  -H "x-forwarded-host: spoofed.example" \
  'https://api.example.test:8443/legacy/orders/%2Fopen?cursor=a%2Fb'
assert_h2_status http2-auth-missing.txt 401
grep -Fq unauthorized "$stage_dir/http2-auth-missing.txt"

h2_request http2-catalog.txt \
  -H "x-client-protocol: h2" \
  -H "x-forwarded-host: spoofed.example" \
  'https://api.example.test:8443/catalog?view=%2Fraw&empty='
assert_h2_status http2-catalog.txt 200

h2_request http2-authority.txt \
  -H "x-client-protocol: h2" \
  -H "x-forwarded-host: spoofed.example" \
  'https://api.example.test:8443/authority?mode=raw'
assert_h2_status http2-authority.txt 200

h2_request http2-plain.txt \
  -H "x-client-protocol: h2" \
  -H "x-forwarded-host: spoofed.example" \
  'https://api.example.test:8443/plain?keep=%2Fraw'
assert_h2_status http2-plain.txt 200

h2_request http2-retry.txt \
  -H "x-client-protocol: h2" \
  -H "x-forwarded-host: spoofed.example" \
  'https://api.example.test:8443/retry?attempt=stable'
assert_h2_status http2-retry.txt 200

limit_query="$(python3 -c 'print("q" * 300)')"
h2_request http2-limit.txt \
  -H "x-client-protocol: h2" \
  -H "x-forwarded-host: spoofed.example" \
  "https://api.example.test:8443/limit?padding=$limit_query"
assert_h2_status http2-limit.txt 414
grep -Fq rewritten_request_target_too_large "$stage_dir/http2-limit.txt"

h2_request http2-recovery.txt \
  -H "x-client-protocol: h2" \
  -H "x-forwarded-host: spoofed.example" \
  'https://api.example.test:8443/plain?after=limit'
assert_h2_status http2-recovery.txt 200

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-route-rewrites-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$upstream" python -c '
import urllib.request
metrics = urllib.request.urlopen(
    "http://bonvoyage-route-rewrites-gateway-'"$suffix"':9090/metrics",
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
assert total("requests_total") == 16
assert total("responses_2xx_total") == 12
assert total("responses_4xx_total") == 4
assert total("responses_5xx_total") == 0
assert total("api_key_auth_successes_total") == 2
assert total("api_key_auth_rejections_total") == 2
assert total("cors_actual_allows_total") == 2
assert total("request_header_transformation_applications_total") == 2
assert total("request_authority_rewrite_applications_total") == 8
assert total("request_path_rewrite_applications_total") == 8
assert total("request_rewrite_limit_rejections_total") == 2
assert total("retry_attempts_total") == 2
assert total("retry_successes_total") == 2
assert total("upstream_endpoint_selections_total") == 14
assert total("upstream_failures_total") == 0
assert total("route_misses_total") == 0
assert total("active_route_requests") == 0
assert total("active_upstream_requests") == 0
assert total("active_retries") == 0
print("route rewrite metrics and final gauges passed")
' >"$stage_dir/metrics-validation.txt"

docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1
docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1

python3 - "$stage_dir/upstream.log" \
  >"$stage_dir/upstream-validation.txt" <<'PY'
import json
import sys
from collections import Counter

records = []
for line in open(sys.argv[1], encoding="utf-8"):
    if line.startswith("REQUEST "):
        records.append(json.loads(line.removeprefix("REQUEST ")))
assert len(records) == 14, records

for protocol in ("h1", "h2"):
    selected = [
        record for record in records
        if record["headers"].get("x-client-protocol") == protocol
    ]
    assert len(selected) == 7, selected
    paths = Counter(record["path"] for record in selected)
    main_path = (
        "/v2/orders/%7Eopen?cursor=a%2Fb"
        if protocol == "h1"
        else "/v2/orders/%2Fopen?cursor=a%2Fb"
    )
    original_authority = (
        "api.example.test" if protocol == "h1" else "api.example.test:8443"
    )
    assert paths == Counter({
        main_path: 1,
        "/internal/catalog?view=%2Fraw&empty=": 1,
        "/authority?mode=raw": 1,
        "/plain?keep=%2Fraw": 1,
        "/internal/retry?attempt=stable": 2,
        "/plain?after=limit": 1,
    }), paths

    for record in selected:
        headers = record["headers"]
        assert "x-api-key" not in headers
        assert headers["x-forwarded-proto"] == (
            "http" if protocol == "h1" else "https"
        )
        if record["path"] == main_path:
            assert headers["host"] == "orders.internal.test:9443"
            assert headers["x-forwarded-host"] == original_authority
            assert headers["x-route-tier"] == "gold"
        elif record["path"] == "/authority?mode=raw":
            assert headers["host"] == "authority.internal.test:8088"
            assert headers["x-forwarded-host"] == original_authority
        elif record["path"] == "/internal/retry?attempt=stable":
            assert headers["host"] == "retry.internal.test"
            assert headers["x-forwarded-host"] == original_authority
        else:
            assert headers["host"] == original_authority
            assert "x-forwarded-host" not in headers

assert not any(record["path"].startswith("/limit") for record in records)
assert not any("spoofed.example" in record["headers"].values() for record in records)
print("controlled upstream observed exact rewrite, retry, isolation, and recovery behavior")
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
rewrite_forms=authority,full-path,matched-prefix
raw_query_preserved=true
runtime_request_header_limit_bytes=1024
rewritten_target_limit_status=414
observed_limit_rejections=2
retry_attempts=2
post_rejection_recovery_requests=2
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<'EOF'
# Phase 3 bounded route rewrite evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway applied immutable authority, full-path, and matched-prefix rewrites over HTTP/1.1 and TLS HTTP/2. Matching, API-key authentication, and CORS completed against the original request; request-header transformation then composed with the prepared rewrite. Raw query bytes and unmatched prefix suffixes were preserved, spoofed forwarding identity was removed, and authority rewrites synthesized the validated original authority as `X-Forwarded-Host`. Retry attempts rebuilt the same rewritten authority and target. Targets expanded beyond the configured 1,024-byte bound returned `414` before upstream selection, and later requests succeeded without a process restart. An unconfigured route retained its original authority and target.

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
dataplane/include/bonvoyage/http/http1_validation.hh
dataplane/include/bonvoyage/runtime/route_rewrite.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/gateway.cc
dataplane/src/http1_validation.cc
dataplane/src/http2_request_validation.cc
dataplane/src/route_rewrite.cc
dataplane/src/runtime_snapshot.cc
dataplane/tests/http2_request_validation_test.cc
dataplane/tests/route_rewrite_test.cc
dataplane/tests/runtime_snapshot_test.cc
docs/architecture/decisions/0025-bounded-route-host-path-rewrites.md
scripts/phase3-route-rewrites-client.py
scripts/phase3-route-rewrites-smoke.sh
scripts/test-fixture-secrets.sh
scripts/phase3-route-rewrites-upstream.py
tests/fixtures/phase3-route-rewrites.yaml
EOF
while IFS= read -r source_file; do hash_file "$source_file"; done \
  <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md compiler.txt gateway.inspect.json gateway.log \
    http1-results.json http2-auth-missing.txt http2-authority.txt \
    http2-catalog.txt http2-limit.txt http2-main.txt http2-plain.txt \
    http2-recovery.txt http2-retry.txt metadata.txt metrics-validation.txt \
    metrics.prom runtime-image.inspect.json source-checksums.sha256 \
    upstream.log upstream-validation.txt; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-route-rewrites.txt.tmp"
mv "$output_root/current-route-rewrites.txt.tmp" \
  "$output_root/current-route-rewrites.txt"

printf 'route rewrite integration passed: %s\n' "$output_dir"
cat "$output_dir/http1-results.json"
cat "$output_dir/metrics-validation.txt"
cat "$output_dir/upstream-validation.txt"
