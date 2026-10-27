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
run_id="jwt-smoke-$timestamp"
suffix="$$"
network="bonvoyage-jwt-$suffix"
volume="bonvoyage-jwt-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-jwt-gateway-$suffix"
invalid_gateway="bonvoyage-jwt-invalid-$suffix"
upstream="bonvoyage-jwt-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-jwt.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_JWT_EVIDENCE_ROOT:-benchmarks/results/verification}"
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
    echo "JWT smoke failed; temporary evidence: $stage_dir" >&2
    if [ -f "$stage_dir/gateway.log" ]; then
      sed -n '1,160p' "$stage_dir/gateway.log" >&2
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

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage JWT Test CA" \
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
python3 scripts/generate-jwt-smoke-material.py "$work_dir"
chmod 600 "$work_dir"/*-key.pem "$work_dir/phase3-jwks.json" \
  "$work_dir/jwt-tokens.json"

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem phase3-jwks.json

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-jwt.yaml:/etc/bonvoyage/jwt.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/jwt.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --volume "$work_dir:/tls:ro" \
  --volume "$PWD/scripts/phase3-jwt-client.py:/jwt-client.py:ro" \
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

docker exec "$upstream" python /jwt-client.py http1 \
  "bonvoyage-jwt-gateway-$suffix" >"$stage_dir/http1-results.json"
docker exec "$upstream" python /jwt-client.py http2 \
  "bonvoyage-jwt-gateway-$suffix" >"$stage_dir/http2-results.json"

# Validate the HTTP/2 status and challenge without placing a token in output.
docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  --debug --no-color --http-version 2 --disable-compression --no-tui -n 1 \
  --cacert /tls/ca.pem \
  https://api.example.test:8443/protected-fixed \
  >"$stage_dir/http2-missing-response.txt" 2>&1
grep -Eiq 'status[^0-9]*401|401 Unauthorized' \
  "$stage_dir/http2-missing-response.txt"
grep -Eiq 'www-authenticate[^A-Za-z]+Bearer' \
  "$stage_dir/http2-missing-response.txt"

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-jwt-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$upstream" python -c '
import urllib.request

metrics = urllib.request.urlopen(
    "http://bonvoyage-jwt-gateway-'"$suffix"':9090/metrics", timeout=10
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

assert total("jwt_auth_successes_total") == 4
assert total("jwt_auth_rejections_total") == 40
assert total("jwt_authorization_rejections_total") == 6
assert total("jwt_verification_overload_rejections_total") == 1
assert total("responses_4xx_total") == 46
assert total("responses_5xx_total") == 1
assert total("upstream_failures_total") == 0
assert total("active_upstream_requests") == 0
print("JWT metrics and final gauges passed")
' >"$stage_dir/metrics-validation.txt"

docker stop --signal TERM --time 15 "$gateway" >/dev/null
gateway_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
test "$gateway_exit_code" -eq 0

docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1
docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1

# An empty JWKS must terminate startup before any downstream listener opens.
printf '%s\n' '{"keys":[]}' >"$work_dir/phase3-jwks.json"
bv_stage_fixture_secrets --refresh "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem phase3-jwks.json
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
    echo "gateway remained running with an invalid JWT JWKS" >&2
    exit 1
  fi
  sleep 0.1
done
invalid_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$invalid_gateway")"
test "$invalid_exit_code" -ne 0
docker logs "$invalid_gateway" >"$stage_dir/invalid-startup.log" 2>&1
printf 'invalid_jwks_exit_code=%s\ndownstream_listener_started=false\n' \
  "$invalid_exit_code" >"$stage_dir/startup-validation.txt"

python3 -c '
import json
import pathlib
import sys

tokens = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="ascii"))
for log_name in sys.argv[2:]:
    content = pathlib.Path(log_name).read_text(encoding="utf-8", errors="replace")
    for name, token in tokens.items():
        if token in content:
            raise SystemExit(f"ephemeral JWT {name} appeared in {log_name}")
' "$work_dir/jwt-tokens.json" "$stage_dir/gateway.log" \
  "$stage_dir/invalid-startup.log" "$stage_dir/upstream.log"

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
algorithms_exercised=RS256
jwks_key_count=1
token_maximum_bytes=8192
jwks_maximum_bytes=65536
verification_budget_capacity=2
verification_budget_refill_per_second=1
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 shard-local JWT validation evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway protected fixed and proxied routes over HTTP/1.1 and TLS HTTP/2. It accepted a locally signed RS256 token; rejected malformed signatures, duplicate JSON members, embedded-NUL values, token-controlled key references, and base-claim failures as one non-revealing 401 class; rejected authenticated scope/claim failures as one 403 class; removed Authorization before proxying; preserved an unrelated request header; left an unprotected route accessible; bounded known-key bad-signature work with a shard-local verification budget; recovered after refill without restart; exposed fixed-cardinality counters; and refused startup with an empty JWKS. Retained logs contain no token value.

This is a correctness and security-boundary record. It does not qualify remote JWKS retrieval, control-plane rotation, multi-shard behavior, production throughput, or publishable feature cost.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
.github/workflows/ci.yml
Makefile
api/gen/go/bonvoyage/v1/config.pb.go
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
dataplane/CMakeLists.txt
dataplane/include/bonvoyage/runtime/jwt_auth.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/gateway.cc
dataplane/src/jwt_auth.cc
dataplane/src/runtime_snapshot.cc
dataplane/tests/jwt_auth_test.cc
dataplane/tests/runtime_snapshot_test.cc
deploy/docker/bonvoyage/Dockerfile
deploy/docker/bonvoyage/patches/libjwt-jwks-reject-duplicates.patch
deploy/docker/upstream/server.py
scripts/generate-jwt-smoke-material.py
scripts/phase3-jwt-client.py
scripts/phase3-jwt-smoke.sh
scripts/test-fixture-secrets.sh
scripts/build-dataplane-sanitized.sh
scripts/qualify-runtime-dependencies.sh
security/dependencies/libjwt-3.6.1.json
tests/fixtures/phase3-jwt.yaml
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
printf '%s\n' "$run_id" >"$output_root/current-jwt-smoke.txt.tmp"
mv "$output_root/current-jwt-smoke.txt.tmp" \
  "$output_root/current-jwt-smoke.txt"

printf 'JWT authentication integration passed: %s\n' "$output_dir"
cat "$output_dir/http1-results.json"
cat "$output_dir/http2-results.json"
cat "$output_dir/metrics-validation.txt"
cat "$output_dir/startup-validation.txt"
