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
run_id="source-ip-policy-smoke-$timestamp"
suffix="$$"
network="bonvoyage-source-ip-policy-$suffix"
volume="bonvoyage-source-ip-policy-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-source-ip-policy-gateway-$suffix"
upstream="bonvoyage-source-ip-policy-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-source-ip-policy.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_SOURCE_IP_POLICY_EVIDENCE_ROOT:-benchmarks/results/verification}"
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
    echo "source IP policy smoke failed; temporary evidence: $stage_dir" >&2
    if [ -f "$stage_dir/gateway.log" ]; then
      sed -n '1,200p' "$stage_dir/gateway.log" >&2
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
  -subj "/CN=BonVoyage Source IP Policy Test CA" \
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

# The credential exists only to prove source policy executes before auth.
api_key="$(openssl rand -hex 16)"
printf '%s\n' "$api_key" >"$work_dir/phase3-source-api-keys.txt"
chmod 600 "$work_dir"/*-key.pem "$work_dir/phase3-source-api-keys.txt"

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem phase3-source-api-keys.txt

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-source-ip-policy.yaml:/etc/bonvoyage/source-ip-policy.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/source-ip-policy.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --volume "$work_dir:/tls:ro" \
  --volume "$PWD/scripts/phase3-source-ip-policy-client.py:/source-policy-client.py:ro" \
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

docker exec "$upstream" python /source-policy-client.py http1 \
  "bonvoyage-source-ip-policy-gateway-$suffix" \
  >"$stage_dir/http1-results.json"
docker exec "$upstream" python /source-policy-client.py http2 \
  "bonvoyage-source-ip-policy-gateway-$suffix" \
  >"$stage_dir/http2-results.json"

# Confirm the HTTP/2 rejection status independently without any credential.
docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
  --volume "$work_dir:/tls:ro" "$oha_image" \
  --debug --no-color --http-version 2 --disable-compression --no-tui -n 1 \
  -H "x-forwarded-for: 198.51.100.200" --cacert /tls/ca.pem \
  https://api.example.test:8443/api-key-observation \
  >"$stage_dir/http2-denied-response.txt" 2>&1
grep -Eiq 'status[^0-9]*403|403 Forbidden' \
  "$stage_dir/http2-denied-response.txt"
grep -Fq 'source_ip_denied' "$stage_dir/http2-denied-response.txt"

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-source-ip-policy-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$upstream" python -c '
import urllib.request

metrics = urllib.request.urlopen(
    "http://bonvoyage-source-ip-policy-gateway-'"$suffix"':9090/metrics",
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

assert total("source_ip_policy_allows_total") == 10
assert total("source_ip_policy_rejections_total") == 15
assert total("api_key_auth_successes_total") == 2
assert total("api_key_auth_rejections_total") == 2
assert total("trusted_proxy_client_ip_resolutions_total") == 24
assert total("forwarded_header_rejections_total") == 2
assert total("responses_4xx_total") == 19
assert total("upstream_failures_total") == 0
assert total("active_upstream_requests") == 0
print("source IP policy metrics and final gauges passed")
' >"$stage_dir/metrics-validation.txt"

docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1
docker logs "$upstream" >"$stage_dir/upstream.log" 2>&1

for log_file in "$stage_dir/gateway.log" "$stage_dir/upstream.log"; do
  if grep -Fq "$api_key" "$log_file"; then
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
maximum_combined_source_cidrs=64
trusted_proxy_cidr_count=3
protocols=http1,tls-http2
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 static source IP policy evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway enforced bounded IPv4 and IPv6 route policies over HTTP/1.1 and TLS HTTP/2. It proved allow-only default deny, deny-only default allow, narrower-deny precedence, fixed and proxied actions, execution before API-key authentication, public routes without policy, fail-closed malformed trusted chains, rejection of spoofed forwarding identity from an untrusted listener, safe close behavior for a rejected HTTP/1.1 request with an unread body, and fixed-cardinality counters. Retained output contains no credential or client-IP metric labels.

This is a correctness and security-boundary record. It does not qualify dynamic reputation lists, geolocation, control-plane policy distribution, policy cost, multi-shard behavior, production throughput, or publishable performance.
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
dataplane/include/bonvoyage/runtime/client_identity.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/client_identity.cc
dataplane/src/gateway.cc
dataplane/src/runtime_snapshot.cc
dataplane/tests/runtime_snapshot_test.cc
dataplane/tests/source_ip_policy_test.cc
deploy/docker/upstream/server.py
scripts/phase3-source-ip-policy-client.py
scripts/phase3-source-ip-policy-smoke.sh
scripts/test-fixture-secrets.sh
tests/fixtures/phase3-source-ip-policy.yaml
EOF
while IFS= read -r source_file; do
  hash_file "$source_file"
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md compiler.txt gateway.inspect.json \
    gateway.log http1-results.json http2-denied-response.txt \
    http2-results.json metadata.txt metrics-validation.txt metrics.prom \
    runtime-image.inspect.json source-checksums.sha256 upstream.log; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-source-ip-policy.txt.tmp"
mv "$output_root/current-source-ip-policy.txt.tmp" \
  "$output_root/current-source-ip-policy.txt"

printf 'Source IP policy integration passed: %s\n' "$output_dir"
cat "$output_dir/http1-results.json"
cat "$output_dir/http2-results.json"
cat "$output_dir/metrics-validation.txt"
