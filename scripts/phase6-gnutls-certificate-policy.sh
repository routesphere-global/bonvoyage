#!/bin/sh
set -eu

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
builder_image="${BONVOYAGE_BUILDER_IMAGE:-bonvoyage-build:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
evidence_dir="${BONVOYAGE_GNUTLS_POLICY_EVIDENCE_DIR:-}"
suffix="$$"
network="bonvoyage-gnutls-policy-$suffix"
volume="bonvoyage-gnutls-policy-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-gnutls-policy-gateway-$suffix"
constrained_gateway="bonvoyage-gnutls-constrained-gateway-$suffix"
malformed_trust_gateway="bonvoyage-gnutls-malformed-trust-gateway-$suffix"
valid_upstream="bonvoyage-gnutls-valid-$suffix"
cn_upstream="bonvoyage-gnutls-cn-$suffix"
zero_usage_upstream="bonvoyage-gnutls-zero-usage-$suffix"
malformed_usage_upstream="bonvoyage-gnutls-malformed-usage-$suffix"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-gnutls-policy.XXXXXX")"

cleanup() {
  status="$?"
  if [ "$status" -ne 0 ] && [ -n "$evidence_dir" ]; then
    printf 'exit_status=%s\n' "$status" >"$evidence_dir/failed-attempt.env"
    if [ -f "$fixture_dir/traffic-matrix.json" ]; then
      cp "$fixture_dir/traffic-matrix.json" \
        "$evidence_dir/failed-traffic-matrix.json"
    fi
    for container in "$gateway" "$constrained_gateway" "$malformed_trust_gateway" \
      "$valid_upstream" \
      "$cn_upstream" "$zero_usage_upstream" "$malformed_usage_upstream"; do
      if docker inspect "$container" >/dev/null 2>&1; then
        docker logs "$container" >"$evidence_dir/failed-$container.log" 2>&1 || true
        docker inspect "$container" \
          >"$evidence_dir/failed-$container.inspect.json" 2>&1 || true
      fi
    done
  fi
  if [ "$status" -ne 0 ] && docker inspect "$gateway" >/dev/null 2>&1; then
    docker logs "$gateway" >&2 || true
  fi
  docker rm --force "$gateway" "$constrained_gateway" "$malformed_trust_gateway" \
    "$valid_upstream" \
    "$cn_upstream" "$zero_usage_upstream" "$malformed_usage_upstream" \
    >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$fixture_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  rm -rf "$fixture_dir"
  exit "$status"
}
trap cleanup EXIT INT TERM

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required for ephemeral certificate fixtures" >&2
  exit 1
}

if [ -n "$evidence_dir" ]; then
  mkdir -p "$evidence_dir"
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage Certificate Policy CA" \
  -keyout "$fixture_dir/policy-ca-key.pem" \
  -out "$fixture_dir/policy-ca.pem" >/dev/null 2>&1

issue_certificate() {
  name="$1"
  common_name="$2"
  extensions="$3"
  openssl req -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=$common_name" \
    -keyout "$fixture_dir/$name-key.pem" \
    -out "$fixture_dir/$name.csr" >/dev/null 2>&1
  openssl x509 -req -days 1 -sha256 -in "$fixture_dir/$name.csr" \
    -CA "$fixture_dir/policy-ca.pem" \
    -CAkey "$fixture_dir/policy-ca-key.pem" \
    -CAcreateserial -extfile "$extensions" \
    -out "$fixture_dir/$name.pem" >/dev/null 2>&1
}

printf '%s\n' \
  "subjectAltName=DNS:valid.example.test" \
  "extendedKeyUsage=serverAuth" \
  "keyUsage=critical,digitalSignature,keyEncipherment" \
  >"$fixture_dir/valid.cnf"
issue_certificate valid valid.example.test "$fixture_dir/valid.cnf"

printf '%s\n' \
  "extendedKeyUsage=serverAuth" \
  "keyUsage=critical,digitalSignature,keyEncipherment" \
  >"$fixture_dir/cn-only.cnf"
issue_certificate cn-only cn-only.example.test "$fixture_dir/cn-only.cnf"

printf '%s\n' \
  "subjectAltName=DNS:zero-key-usage.example.test" \
  "extendedKeyUsage=serverAuth" \
  "2.5.29.15=critical,DER:03:01:00" \
  >"$fixture_dir/zero-key-usage.cnf"
issue_certificate zero-key-usage zero-key-usage.example.test \
  "$fixture_dir/zero-key-usage.cnf"

printf '%s\n' \
  "subjectAltName=DNS:malformed-key-usage.example.test" \
  "extendedKeyUsage=serverAuth" \
  "2.5.29.15=critical,DER:05:00" \
  >"$fixture_dir/malformed-key-usage.cnf"
issue_certificate malformed-key-usage malformed-key-usage.example.test \
  "$fixture_dir/malformed-key-usage.cnf"

printf '%s\n' \
  "[req]" \
  "prompt = no" \
  "distinguished_name = dn" \
  "x509_extensions = v3_ca" \
  "[dn]" \
  "CN = BonVoyage Constrained Policy CA" \
  "O = Root" \
  "[v3_ca]" \
  "basicConstraints = critical,CA:true" \
  "keyUsage = critical,keyCertSign,cRLSign" \
  "subjectKeyIdentifier = hash" \
  "authorityKeyIdentifier = keyid:always" \
  "nameConstraints = critical,permitted;dirName:permitted_dn" \
  "[permitted_dn]" \
  "O = Good" \
  >"$fixture_dir/constrained-ca.cnf"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -config "$fixture_dir/constrained-ca.cnf" \
  -keyout "$fixture_dir/constrained-ca-key.pem" \
  -out "$fixture_dir/constrained-ca.pem" >/dev/null 2>&1

printf '%s\n' \
  "-----BEGIN CERTIFICATE-----" \
  "not-a-valid-certificate" \
  "-----END CERTIFICATE-----" \
  >"$fixture_dir/malformed-ca.pem"

chmod 600 "$fixture_dir"/*-key.pem

docker image inspect "$compiler_image" >/dev/null 2>&1 || \
  docker buildx build --platform "$platform" --load --tag "$compiler_image" \
    --file deploy/docker/control-plane/Dockerfile .
docker image inspect "$upstream_image" >/dev/null 2>&1 || \
  docker buildx build --platform "$platform" --load --tag "$upstream_image" \
    --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker image inspect "$builder_image" >/dev/null 2>&1 || {
  echo "missing required dataplane builder image: $builder_image" >&2
  exit 1
}

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/gnutls-policy-upstream.c:/src/gnutls-policy-upstream.c:ro" \
  --volume "$fixture_dir:/out" \
  "$builder_image" sh -lc \
  'cc -std=c11 -O2 -Wall -Wextra -Werror /src/gnutls-policy-upstream.c \
    -o /out/gnutls-policy-upstream $(pkg-config --cflags --libs gnutls)'

docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$fixture_dir" "$upstream_image" "$platform" \
  policy-ca.pem constrained-ca.pem malformed-ca.pem

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase6-gnutls-certificate-policy.yaml:/etc/bonvoyage/input.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/input.yaml \
  -output /var/lib/bonvoyage/policy.pb >/dev/null
docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase6-gnutls-constrained-trust.yaml:/etc/bonvoyage/input.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/input.yaml \
  -output /var/lib/bonvoyage/constrained.pb >/dev/null
docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase6-gnutls-malformed-trust.yaml:/etc/bonvoyage/input.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/input.yaml \
  -output /var/lib/bonvoyage/malformed.pb >/dev/null

start_upstream() {
  container="$1"
  alias="$2"
  certificate="$3"
  private_key="$4"
  docker run --detach --platform "$platform" --name "$container" \
    --network "$network" --network-alias "$alias" \
    --volume "$fixture_dir:/tls:ro" \
    --env "BONVOYAGE_UPSTREAM_TLS_CERTIFICATE=/tls/$certificate" \
    --env "BONVOYAGE_UPSTREAM_TLS_PRIVATE_KEY=/tls/$private_key" \
    "$upstream_image" >/dev/null
}

start_gnutls_upstream() {
  container="$1"
  alias="$2"
  certificate="$3"
  private_key="$4"
  docker run --detach --platform "$platform" --name "$container" \
    --network "$network" --network-alias "$alias" \
    --volume "$fixture_dir:/tls:ro" \
    "$builder_image" /tls/gnutls-policy-upstream \
    "/tls/$certificate" "/tls/$private_key" 8081 >/dev/null
}

start_upstream "$valid_upstream" valid.example.test valid.pem valid-key.pem
start_upstream "$cn_upstream" cn-only.example.test cn-only.pem cn-only-key.pem
start_gnutls_upstream "$zero_usage_upstream" zero-key-usage.example.test \
  zero-key-usage.pem zero-key-usage-key.pem
start_gnutls_upstream "$malformed_usage_upstream" malformed-key-usage.example.test \
  malformed-key-usage.pem malformed-key-usage-key.pem

docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias gateway \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
  "$image" --snapshot /snapshot/policy.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --runtime-log-transport stderr-pipe \
  --smp 1 --memory 256M --overprovisioned >/dev/null

bv_wait_gateway_ready "$gateway" "$valid_upstream" "http://gateway:9901/health/ready"

if ! docker exec "$valid_upstream" python -c '
import http.client
import json

def request(host):
    connection = http.client.HTTPConnection("gateway", 8080, timeout=10)
    connection.request("GET", "/payload/16", headers={"Host": host})
    response = connection.getresponse()
    body = response.read()
    connection.close()
    return response.status, body

results = {}
status, body = request("valid.client.example.test")
results["valid_dns_san"] = {"status": status, "body": body.decode("ascii")}

for name, host in (
    ("cn_only", "cn-only.client.example.test"),
    ("zero_key_usage", "zero-key-usage.client.example.test"),
    ("malformed_key_usage", "malformed-key-usage.client.example.test"),
):
    status, body = request(host)
    results[name] = {"status": status, "body": body.decode("ascii")}

print(json.dumps(results, indent=2, sort_keys=True))
assert results["valid_dns_san"] == {"status": 200, "body": "x" * 16}, results
for name in ("cn_only", "zero_key_usage", "malformed_key_usage"):
    assert results[name]["status"] == 502, results
    assert "upstream_failure" in results[name]["body"], results
' >"$fixture_dir/traffic-matrix.json"; then
  cat "$fixture_dir/traffic-matrix.json" >&2
  exit 1
fi

docker stop --signal TERM --time 15 "$gateway" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$gateway")" -eq 0

docker run --detach --platform "$platform" --name "$constrained_gateway" \
  --network "$network" \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
  "$image" --snapshot /snapshot/constrained.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-port 0 --metrics-port 0 \
  --runtime-log-transport stderr-pipe \
  --smp 1 --memory 256M --overprovisioned >/dev/null

attempt=0
while [ "$(docker inspect --format '{{.State.Running}}' "$constrained_gateway")" = true ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 10 ]; then
    echo "BonVoyage accepted unsupported directoryName trust constraints" >&2
    exit 1
  fi
  sleep 1
done
test "$(docker inspect --format '{{.State.ExitCode}}' "$constrained_gateway")" -ne 0
constrained_logs="$(docker logs "$constrained_gateway" 2>&1)"
printf '%s\n' "$constrained_logs" | \
  grep -F "unsupported directoryName or URI name constraints" >/dev/null

docker run --detach --platform "$platform" --name "$malformed_trust_gateway" \
  --network "$network" \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
  "$image" --snapshot /snapshot/malformed.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-port 0 --metrics-port 0 \
  --runtime-log-transport stderr-pipe \
  --smp 1 --memory 256M --overprovisioned >/dev/null

attempt=0
while [ "$(docker inspect --format '{{.State.Running}}' "$malformed_trust_gateway")" = true ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 10 ]; then
    echo "BonVoyage accepted a malformed trust bundle" >&2
    exit 1
  fi
  sleep 1
done
malformed_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$malformed_trust_gateway")"
test "$malformed_exit_code" -eq 1
malformed_trust_logs="$(docker logs "$malformed_trust_gateway" 2>&1)"
printf '%s\n' "$malformed_trust_logs" | grep -F "event=dataplane_failed" >/dev/null
printf '%s\n' "$malformed_trust_logs" | \
  grep -F "Base64 unexpected header error." >/dev/null
echo "malformed trust bundle terminated through the exception path"

if [ -n "$evidence_dir" ]; then
  printf '%s\n' "$constrained_logs" >"$evidence_dir/constrained-trust.log"
  printf '%s\n' "$malformed_trust_logs" >"$evidence_dir/malformed-trust.log"
  docker logs "$gateway" >"$evidence_dir/gateway.log" 2>&1
  docker image inspect "$image" "$builder_image" "$compiler_image" "$upstream_image" \
    >"$evidence_dir/images.inspect.json"
  cp "$0" "$evidence_dir/harness.sh"
  cp tests/fixtures/phase6-gnutls-certificate-policy.yaml \
    "$evidence_dir/policy.yaml"
  cp tests/fixtures/phase6-gnutls-constrained-trust.yaml \
    "$evidence_dir/constrained.yaml"
  cp tests/fixtures/phase6-gnutls-malformed-trust.yaml \
    "$evidence_dir/malformed.yaml"
  cp deploy/docker/bonvoyage/patches/seastar-tls-certificate-policy.patch \
    "$evidence_dir/seastar-tls-certificate-policy.patch"
  cp tests/fixtures/gnutls-policy-upstream.c \
    "$evidence_dir/gnutls-policy-upstream.c"
  cp "$fixture_dir/traffic-matrix.json" "$evidence_dir/traffic-matrix.json"
  openssl x509 -in "$fixture_dir/constrained-ca.pem" -noout -text \
    >"$evidence_dir/constrained-ca.txt"
  (
    cd "$evidence_dir"
    shasum -a 256 constrained-trust.log malformed-trust.log gateway.log \
      images.inspect.json harness.sh policy.yaml constrained.yaml malformed.yaml \
      seastar-tls-certificate-policy.patch gnutls-policy-upstream.c \
      traffic-matrix.json constrained-ca.txt \
      >SHA256SUMS
  )
fi

echo "BonVoyage strict TLS certificate policy passed"
