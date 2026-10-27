#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
# shellcheck disable=SC1091
. "$repo/scripts/test-fixture-secrets.sh"

platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
gateway_image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
fixture_image="${BONVOYAGE_FIXTURE_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
suffix="$$-$(date -u +%Y%m%dT%H%M%SZ)"
network="bonvoyage-perf01-$suffix"
base_volume="bonvoyage-perf01-base-$suffix"
policy_volume="bonvoyage-perf01-policy-$suffix"
secrets_volume="bonvoyage-perf01-secrets-$suffix"
gateway="bonvoyage-perf01-gateway-$suffix"
upstream_a="bonvoyage-perf01-upstream-a-$suffix"
upstream_b="bonvoyage-perf01-upstream-b-$suffix"
work="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-perf01.XXXXXX")"

fail() { echo "phase5-fixture-smoke: $*" >&2; exit 1; }
cleanup() {
  status="$?"
  set +e
  docker rm --force "$gateway" "$upstream_a" "$upstream_b" >/dev/null 2>&1
  docker network rm "$network" >/dev/null 2>&1
  docker volume rm "$base_volume" "$policy_volume" >/dev/null 2>&1
  bv_remove_fixture_secrets "$secrets_volume" "$work" >/dev/null 2>&1
  if [ "$status" -eq 0 ]; then rm -rf "$work"; else
    echo "partial smoke evidence retained: $work" >&2; fi
  exit "$status"
}
trap cleanup EXIT INT TERM

for tool in docker jq openssl; do command -v "$tool" >/dev/null || fail "$tool required"; done
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj '/CN=BonVoyage PERF-01 CA' -keyout "$work/ca-key.pem" \
  -out "$work/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 -subj '/CN=api.example.test' \
  -keyout "$work/server-key.pem" -out "$work/server.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:api.example.test' 'extendedKeyUsage=serverAuth' \
  'keyUsage=digitalSignature,keyEncipherment' >"$work/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work/server.csr" \
  -CA "$work/ca.pem" -CAkey "$work/ca-key.pem" -CAcreateserial \
  -extfile "$work/server-ext.cnf" -out "$work/server-chain.pem" >/dev/null 2>&1
key="$(openssl rand -hex 16)"
printf '%s\n' "$key" >"$work/perf01-api-keys.txt"
chmod 600 "$work"/*-key.pem "$work/perf01-api-keys.txt"

docker network create "$network" >/dev/null
docker volume create "$base_volume" >/dev/null
docker volume create "$policy_volume" >/dev/null
bv_stage_fixture_secrets "$secrets_volume" "$work" "$fixture_image" "$platform" \
  server-chain.pem server-key.pem perf01-api-keys.txt
for item in "base:$base_volume" "api-key:$policy_volume"; do
  name="${item%%:*}"
  volume="${item#*:}"
  docker run --rm --pull never --platform "$platform" --user 0:0 \
    --network none --volume "$volume:/output" --entrypoint python \
    "$fixture_image" -c \
    'import os; os.chmod("/output", 0o700); os.chown("/output", 65532, 65532)' \
    >/dev/null
  docker run --rm --pull never --platform "$platform" \
    --volume "$repo/tests/fixtures/phase5-baseline-$name.yaml:/config/input.yaml:ro" \
    --volume "$volume:/output" "$compiler_image" \
    -input /config/input.yaml -output /output/snapshot.pb >"$work/$name.compile.log"
done
docker run --detach --pull never --platform "$platform" --name "$upstream_a" \
  --network "$network" --network-alias upstream-a \
  --env BONVOYAGE_UPSTREAM_ID=upstream-a "$upstream_image" >/dev/null
docker run --detach --pull never --platform "$platform" --name "$upstream_b" \
  --network "$network" --network-alias upstream-b \
  --env BONVOYAGE_UPSTREAM_ID=upstream-b "$upstream_image" >/dev/null

start_gateway() {
  volume="$1"
  docker run --detach --pull never --platform "$platform" --name "$gateway" \
    --network "$network" --network-alias gateway \
    --network-alias api.example.test --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    --cap-drop ALL --cap-add SYS_NICE --security-opt no-new-privileges:true \
    --volume "$volume:/snapshot:ro" \
    --volume "$secrets_volume:/etc/bonvoyage/secrets:ro" \
    "$gateway_image" --snapshot /snapshot/snapshot.pb \
    --secrets-directory /etc/bonvoyage/secrets \
    --smp 1 --memory 384M --overprovisioned >/dev/null
  sleep 2
  [ "$(docker inspect --format '{{.State.Running}}' "$gateway")" = true ] || \
    fail 'gateway did not start'
}

probe() {
  label="$1"; protocol="$2"; url="$3"; shift 3
  docker run --rm --pull never --platform "$platform" --network "$network" \
    --volume "$work/ca.pem:/tls/ca.pem:ro" "$oha_image" \
    -z 2s -c 4 -w --disable-compression --no-tui --no-color \
    --http-version "$protocol" --cacert /tls/ca.pem \
    --output-format json "$@" "$url" >"$work/$label.oha.json"
  jq -e '.statusCodeDistribution == {"200": .statusCodeDistribution["200"]} and
    .statusCodeDistribution["200"] > 0 and
    (.errorDistribution | length) == 0 and .summary.sizePerRequest == 256' \
    "$work/$label.oha.json" >/dev/null || fail "$label did not return only 256-byte HTTP 200"
}

start_gateway "$base_volume"
probe upstream-a 1.1 http://upstream-a:8081/payload/256
probe upstream-b 1.1 http://upstream-b:8081/payload/256
probe P5-B01 1.1 http://gateway:8080/payload/256 -H 'Host: api.example.test'
count_upstream_requests() {
  docker logs "$1" 2>&1 | grep -c '"GET /payload/256 HTTP/1.1" 200' || true
}
before_a="$(count_upstream_requests "$upstream_a")"
before_b="$(count_upstream_requests "$upstream_b")"
docker run --rm --pull never --platform "$platform" --network "$network" \
  --entrypoint sh "$fixture_image" -c \
  'for request in 1 2 3 4 5 6 7 8; do wget -q -O /dev/null --header="Host: api.example.test" http://gateway:8080/payload/256; done'
after_a="$(count_upstream_requests "$upstream_a")"
after_b="$(count_upstream_requests "$upstream_b")"
delta_a=$((after_a - before_a))
delta_b=$((after_b - before_b))
[ "$delta_a" -gt 0 ] && [ "$delta_b" -gt 0 ] &&
  [ $((delta_a + delta_b)) -eq 8 ] ||
  fail "round-robin probe reached upstream-a=$delta_a upstream-b=$delta_b"
probe P5-B02 1.1 https://api.example.test:8443/payload/256
probe P5-B03 2 https://api.example.test:8444/payload/256
docker rm --force "$gateway" >/dev/null
start_gateway "$policy_volume"
probe P5-B04 1.1 https://api.example.test:8443/payload/256 -H "X-API-Key: $key"
docker run --rm --pull never --platform "$platform" --network "$network" \
  --volume "$work/ca.pem:/tls/ca.pem:ro" "$oha_image" \
  -z 1s -c 1 -w --http-version 1.1 --cacert /tls/ca.pem \
  --no-tui --no-color --output-format json -H 'X-API-Key: invalid' \
  https://api.example.test:8443/payload/256 >"$work/rejected.oha.json"
jq -e '(.statusCodeDistribution["200"] // 0) == 0 and
  ([.statusCodeDistribution | to_entries[] | select(.key == "401" or .key == "403") | .value] | add // 0) > 0' \
  "$work/rejected.oha.json" >/dev/null || fail 'invalid API key was not rejected'
echo 'PERF-01 fixture smoke passed: two upstreams, HTTP/1.1, HTTPS, HTTP/2, API key, rejection'
