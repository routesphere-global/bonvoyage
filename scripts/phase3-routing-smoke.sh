#!/bin/sh
set -eu

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
cost_seconds="${BONVOYAGE_ROUTING_COST_SECONDS:-3}"
cost_repetitions="${BONVOYAGE_ROUTING_COST_REPETITIONS:-3}"
cost_concurrency="${BONVOYAGE_ROUTING_COST_CONCURRENCY:-32}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="routing-smoke-$timestamp"
suffix="$$"
network="bonvoyage-routing-$suffix"
volume="bonvoyage-routing-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-routing-gateway-$suffix"
upstream="bonvoyage-routing-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-routing.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_ROUTING_EVIDENCE_ROOT:-benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"

cleanup() {
  status="$?"
  if [ -d "$stage_dir" ] && docker inspect "$gateway" >/dev/null 2>&1; then
    docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1 || true
  fi
  if [ "$status" -ne 0 ]; then
    echo "routing smoke failed; temporary evidence: $stage_dir" >&2
    if [ -f "$stage_dir/gateway.log" ]; then
      cat "$stage_dir/gateway.log" >&2
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

for command_name in date docker git mktemp openssl sed sort uname; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name is required" >&2
    exit 1
  }
done

case "$cost_seconds:$cost_repetitions:$cost_concurrency" in
  *[!0-9:]*|0:*|*:0:*|*:0)
    echo "routing cost controls must be positive integers" >&2
    exit 1
    ;;
esac

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage Routing Test CA" \
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
chmod 600 "$work_dir"/*-key.pem

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-routing.yaml:/etc/bonvoyage/routing.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/routing.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --volume "$work_dir:/tls:ro" --volume "$stage_dir:/evidence:ro" \
  "$upstream_image" >/dev/null
docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$image" \
  --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 256M --overprovisioned >/dev/null

bv_wait_gateway_ready "$gateway" "$upstream" "http://$gateway:9901/health/ready"

docker exec "$upstream" python -c '
import json
import urllib.request

gateway = "http://bonvoyage-routing-gateway-'"$suffix"':8080"

def request(path, expected_status, expected_body, method="GET", headers=None):
    request_headers = {"Host": "api.example.test"}
    request_headers.update(headers or {})
    item = urllib.request.Request(
        gateway + path,
        headers=request_headers,
        method=method,
    )
    with urllib.request.urlopen(item, timeout=10) as response:
        body = response.read().decode()
        assert response.status == expected_status, (path, response.status)
        assert body == expected_body, (path, body)
    return {"path": path, "method": method, "status": expected_status}

results = [
    request(
        "/routing/select?tenant=ac%6de",
        200,
        "predicate-selected\n",
        headers={"X-Release": "beta"},
    ),
    request(
        "/routing/select?tenant=acme",
        201,
        "predicate-fallback\n",
        method="POST",
        headers={"X-Release": "beta"},
    ),
    request(
        "/routing/select?tenant=ac+me",
        201,
        "predicate-fallback\n",
        headers={"X-Release": "beta"},
    ),
    request(
        "/routing/absence?other=1",
        202,
        "negative-presence\n",
    ),
    request(
        "/routing/items/42",
        203,
        "safe-regex\n",
    ),
]
print(json.dumps({"protocol": "http1", "results": results}, indent=2))
' >"$stage_dir/http1-results.json"

run_h2() {
  name="$1"
  shift
  docker run --user "$(id -u):$(id -g)" --rm --platform "$platform" --network "$network" \
    --volume "$work_dir:/tls:ro" "$oha_image" \
    -n 8 -c 1 -p 4 --no-tui --output-format json \
    --http-version 2 --disable-compression --cacert /tls/ca.pem \
    "$@" >"$stage_dir/h2-$name.oha.json"
}

run_h2 selected -H "x-release: beta" \
  "https://api.example.test:8443/routing/select?tenant=ac%6de"
run_h2 fallback -m POST -H "x-release: beta" \
  "https://api.example.test:8443/routing/select?tenant=acme"
run_h2 absence "https://api.example.test:8443/routing/absence?other=1"
run_h2 regex "https://api.example.test:8443/routing/items/42"

docker exec "$upstream" python -c '
import json

expected = {
    "h2-selected.oha.json": "200",
    "h2-fallback.oha.json": "201",
    "h2-absence.oha.json": "202",
    "h2-regex.oha.json": "203",
}
for filename, status in expected.items():
    with open("/evidence/" + filename, encoding="utf-8") as source:
        result = json.load(source)
    assert result["summary"]["successRate"] == 1, filename
    assert result["statusCodeDistribution"] == {status: 8}, filename
' >"$stage_dir/http2-validation.txt"

run_cost_case() {
  case_name="$1"
  repetition="$2"
  shift 2
  docker run --rm --platform "$platform" --network "$network" "$oha_image" \
    -z "${cost_seconds}s" -c "$cost_concurrency" \
    --no-tui --output-format json --http-version 1.1 \
    --disable-compression --host api.example.test \
    "$@" >"$stage_dir/cost-$case_name-rep$repetition.oha.json"
}

repetition=1
while [ "$repetition" -le "$cost_repetitions" ]; do
  if [ $((repetition % 2)) -eq 1 ]; then
    cases="baseline compound regex"
  else
    cases="regex compound baseline"
  fi
  for case_name in $cases; do
    case "$case_name" in
      baseline)
        run_cost_case baseline "$repetition" \
          "http://api.example.test:8080/routing/baseline"
        ;;
      compound)
        run_cost_case compound "$repetition" -H "x-release: beta" \
          "http://api.example.test:8080/routing/select?tenant=acme"
        ;;
      regex)
        run_cost_case regex "$repetition" \
          "http://api.example.test:8080/routing/items/42"
        ;;
    esac
  done
  repetition=$((repetition + 1))
done

docker exec "$upstream" python -c '
import glob
import json
import statistics

seconds = int("'"$cost_seconds"'")
repetitions = int("'"$cost_repetitions"'")
concurrency = int("'"$cost_concurrency"'")

def summarize(case):
    samples = []
    for path in sorted(glob.glob(f"/evidence/cost-{case}-rep*.oha.json")):
        with open(path, encoding="utf-8") as source:
            result = json.load(source)
        assert result["summary"]["successRate"] == 1, path
        samples.append({
            "requests_per_second": float(result["summary"]["requestsPerSec"]),
            "p99_ms": float(result["latencyPercentiles"]["p99"]) * 1000,
            "p999_ms": float(result["latencyPercentiles"]["p99.9"]) * 1000,
        })
    assert len(samples) == repetitions, (case, len(samples))
    return {
        "samples": samples,
        "median_requests_per_second": statistics.median(
            item["requests_per_second"] for item in samples
        ),
        "median_p99_ms": statistics.median(item["p99_ms"] for item in samples),
        "median_p999_ms": statistics.median(item["p999_ms"] for item in samples),
    }

cases = {name: summarize(name) for name in ("baseline", "compound", "regex")}
baseline = cases["baseline"]["median_requests_per_second"]
summary = {
    "schema_version": 1,
    "run_id": "'"$run_id"'",
    "evidence": {
        "class": "local-engineering",
        "publishable": False,
        "marketing_use_authorized": False,
        "claim": "Local route-predicate cost observation only",
    },
    "controls": {
        "gateway_shards": 1,
        "protocol": "cleartext HTTP/1.1",
        "fixed_response_action": True,
        "measurement_seconds_per_repetition": seconds,
        "repetitions": repetitions,
        "logical_concurrency": concurrency,
        "order": "alternating by repetition",
    },
    "cases": cases,
    "observed_comparison": {
        "compound_to_baseline_rps_ratio": cases["compound"]["median_requests_per_second"] / baseline,
        "regex_to_baseline_rps_ratio": cases["regex"]["median_requests_per_second"] / baseline,
    },
    "limitations": [
        "Local Docker scheduling and shared-host noise are not controlled.",
        "The load generator and gateway share the local Docker runtime.",
        "This evidence cannot support marketing, customer, or competitive claims.",
    ],
}
print(json.dumps(summary, indent=2, sort_keys=True))
' >"$stage_dir/summary.json"

docker exec "$upstream" python -c '
import json
with open("/evidence/summary.json", encoding="utf-8") as source:
    summary = json.load(source)
print("LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE")
for name in ("baseline", "compound", "regex"):
    case = summary["cases"][name]
    print(
        f"{name}: median {case['"'"'median_requests_per_second'"'"']:.1f} RPS; "
        f"p99 {case['"'"'median_p99_ms'"'"']:.3f} ms; "
        f"p99.9 {case['"'"'median_p999_ms'"'"']:.3f} ms"
    )
comparison = summary["observed_comparison"]
print(
    "Observed RPS ratios: compound/baseline "
    f"{comparison['"'"'compound_to_baseline_rps_ratio'"'"']:.3f}; "
    "regex/baseline "
    f"{comparison['"'"'regex_to_baseline_rps_ratio'"'"']:.3f}"
)
' >"$stage_dir/summary.txt"

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-routing-gateway-'"$suffix"':9090/metrics", timeout=10
).read().decode(), end="")
' >"$stage_dir/metrics.prom"
docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1

source_commit="$(git rev-parse HEAD)"
source_dirty="$(if git diff --quiet && git diff --cached --quiet; then printf false; else printf true; fi)"
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
http1_functional_requests=5
http2_functional_requests=32
cost_seconds_per_repetition=$cost_seconds
cost_repetitions=$cost_repetitions
cost_concurrency=$cost_concurrency
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 route-predicate integration evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The same immutable snapshot was exercised over cleartext HTTP/1.1 and TLS HTTP/2. The checks cover method, exact header, exact and negative-presence query predicates, RFC 3986 percent decoding, literal plus handling, safe-regex selection, and same-path fallback ordering. All functional requests returned their expected route-specific status and body.

The local cost probe compares an exact-path fixed response with a compound method/header/query route and a safe-regex route on one Seastar shard. Its raw oha outputs and machine-readable summary are retained, but shared Docker scheduling prevents publication-quality conclusions.

\`summary.txt\` provides the concise observation. \`summary.json\`, raw oha files, metrics, image identities, logs, source checksums, and evidence checksums preserve the full record.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
dataplane/CMakeLists.txt
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/gateway.cc
dataplane/src/runtime_snapshot.cc
deploy/docker/bonvoyage/Dockerfile
scripts/phase3-routing-smoke.sh
scripts/test-fixture-secrets.sh
security/dependencies/abseil-20250512.1.json
security/dependencies/re2-2025-11-05.json
tests/fixtures/phase3-routing.yaml
EOF
while IFS= read -r source_file; do
  hash_file "$source_file"
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md compiler.txt gateway.inspect.json \
    gateway.log http1-results.json http2-validation.txt h2-*.oha.json \
    cost-*.oha.json metadata.txt metrics.prom runtime-image.inspect.json \
    source-checksums.sha256 summary.json summary.txt; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-routing-smoke.txt.tmp"
mv "$output_root/current-routing-smoke.txt.tmp" \
  "$output_root/current-routing-smoke.txt"

printf 'Route predicate integration passed: %s\n' "$output_dir"
cat "$output_dir/summary.txt"
