#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

base_image="${BONVOYAGE_GLIBC_TRACE_BASE_IMAGE:-}"
expected_base_id="${BONVOYAGE_GLIBC_TRACE_BASE_IMAGE_ID:-}"
build_image="${BONVOYAGE_GLIBC_TRACE_BUILD_IMAGE:-bonvoyage-build:dev}"
mode="${BONVOYAGE_GLIBC_TRACE_MODE:-diagnostic}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="runtime-glibc-call-trace-$timestamp"
evidence_root="${BONVOYAGE_GLIBC_TRACE_EVIDENCE_ROOT:-$repo_root/benchmarks/results/local-archives}"

if [ -z "$base_image" ] || [ -z "$expected_base_id" ]; then
  echo "BONVOYAGE_GLIBC_TRACE_BASE_IMAGE and BONVOYAGE_GLIBC_TRACE_BASE_IMAGE_ID are required" >&2
  exit 2
fi
case "$mode" in
  diagnostic|clean-bound) ;;
  *) echo "BONVOYAGE_GLIBC_TRACE_MODE must be diagnostic or clean-bound" >&2; exit 2 ;;
esac
if [ "$platform" != linux/amd64 ]; then
  echo "runtime glibc call tracing is qualified only for linux/amd64" >&2
  exit 2
fi

for command_name in date docker git grep mktemp python3 sed uname; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name is required" >&2
    exit 1
  }
done

if command -v sha256sum >/dev/null 2>&1; then
  hash_file() { sha256sum "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  hash_file() { shasum -a 256 "$1"; }
else
  echo "sha256sum or shasum is required" >&2
  exit 1
fi

docker image inspect "$base_image" >/dev/null 2>&1 || {
  echo "base runtime image is missing: $base_image" >&2
  exit 1
}
docker image inspect "$build_image" >/dev/null 2>&1 || {
  echo "observer build image is missing: $build_image" >&2
  exit 1
}

base_id="$(docker image inspect "$base_image" --format '{{.Id}}')"
base_platform="$(docker image inspect "$base_id" --format '{{.Os}}/{{.Architecture}}')"
base_revision="$(docker image inspect "$base_id" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')"
base_source_dirty="$(docker image inspect "$base_id" --format '{{index .Config.Labels "io.routesphere.bonvoyage.source-dirty"}}')"
build_id="$(docker image inspect "$build_image" --format '{{.Id}}')"
source_commit="$(git rev-parse HEAD)"
source_status="$(git status --porcelain=v1 --untracked-files=all)"
source_dirty=true
if [ -z "$source_status" ]; then
  source_dirty=false
fi

if [ "$base_id" != "$expected_base_id" ] || [ "$base_platform" != "$platform" ]; then
  echo "base runtime image identity or platform differs from the explicit lock" >&2
  exit 2
fi
if [ "$mode" = clean-bound ] && {
  [ "$source_dirty" != false ] || [ "$base_revision" != "$source_commit" ] ||
  [ "$base_source_dirty" != false ];
}; then
  echo "clean-bound tracing requires clean source and an exact clean-source runtime image" >&2
  exit 2
fi

mkdir -p "$evidence_root"
evidence_root="$(CDPATH='' cd -- "$evidence_root" && pwd)"
output_dir="$evidence_root/$run_id"
test ! -e "$output_dir" || {
  echo "evidence directory already exists: $output_dir" >&2
  exit 2
}

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-glibc-trace.XXXXXX")"
stage_dir="$work_dir/evidence"
trace_image="bonvoyage-runtime-glibc-trace:$timestamp-$$"
locked_base_image="bonvoyage-runtime-glibc-trace-base:$timestamp-$$"
locked_build_image="bonvoyage-runtime-glibc-trace-builder:$timestamp-$$"
mkdir "$stage_dir"
export BUILDX_CONFIG="$work_dir/buildx"
mkdir "$BUILDX_CONFIG"
completed=false
cleanup() {
  status="$?"
  docker image rm "$trace_image" "$locked_base_image" "$locked_build_image" \
    >/dev/null 2>&1 || true
  if [ "$completed" = true ]; then
    rm -rf "$work_dir"
  else
    echo "runtime glibc trace did not complete; temporary evidence: $stage_dir" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM
docker image tag "$base_id" "$locked_base_image"
docker image tag "$build_id" "$locked_build_image"

docker build --platform "$platform" --pull=false \
  --tag "$trace_image" \
  --build-arg "BONVOYAGE_OBSERVER_BUILD_IMAGE=$locked_build_image" \
  --build-arg "BONVOYAGE_RUNTIME_IMAGE=$locked_base_image" \
  --build-arg "BONVOYAGE_BASE_RUNTIME_IMAGE_ID=$base_id" \
  --build-arg "BONVOYAGE_OBSERVER_BUILD_IMAGE_ID=$build_id" \
  --label "io.routesphere.bonvoyage.diagnostic.source-commit=$source_commit" \
  --file deploy/docker/security/runtime-glibc-call-trace.Dockerfile . \
  >"$stage_dir/build.log" 2>&1

trace_id="$(docker image inspect "$trace_image" --format '{{.Id}}')"
recorded_base_id="$(docker image inspect "$trace_id" --format '{{index .Config.Labels "io.routesphere.bonvoyage.diagnostic.base-runtime-image-id"}}')"
recorded_build_id="$(docker image inspect "$trace_id" --format '{{index .Config.Labels "io.routesphere.bonvoyage.diagnostic.observer-build-image-id"}}')"
test "$recorded_base_id" = "$base_id"
test "$recorded_build_id" = "$build_id"

docker run --rm --platform "$platform" --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --entrypoint /usr/local/libexec/bonvoyage-runtime-glibc-call-trace-selftest \
  "$trace_image" >"$stage_dir/selftest.log" 2>&1

mkdir "$stage_dir/baseline"
env BONVOYAGE_BUILD_PLATFORM="$platform" \
  BONVOYAGE_DATAPLANE_IMAGE="$trace_image" \
  BONVOYAGE_HTTP1_FRAMING_EVIDENCE_DIR="$stage_dir/baseline" \
  ./scripts/smoke-dataplane-container.sh \
  >"$stage_dir/baseline-command.log" 2>&1

mkdir "$stage_dir/jwt"
env BONVOYAGE_BUILD_PLATFORM="$platform" \
  BONVOYAGE_DATAPLANE_IMAGE="$trace_image" \
  BONVOYAGE_JWT_EVIDENCE_ROOT="$stage_dir/jwt" \
  ./scripts/phase3-jwt-smoke.sh >"$stage_dir/jwt-command.log" 2>&1
jwt_run_id="$(sed -n '1p' "$stage_dir/jwt/current-jwt-smoke.txt")"
case "$jwt_run_id" in
  jwt-smoke-[0-9]*Z) ;;
  *) echo "invalid JWT evidence run identifier" >&2; exit 2 ;;
esac
test -f "$stage_dir/jwt/$jwt_run_id/gateway.log"

set +e
(
  cd "$stage_dir"
  python3 -B "$repo_root/scripts/analyze-runtime-glibc-call-trace.py" \
    --control selftest=selftest.log \
    --scenario baseline=baseline/gateway.log \
    --scenario "tls-jwt=jwt/$jwt_run_id/gateway.log" \
    --output runtime-glibc-call-observation.private.json
) >"$stage_dir/analyzer.stdout" 2>"$stage_dir/analyzer.stderr"
analyzer_status="$?"
set -e

result=FAIL
if [ "$analyzer_status" -eq 0 ]; then
  result=PASS
fi
evidence_class=diagnostic-security-engineering
if [ "$mode" = clean-bound ]; then
  evidence_class=clean-source-security-engineering
fi

docker image inspect "$base_id" "$build_id" "$trace_id" \
  >"$stage_dir/images.inspect.json"
cat >"$stage_dir/environment.txt" <<EOF
captured_at_utc=$timestamp
run_id=$run_id
result=$result
mode=$mode
evidence_class=$evidence_class
publishable=false
marketing_use_authorized=false
source_commit=$source_commit
source_dirty=$source_dirty
base_runtime_image=$base_image
base_runtime_image_id=$base_id
base_runtime_platform=$base_platform
base_runtime_source_revision=$base_revision
base_runtime_source_dirty=$base_source_dirty
observer_build_image=$build_image
observer_build_image_id=$build_id
trace_image_id=$trace_id
analyzer_exit_code=$analyzer_status
reachability_closed=false
vex_authorized=false
scanner_suppression_authorized=false
release_authorized=false
host=$(uname -s) $(uname -r) $(uname -m)
EOF

cat >"$stage_dir/README.md" <<EOF
# Runtime glibc call observation

Result: **$result** in **$mode** mode.

This private diagnostic archive binds one positive observer control, an
HTTP/1.1 proxy/recovery scenario and a TLS/JWT scenario to explicit source and
image identities. The observer records libc function class, calling object and
file mode; it deliberately excludes file paths, DNS names and addresses.

A pass means the observer worked, every traced process completed one lifecycle,
all calls were attributed, no gateway scenario invoked a glibc resolver entry
point and no observed file mode contained the comma-ccs mode extension. It does
**not** prove whole-program unreachability. CVE-2026-8674 and CVE-2026-18374
remain under review;
VEX, scanner suppression, release approval and marketing claims remain false.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
.github/workflows/ci.yml
Makefile
ci/check-manual-coverage.mjs
ci/check-manual-coverage.test.mjs
deploy/docker/security/runtime-glibc-call-trace.Dockerfile
docs/implementation/phases-and-milestones.md
docs/security/runtime-finding-disposition.md
docs/security/verified-release-contract.md
scripts/analyze-runtime-glibc-call-trace.py
scripts/phase3-jwt-smoke.sh
scripts/phase5-runtime-glibc-call-trace.sh
scripts/runtime-glibc-call-trace-selftest.c
scripts/runtime-glibc-call-trace.c
scripts/smoke-dataplane-container.sh
scripts/test-runtime-glibc-call-trace.sh
scripts/test_analyze_runtime_glibc_call_trace.py
EOF
while IFS= read -r source_file; do
  test -f "$source_file"
  hash_file "$source_file"
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"

(
  cd "$stage_dir"
  find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort | while IFS= read -r file; do
    hash_file "$file"
  done >SHA256SUMS
)

mv "$stage_dir" "$output_dir"
completed=true
echo "Runtime glibc call observation $result: $output_dir"
if [ "$analyzer_status" -ne 0 ]; then
  exit "$analyzer_status"
fi
