#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

jobs="${BONVOYAGE_BUILD_JOBS:-2}"
upstream_http1_client="${BONVOYAGE_UPSTREAM_HTTP1_CLIENT:-seastar-reference}"
expected_ctest_targets=44
case "$upstream_http1_client" in
  seastar-reference|llhttp-candidate) ;;
  *)
    echo "unsupported upstream HTTP/1 client: $upstream_http1_client" >&2
    exit 2
    ;;
esac
engine_arch="$(docker info --format '{{.Architecture}}')"
case "$engine_arch" in
  amd64|x86_64)
    native_platform=linux/amd64
    ;;
  arm64|aarch64)
    native_platform=linux/arm64
    ;;
  *)
    echo "unsupported Docker engine architecture: $engine_arch" >&2
    exit 1
    ;;
esac

# Sanitizer executables must run natively; QEMU cannot reliably reserve ASan's
# shadow address space. Seastar's sanitize mode also selects the system
# allocator so it does not conflict with ASan's malloc interposition.
# The consumer configuration must be Sanitize too: Seastar's exported target
# otherwise omits debug macros that change gate and holder object layouts.
platform="${BONVOYAGE_SANITIZER_PLATFORM:-$native_platform}"
target_arch="${platform#linux/}"
runtime_tests=ON

case "$engine_arch:$target_arch" in
  amd64:amd64|x86_64:amd64|arm64:arm64|aarch64:arm64)
    ;;
  *)
    runtime_tests=OFF
    echo "cross-architecture build: skipping ASan reactor startup test"
    ;;
esac

evidence_id="${BONVOYAGE_SANITIZER_EVIDENCE_ID:-}"
evidence_root="${BONVOYAGE_SANITIZER_EVIDENCE_ROOT:-benchmarks/results/verification}"
if [ -z "$evidence_id" ]; then
  exec docker buildx build \
    --platform "$platform" \
    --target bonvoyage-build \
    --build-arg "BUILD_JOBS=$jobs" \
    --build-arg SEASTAR_MODE=sanitize \
    --build-arg BONVOYAGE_BUILD_TYPE=Sanitize \
    --build-arg BONVOYAGE_ENABLE_SANITIZERS=ON \
    --build-arg "BONVOYAGE_RUN_RUNTIME_TESTS=$runtime_tests" \
    --build-arg "BONVOYAGE_UPSTREAM_HTTP1_CLIENT=$upstream_http1_client" \
    --file deploy/docker/bonvoyage/Dockerfile \
    .
fi

if [ "$evidence_root" = "benchmarks/results/verification" ]; then
  case "$evidence_id" in
    sanitizers-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;;
    *)
      echo "invalid retained sanitizer evidence id: $evidence_id" >&2
      exit 2
      ;;
  esac
else
  case "$evidence_id" in
    sanitizers-[a-z0-9][a-z0-9-]*) ;;
    *)
      echo "invalid isolated sanitizer evidence id: $evidence_id" >&2
      exit 2
      ;;
  esac
fi

evidence_dir="$evidence_root/$evidence_id"
if [ -e "$evidence_dir" ]; then
  echo "sanitizer evidence directory already exists: $evidence_dir" >&2
  exit 2
fi
mkdir -p "$evidence_dir"
transcript="$evidence_dir/ctest.txt"
iid_file="$evidence_dir/image-id.txt"

build_status=0
docker buildx build \
  --platform "$platform" \
  --target bonvoyage-build \
  --no-cache-filter bonvoyage-build \
  --progress=plain \
  --iidfile "$iid_file" \
  --build-arg "BUILD_JOBS=$jobs" \
  --build-arg SEASTAR_MODE=sanitize \
  --build-arg BONVOYAGE_BUILD_TYPE=Sanitize \
  --build-arg BONVOYAGE_ENABLE_SANITIZERS=ON \
  --build-arg "BONVOYAGE_RUN_RUNTIME_TESTS=$runtime_tests" \
  --build-arg "BONVOYAGE_UPSTREAM_HTTP1_CLIENT=$upstream_http1_client" \
  --file deploy/docker/bonvoyage/Dockerfile \
  . >"$transcript" 2>&1 || build_status=$?
cat "$transcript"
if [ "$build_status" -ne 0 ]; then
  echo "sanitizer build failed; retained transcript: $transcript" >&2
  exit "$build_status"
fi

grep -Fq \
  "100% tests passed, 0 tests failed out of $expected_ctest_targets" \
  "$transcript"
grep -Fq "Found Sanitizers: -fsanitize=address;-fsanitize=undefined" \
  "$transcript"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

source_list="$evidence_dir/source-files.txt"
{
  printf '%s\n' \
    scripts/build-dataplane-sanitized.sh \
    deploy/docker/bonvoyage/Dockerfile \
    security/dependencies/abseil-20250512.1.json \
    security/dependencies/c-ares-1.34.8.json \
    security/dependencies/libjwt-3.6.1.json \
    security/dependencies/llhttp-9.4.3.json \
    security/dependencies/nghttp2-1.70.0.json \
    security/dependencies/opentelemetry-proto-1.11.0.json \
    security/dependencies/re2-2025-11-05.json \
    security/dependencies/seastar-25.05.0.json \
    third_party/opentelemetry-proto/LICENSE \
    third_party/opentelemetry-proto/opentelemetry/proto/collector/trace/v1/trace_service.proto \
    third_party/opentelemetry-proto/opentelemetry/proto/common/v1/common.proto \
    third_party/opentelemetry-proto/opentelemetry/proto/resource/v1/resource.proto \
    third_party/opentelemetry-proto/opentelemetry/proto/trace/v1/trace.proto
  find deploy/docker/bonvoyage/patches -type f -name '*.patch' -print
  find api/proto -type f -name '*.proto' -print
  find dataplane -type f \( \
    -name 'CMakeLists.txt' -o -name '*.cmake' -o -name '*.cc' -o \
    -name '*.hh' \
  \) -print
} | LC_ALL=C sort -u >"$source_list"

while IFS= read -r source_file; do
  hash_file "$source_file"
done <"$source_list" >"$evidence_dir/source-checksums.sha256"
rm "$source_list"

captured_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ctest_seconds="$(sed -n \
  's/.*Total Test time (real) = *\([0-9.]*\) sec/\1/p' \
  "$transcript" | tail -n 1)"
output_image_id="$(cat "$iid_file")"
docker_engine="$(docker version --format '{{.Server.Version}}')"
docker_os="$(docker info --format '{{.OperatingSystem}}')"
docker_cpus="$(docker info --format '{{.NCPU}}')"
docker_memory_bytes="$(docker info --format '{{.MemTotal}}')"
host_os="$(sw_vers -productName 2>/dev/null || uname -s)"
host_version="$(sw_vers -productVersion 2>/dev/null || uname -r)"
host_arch="$(uname -m)"
ctest_sha256="$(hash_file "$transcript" | awk '{print $1}')"

cat >"$evidence_dir/build-metadata.txt" <<EOF
captured_utc=$captured_utc
supported_command=make dataplane-sanitize
retained_command=BONVOYAGE_UPSTREAM_HTTP1_CLIENT=$upstream_http1_client BONVOYAGE_SANITIZER_EVIDENCE_ID=$evidence_id make dataplane-sanitize
host_os=$host_os $host_version
host_arch=$host_arch
docker_engine=$docker_engine
docker_os=$docker_os
docker_arch=$engine_arch
docker_cpus=$docker_cpus
docker_memory_bytes=$docker_memory_bytes
platform=$platform
upstream_http1_client=$upstream_http1_client
seastar_version=25.05.0
seastar_commit=8df8212e53577e1d8477a5c901457cd61d88afc7
c_ares_version=1.34.8
c_ares_commit=c7a3138dcfe3bb0eaaf10c0c24c36dc66dc790ab
c_ares_instrumentation=address,undefined
nghttp2_version=1.70.0
nghttp2_commit=85e300c79fb6dbcfa9c1013215c8710c1c2cd3d2
libjwt_version=3.6.1
libjwt_commit=f4edfe5b2c44ac57edf00342550e81017f5329eb
opentelemetry_proto_version=1.11.0
opentelemetry_proto_commit=790608c4d51e6ffc12210b541e8514cbed9e91a4
re2_version=2025-11-05
re2_commit=927f5d53caf8111721e734cf24724686bb745f55
abseil_version=20250512.1
abseil_commit=76bb24329e8bf5f39704eb10d21b9a80befa7c81
seastar_mode=sanitize
bonvoyage_build_type=Sanitize
bonvoyage_configuration_flags=-O2 -g -DNDEBUG
bonvoyage_instrumentation=address,undefined
nghttp2_instrumentation=address,undefined
libjwt_instrumentation=address,undefined
opentelemetry_generated_code_instrumentation=address,undefined
abseil_instrumentation=address
re2_instrumentation=address
dependency_ubsan_exception=GCC bug 71962 tracked as abseil-cpp issue 1634
asan_options=halt_on_error=1:abort_on_error=1
ubsan_options=halt_on_error=1:print_stacktrace=1
ctest_passed=$expected_ctest_targets
ctest_failed=0
ctest_seconds=$ctest_seconds
output_image_id=$output_image_id
ctest_transcript_sha256=$ctest_sha256
EOF

cat >"$evidence_dir/README.md" <<EOF
# BonVoyage dataplane sanitizer verification

- Captured: $captured_utc
- Supported command: \`make dataplane-sanitize\`
- Retained command: \`BONVOYAGE_UPSTREAM_HTTP1_CLIENT=$upstream_http1_client BONVOYAGE_SANITIZER_EVIDENCE_ID=$evidence_id make dataplane-sanitize\`
- Platform: $platform on $docker_os
- Upstream HTTP/1 client: \`$upstream_http1_client\`
- Seastar: 25.05.0 at \`8df8212e53577e1d8477a5c901457cd61d88afc7\`
- nghttp2: 1.70.0 at \`85e300c79fb6dbcfa9c1013215c8710c1c2cd3d2\`
- OpenTelemetry Proto: 1.11.0 at \`790608c4d51e6ffc12210b541e8514cbed9e91a4\`
- RE2: 2025-11-05 at \`927f5d53caf8111721e734cf24724686bb745f55\`
- Abseil: 20250512.1 at \`76bb24329e8bf5f39704eb10d21b9a80befa7c81\`
- BonVoyage instrumentation: AddressSanitizer and UndefinedBehaviorSanitizer
- Seastar instrumentation: upstream sanitize mode
- BonVoyage consumer configuration: Sanitize, matching Seastar's debug ABI
- nghttp2 instrumentation: AddressSanitizer and UndefinedBehaviorSanitizer
- Abseil and RE2 instrumentation: AddressSanitizer; GCC UBSan is excluded for
  these two libraries because GCC bug 71962 prevents Abseil's affected
  constexpr hash helper from compiling (tracked by Abseil issue 1634)
- Result: $expected_ctest_targets of $expected_ctest_targets CTest targets passed in $ctest_seconds seconds
- Output image identity: \`$output_image_id\`
- Evidence class: local functional verification, not performance evidence

The retained build compiles the bounded upstream response-head and chunk
metadata patch, fixed-length and chunked translation paths, downstream and
upstream HTTP/2 protocol engines, native unary gRPC framing and terminal
metadata, TLS paths, bounded route CORS,
request-content, header-transformation, and
authority/path rewrite policy, shard-local weighted cluster selection, retry
policy and budget, bounded HTTP/1.1 WebSocket tunneling, bounded shard-local
access logging and its real-reactor recovery/byte-ceiling test, snapshot
runtime, W3C trace context, the bounded OTLP exporter and its generated
Protobuf contracts, the authenticated discovery codec and client, all-shard
live snapshot preparation and activation, and a loopback HTTP listener
lifecycle regression.
The consumer uses CMake's Sanitize configuration with explicit optimization
and debug-information flags so Seastar's exported debug layout macros match
its compiled library. BonVoyage code retains
both ASan and UBSan. Abseil and RE2 retain
ASan but not direct UBSan instrumentation due to the documented GCC compiler
defect; this is a coverage limitation, not a passed UBSan claim for those
library internals. CTest reported no ASan diagnostic, UBSan runtime error,
failed target, or build failure.

\`ctest.txt\` preserves the complete build and test transcript.
\`build-metadata.txt\` preserves builder and output identity.
\`source-checksums.sha256\` binds the evidence to compiled source and build
inputs. \`evidence-checksums.sha256\` protects this retained record.
EOF

(
  cd "$evidence_dir"
  for evidence_file in README.md build-metadata.txt ctest.txt image-id.txt \
    source-checksums.sha256; do
    hash_file "$evidence_file"
  done >evidence-checksums.sha256
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum --check --quiet evidence-checksums.sha256
  else
    shasum -a 256 --check --quiet evidence-checksums.sha256
  fi
)

printf '%s\n' "$evidence_id" >"$evidence_root/current-sanitizer.txt.tmp"
mv "$evidence_root/current-sanitizer.txt.tmp" \
  "$evidence_root/current-sanitizer.txt"

echo "retained sanitizer evidence: $evidence_dir"
