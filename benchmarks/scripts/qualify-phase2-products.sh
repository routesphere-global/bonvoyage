#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
cd "$repo_root"

product_lock="benchmarks/products/lock.json"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-benchmark-upstream:phase2}"
smoke_seconds="${BONVOYAGE_PHASE2_SMOKE_SECONDS:-5}"
smoke_connections="${BONVOYAGE_PHASE2_SMOKE_CONNECTIONS:-16}"
maximum_error_rate="${BONVOYAGE_MAXIMUM_ERROR_RATE:-0.001}"
gateway_cpus="${BONVOYAGE_GATEWAY_ONE_CPUS:-}"
load_generator_cpus="${BONVOYAGE_LOAD_GENERATOR_CPUS:-}"
upstream_cpus="${BONVOYAGE_UPSTREAM_CPUS:-}"
skip_pull="${BONVOYAGE_PHASE2_SKIP_PULL:-0}"
skip_upstream_build="${BONVOYAGE_PHASE2_SKIP_UPSTREAM_BUILD:-0}"
publishable_request="${BONVOYAGE_PUBLISHABLE:-0}"
qualification_attestation="${BONVOYAGE_QUALIFICATION_ATTESTATION:-}"
comparison_products="${BONVOYAGE_PHASE2_PRODUCTS:-bonvoyage envoy nginx haproxy}"
expected_payload_sha256="85e62acd750c4eb56b7b6a1d66dca5bfaac5f062608a1a893410d0288936c09a"

fail() {
  echo "phase2-products: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command '$1' is unavailable"
}

docker_run() {
  docker_run_cpus="$1"
  shift
  if [ -n "$docker_run_cpus" ]; then
    docker run --cpuset-cpus "$docker_run_cpus" "$@"
  else
    docker run "$@"
  fi
}

product_selected() {
  case " $comparison_products " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

wait_for_url() {
  wait_url="$1"
  wait_name="$2"
  wait_attempt=0
  until fetch_url "$wait_url" >/dev/null 2>&1; do
    wait_attempt=$((wait_attempt + 1))
    if [ "$wait_attempt" -ge 30 ]; then
      echo "$wait_name did not become ready at $wait_url" >&2
      return 1
    fi
    sleep 1
  done
}

fetch_url() {
  docker run --rm --network host --entrypoint /usr/bin/wget \
    "$upstream_image" -q -O - "$1"
}

for command_name in awk date docker git grep jq mktemp sed sort tr wc; do
  require_command "$command_name"
done
if ! command -v sha256sum >/dev/null 2>&1; then
  require_command shasum
fi

case "$smoke_seconds" in ''|*[!0-9]*) fail "smoke duration must be an integer" ;; esac
case "$smoke_connections" in ''|*[!0-9]*) fail "smoke connections must be an integer" ;; esac
[ "$smoke_seconds" -gt 0 ] || fail "smoke duration must be positive"
[ "$smoke_connections" -gt 0 ] || fail "smoke connections must be positive"

selected_products_seen=""
selected_products_count=0
qualified_products=""
qualified_product_count=0
for selected_product in $comparison_products; do
  case "$selected_product" in
    bonvoyage|envoy|nginx|haproxy) ;;
    *) fail "unsupported Phase 2 product '$selected_product'" ;;
  esac
  case " $selected_products_seen " in
    *" $selected_product "*) fail "duplicate Phase 2 product '$selected_product'" ;;
  esac
  selected_products_seen="$selected_products_seen $selected_product"
  selected_products_count=$((selected_products_count + 1))
  if [ "$selected_product" != "bonvoyage" ]; then
    qualified_products="${qualified_products:+$qualified_products }$selected_product"
    qualified_product_count=$((qualified_product_count + 1))
  fi
done
[ "$selected_products_count" -ge 2 ] || \
  fail "qualification requires BonVoyage and at least one comparator"
product_selected bonvoyage || \
  fail "Phase 2 product selection must include bonvoyage"

docker_arch="$(docker info --format '{{.Architecture}}')"
case "$docker_arch" in
  x86_64|amd64)
    manifest_key="linux_amd64"
    architecture="x86_64"
    ;;
  aarch64|arm64)
    manifest_key="linux_arm64"
    architecture="aarch64"
    ;;
  *) fail "unsupported Docker architecture '$docker_arch'" ;;
esac

evidence_class="local-functional"
if [ "$publishable_request" = "1" ]; then
  [ "$qualified_product_count" -eq 3 ] || \
    fail "native qualification requires every locked comparator"
  [ "$(uname -s)" = "Linux" ] || \
    fail "native comparator qualification requires Linux"
  [ "$architecture" = "x86_64" ] || \
    fail "native comparator qualification requires x86-64"
  source_changes="$(git status --porcelain -- . \
    ':(exclude)benchmarks/results/**' 2>/dev/null || true)"
  [ -z "$source_changes" ] || \
    fail "native comparator qualification requires a clean source tree"
  [ "$qualification_attestation" = "fairness-contract-reviewed" ] || \
    fail "native qualification requires the fairness-contract attestation"
  evidence_class="native-qualification"
fi

captured_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
run_stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
run_id="phase2-products-$run_stamp"
output_root="${BONVOYAGE_PHASE2_QUALIFICATION_DIR:-benchmarks/results/qualification}"
run_dir="$repo_root/$output_root/$run_id"
mkdir -p "$run_dir"
products_jsonl="$run_dir/.products.jsonl"
: >"$products_jsonl"
cp "$product_lock" "$run_dir/product-lock.json"
cp benchmarks/products/envoy/envoy.yaml "$run_dir/envoy.config"
cp benchmarks/products/nginx/nginx.conf "$run_dir/nginx.config"
cp benchmarks/products/haproxy/haproxy.cfg "$run_dir/haproxy.config"

suffix="$$-$run_stamp"
upstream_name="bonvoyage-p2-qualification-upstream-$suffix"
gateway_name=""
extract_name=""

cleanup() {
  set +e
  [ -z "$gateway_name" ] || docker rm --force "$gateway_name" >/dev/null 2>&1
  [ -z "$upstream_name" ] || docker rm --force "$upstream_name" >/dev/null 2>&1
  [ -z "$extract_name" ] || docker rm --force "$extract_name" >/dev/null 2>&1
  rm -f "$products_jsonl"
}
trap cleanup EXIT INT TERM

if [ "$skip_upstream_build" != "1" ]; then
  docker buildx build --load --tag "$upstream_image" benchmarks/products/upstream
fi

loadgen_repository="$(jq -r '.load_generator.repository' "$product_lock")"
loadgen_manifest="$(jq -r --arg key "$manifest_key" \
  '.load_generator.manifests[$key]' "$product_lock")"
loadgen_ref="$loadgen_repository@$loadgen_manifest"
if [ "$skip_pull" != "1" ]; then
  docker pull "$loadgen_ref" >/dev/null
fi

docker_run "$upstream_cpus" --detach \
  --name "$upstream_name" \
  --network host \
  --memory 512m \
  --memory-swap 512m \
  --pids-limit 1024 \
  "$upstream_image" >/dev/null
if ! wait_for_url "http://127.0.0.1:8081/healthz" "controlled upstream"; then
  docker logs "$upstream_name" >&2 || true
  fail "controlled upstream startup failed"
fi

qualify_product() {
  product="$1"
  product_record="$(jq -c --arg product "$product" \
    '.products[] | select(.name == $product)' "$product_lock")"
  [ -n "$product_record" ] || fail "product '$product' is absent from the lock"

  repository="$(printf '%s' "$product_record" | jq -r '.repository')"
  version="$(printf '%s' "$product_record" | jq -r '.version')"
  manifest="$(printf '%s' "$product_record" | jq -r --arg key "$manifest_key" \
    '.manifests[$key]')"
  config="$(printf '%s' "$product_record" | jq -r '.config')"
  locked_config_sha256="$(printf '%s' "$product_record" | jq -r '.config_sha256')"
  executable="$(printf '%s' "$product_record" | jq -r '.executable')"
  readiness_path="$(printf '%s' "$product_record" | jq -r '.readiness_path')"
  image_ref="$repository@$manifest"
  config_sha256="$(sha256_file "$config")"
  [ "$config_sha256" = "$locked_config_sha256" ] || \
    fail "$product config digest does not match the product lock"

  echo "Qualifying $product $version ($architecture)..."
  if [ "$skip_pull" != "1" ]; then
    docker pull "$image_ref" >/dev/null
  fi
  image_id="$(docker image inspect --format '{{.Id}}' "$image_ref")"

  case "$product" in
    envoy)
      version_output="$(docker run --rm --entrypoint "$executable" \
        "$image_ref" --version 2>&1 | tr '\n' ' ')"
      printf '%s' "$version_output" | grep -F "/$version/" >/dev/null || \
        fail "$product image reported an unexpected version: $version_output"
      docker run --rm \
        --user 65532:65532 \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --volume "$repo_root/$config:/etc/phase2/envoy.yaml:ro" \
        --entrypoint "$executable" \
        "$image_ref" \
        --mode validate -c /etc/phase2/envoy.yaml \
        --concurrency 1 --disable-hot-restart --log-level critical >/dev/null
      ;;
    nginx)
      version_output="$(docker run --rm --entrypoint "$executable" \
        "$image_ref" -v 2>&1 | tr '\n' ' ')"
      printf '%s' "$version_output" | grep -F "nginx/$version" >/dev/null || \
        fail "$product image reported an unexpected version: $version_output"
      docker run --rm \
        --user 65532:65532 \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --volume "$repo_root/$config:/etc/nginx/nginx.conf:ro" \
        --entrypoint "$executable" \
        "$image_ref" \
        -t -c /etc/nginx/nginx.conf -g 'worker_processes 1;' >/dev/null
      ;;
    haproxy)
      version_output="$(docker run --rm --entrypoint "$executable" \
        "$image_ref" -v 2>&1 | sed -n '1p')"
      printf '%s' "$version_output" | grep -F "version $version" >/dev/null || \
        fail "$product image reported an unexpected version: $version_output"
      docker run --rm \
        --user 65532:65532 \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --volume "$repo_root/$config:/usr/local/etc/haproxy/haproxy.cfg:ro" \
        --entrypoint "$executable" \
        "$image_ref" \
        -c -f /usr/local/etc/haproxy/haproxy.cfg -nbthread 1 >/dev/null
      ;;
    *) fail "unsupported product '$product'" ;;
  esac

  extract_name="bonvoyage-p2-extract-$product-$suffix"
  docker create --name "$extract_name" --entrypoint "$executable" \
    "$image_ref" --version >/dev/null
  docker cp "$extract_name:$executable" "$run_dir/.$product-executable" >/dev/null
  executable_sha256="$(sha256_file "$run_dir/.$product-executable")"
  docker rm "$extract_name" >/dev/null
  extract_name=""
  rm -f "$run_dir/.$product-executable"

  gateway_name="bonvoyage-p2-qualification-$product-$suffix"
  case "$product" in
    envoy)
      docker_run "$gateway_cpus" --detach --name "$gateway_name" --network host \
        --user 65532:65532 --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --cap-drop ALL --security-opt no-new-privileges \
        --memory 512m --memory-swap 512m --pids-limit 4096 \
        --ulimit nofile=1048576:1048576 \
        --volume "$repo_root/$config:/etc/phase2/envoy.yaml:ro" \
        --entrypoint "$executable" "$image_ref" \
        -c /etc/phase2/envoy.yaml --concurrency 1 \
        --disable-hot-restart --log-level critical >/dev/null
      ;;
    nginx)
      docker_run "$gateway_cpus" --detach --name "$gateway_name" --network host \
        --user 65532:65532 --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --cap-drop ALL --security-opt no-new-privileges \
        --memory 512m --memory-swap 512m --pids-limit 4096 \
        --ulimit nofile=1048576:1048576 \
        --volume "$repo_root/$config:/etc/nginx/nginx.conf:ro" \
        --entrypoint "$executable" "$image_ref" \
        -c /etc/nginx/nginx.conf \
        -g 'daemon off; worker_processes 1;' >/dev/null
      ;;
    haproxy)
      docker_run "$gateway_cpus" --detach --name "$gateway_name" --network host \
        --user 65532:65532 --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --cap-drop ALL --security-opt no-new-privileges \
        --memory 512m --memory-swap 512m --pids-limit 4096 \
        --ulimit nofile=1048576:1048576 \
        --volume "$repo_root/$config:/usr/local/etc/haproxy/haproxy.cfg:ro" \
        --entrypoint "$executable" "$image_ref" \
        -W -db -f /usr/local/etc/haproxy/haproxy.cfg -nbthread 1 >/dev/null
      ;;
  esac

  if ! wait_for_url "http://127.0.0.1:9901$readiness_path" "$product"; then
    docker logs "$gateway_name" >&2 || true
    fail "$product readiness check failed"
  fi
  if ! wait_for_url "http://127.0.0.1:8080/payload/256" "$product data path"; then
    docker logs "$gateway_name" >&2 || true
    fail "$product data path did not become ready"
  fi
  fetch_url "http://127.0.0.1:8080/payload/256" >"$run_dir/$product.payload"
  payload_sha256="$(sha256_file "$run_dir/$product.payload")"
  [ "$(wc -c <"$run_dir/$product.payload" | tr -d ' ')" -eq 256 ] || \
    fail "$product returned the wrong payload size"
  [ "$payload_sha256" = "$expected_payload_sha256" ] || \
    fail "$product returned payload digest $payload_sha256"

  docker_run "$load_generator_cpus" --rm --network host \
    "$loadgen_ref" \
    -z "${smoke_seconds}s" -c "$smoke_connections" -w \
    --http-version 1.1 --disable-compression \
    -H 'accept: application/octet-stream' --no-tui \
    --output-format json http://127.0.0.1:8080/payload/256 \
    >"$run_dir/$product.oha.json"
  success_rate="$(jq -r '
    ([.statusCodeDistribution[]?] | add // 0) as $responses |
    ([.errorDistribution[]?] | add // 0) as $errors |
    (.statusCodeDistribution["200"] // 0) as $successful |
    if ($responses + $errors) == 0 then 0
    else $successful / ($responses + $errors) end
  ' "$run_dir/$product.oha.json")"
  requests_per_second="$(jq -r '
    (.statusCodeDistribution["200"] // 0) / .summary.total
  ' "$run_dir/$product.oha.json")"
  if ! awk -v success="$success_rate" -v maximum="$maximum_error_rate" \
    -v rate="$requests_per_second" \
    'BEGIN {exit !(success >= (1 - maximum) && rate > 0)}'; then
    fail "$product HTTP 200 load smoke exceeded the error ceiling"
  fi
  [ "$(docker inspect --format '{{.State.OOMKilled}}' "$upstream_name")" = "false" ] || \
    fail "controlled upstream encountered an out-of-memory event"

  docker stop --timeout 30 "$gateway_name" >/dev/null
  docker logs "$gateway_name" >"$run_dir/$product.log" 2>&1
  gateway_exit="$(docker inspect --format '{{.State.ExitCode}}' "$gateway_name")"
  docker rm "$gateway_name" >/dev/null
  gateway_name=""
  [ "$gateway_exit" -eq 0 ] || fail "$product exited with status $gateway_exit"

  jq -n \
    --arg name "$product" \
    --arg version "$version" \
    --arg version_output "$version_output" \
    --arg image_manifest_digest "$manifest" \
    --arg image_id "$image_id" \
    --arg config_sha256 "$config_sha256" \
    --arg executable_sha256 "$executable_sha256" \
    --argjson success_rate "$success_rate" \
    --argjson requests_per_second "$requests_per_second" \
    '{
      name: $name,
      version: $version,
      version_output: $version_output,
      image_manifest_digest: $image_manifest_digest,
      image_id: $image_id,
      config_sha256: $config_sha256,
      executable_sha256: $executable_sha256,
      config_valid: true,
      ready: true,
      payload_valid: true,
      smoke_success_rate: $success_rate,
      smoke_requests_per_second: $requests_per_second,
      passed: true
    }' >>"$products_jsonl"
}

for product in $qualified_products; do
  qualify_product "$product"
done

docker logs "$upstream_name" >"$run_dir/upstream.log" 2>&1
product_lock_sha256="$(sha256_file "$product_lock")"
qualification_path="$run_dir/$run_id.qualification.json"
jq -s \
  --arg run_id "$run_id" \
  --arg captured_at "$captured_at" \
  --arg evidence_class "$evidence_class" \
  --arg architecture "$architecture" \
  --arg product_lock_sha256 "$product_lock_sha256" \
  --argjson expected_products "$qualified_product_count" \
  '{
    schema_version: 1,
    run_id: $run_id,
    captured_at: $captured_at,
    evidence_class: $evidence_class,
    architecture: $architecture,
    product_lock_sha256: $product_lock_sha256,
    payload: {
      bytes: 256,
      sha256: "85e62acd750c4eb56b7b6a1d66dca5bfaac5f062608a1a893410d0288936c09a"
    },
    products: .,
    passed: (length == $expected_products and all(.passed))
  }' "$products_jsonl" >"$qualification_path"

report_path="$run_dir/$run_id.md"
{
  printf '# Phase 2 Comparator Qualification: %s\n\n' "$run_id"
  printf -- "- Evidence class: \`%s\`\n" "$evidence_class"
  printf -- "- Architecture: \`%s\`\n" "$architecture"
  printf -- "- Product lock SHA-256: \`%s\`\n\n" "$product_lock_sha256"
  printf '| Product | Version | Smoke RPS | Success | Result |\n'
  printf '| --- | --- | ---: | ---: | --- |\n'
  jq -r '.products[] | "| \(.name) | \(.version) | \(.smoke_requests_per_second | floor) | \(.smoke_success_rate) | pass |"' \
    "$qualification_path"
  printf '\nThis record qualifies configuration, startup, payload identity, and a short HTTP/1.1 load only. It is not competitive performance evidence.\n'
} >"$report_path"

rm -f "$products_jsonl"
echo "Phase 2 product qualification: ${qualification_path#"$repo_root"/}"
