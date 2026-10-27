#!/bin/sh
set -eu

platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
iterations="${BONVOYAGE_LOAD_BALANCING_COST_ITERATIONS:-5000000}"
repetitions="${BONVOYAGE_LOAD_BALANCING_COST_REPETITIONS:-5}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="load-balancing-cost-$timestamp"
image="routesphere-global/bonvoyage-load-balancing-cost:$timestamp"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-load-balancing-cost.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_LOAD_BALANCING_EVIDENCE_ROOT:-benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"

cleanup() {
  status="$?"
  if [ "$status" -ne 0 ]; then
    echo "load-balancing cost probe failed; temporary evidence: $stage_dir" >&2
  else
    rm -rf "$work_dir"
  fi
  return "$status"
}
trap cleanup EXIT INT TERM

for command_name in date docker git mktemp python3 uname; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name is required" >&2
    exit 1
  }
done

case "$iterations:$repetitions" in
  *[!0-9:]*|0:*|*:0)
    echo "cost iterations and repetitions must be positive integers" >&2
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

docker buildx build --platform "$platform" --target bonvoyage-build \
  --load --tag "$image" --file deploy/docker/bonvoyage/Dockerfile .
docker run --rm --platform "$platform" "$image" \
  /usr/src/bonvoyage/build/dataplane/bonvoyage-endpoint-selector-benchmark \
  "$iterations" "$repetitions" >"$stage_dir/raw.csv"
docker image inspect "$image" >"$stage_dir/build-image.inspect.json"

python3 - "$stage_dir/raw.csv" "$stage_dir/summary.json" \
  "$stage_dir/summary.csv" "$stage_dir/summary.txt" <<'PY'
import csv
import json
import statistics
import sys

raw_path, json_path, csv_path, text_path = sys.argv[1:]
with open(raw_path, newline="", encoding="utf-8") as source:
    rows = list(csv.DictReader(source))

expected_policies = {"round_robin", "random", "least_request"}
expected_modes = {"immediate", "window_32"}
expected_endpoints = {2, 8, 64}
groups = {}
for row in rows:
    key = (row["mode"], int(row["endpoint_count"]), row["policy"])
    groups.setdefault(key, []).append(float(row["ns_per_operation"]))

assert {key[0] for key in groups} == expected_modes
assert {key[1] for key in groups} == expected_endpoints
assert {key[2] for key in groups} == expected_policies
repetitions = len(next(iter(groups.values())))
assert repetitions >= 3
assert all(len(samples) == repetitions for samples in groups.values())

results = []
for mode in sorted(expected_modes):
    for endpoint_count in sorted(expected_endpoints):
        baseline = statistics.median(
            groups[(mode, endpoint_count, "round_robin")]
        )
        for policy in ("round_robin", "random", "least_request"):
            samples = groups[(mode, endpoint_count, policy)]
            median = statistics.median(samples)
            results.append({
                "mode": mode,
                "endpoint_count": endpoint_count,
                "policy": policy,
                "samples_ns_per_operation": samples,
                "median_ns_per_operation": median,
                "ratio_to_round_robin": median / baseline,
                "spread_percent_of_median":
                    (max(samples) - min(samples)) / median * 100,
            })

summary = {
    "schema_version": 1,
    "evidence": {
        "class": "local-engineering",
        "publishable": False,
        "marketing_use_authorized": False,
        "claim": "Local selector operation-cost observation only",
    },
    "controls": {
        "repetitions": repetitions,
        "iterations_per_repetition": int(rows[0]["iterations"]),
        "endpoint_counts": sorted(expected_endpoints),
        "modes": sorted(expected_modes),
        "weights": "all endpoints weight 1",
        "passive_ejection": "disabled during cost measurement",
    },
    "results": results,
    "limitations": [
        "The local Docker VM is shared and CPUs are not isolated.",
        "This measures selector plus completion bookkeeping, not end-to-end gateway throughput.",
        "Dedicated native gateway measurements remain required before publication.",
    ],
}
with open(json_path, "w", encoding="utf-8") as output:
    json.dump(summary, output, indent=2, sort_keys=True)
    output.write("\n")

with open(csv_path, "w", newline="", encoding="utf-8") as output:
    writer = csv.writer(output)
    writer.writerow([
        "mode", "endpoint_count", "policy", "median_ns_per_operation",
        "ratio_to_round_robin", "spread_percent_of_median",
    ])
    for result in results:
        writer.writerow([
            result["mode"], result["endpoint_count"], result["policy"],
            f'{result["median_ns_per_operation"]:.3f}',
            f'{result["ratio_to_round_robin"]:.3f}',
            f'{result["spread_percent_of_median"]:.3f}',
        ])

with open(text_path, "w", encoding="utf-8") as output:
    output.write("LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE\n")
    for result in results:
        output.write(
            f'{result["mode"]} endpoints={result["endpoint_count"]} '
            f'{result["policy"]}: '
            f'{result["median_ns_per_operation"]:.3f} ns/op; '
            f'{result["ratio_to_round_robin"]:.3f}x round-robin; '
            f'spread {result["spread_percent_of_median"]:.2f}%\n'
        )
PY

source_commit="$(git rev-parse HEAD)"
if [ -z "$(git status --porcelain)" ]; then
  source_dirty=false
else
  source_dirty=true
fi
image_id="$(docker image inspect "$image" --format '{{.Id}}')"
cat >"$stage_dir/metadata.txt" <<EOF
captured_at_utc=$timestamp
run_id=$run_id
source_commit=$source_commit
source_dirty=$source_dirty
host=$(uname -s) $(uname -r) $(uname -m)
platform=$platform
python=$(python3 --version 2>&1)
build_image=$image
build_image_id=$image_id
iterations_per_repetition=$iterations
repetitions=$repetitions
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 load-balancing selector cost evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The release-built authored selector and completion bookkeeping were measured directly for round-robin, weighted-random, and exact weighted least-request policies with 2, 8, and 64 equal-weight endpoints. The immediate mode completes each selection before the next. The window mode maintains 32 active requests while rotating completions and selections.

This isolates algorithm cost from transport and upstream capacity, but it is not an end-to-end performance result. Shared Docker scheduling and unisolated CPUs prevent publication-quality claims. The dedicated native campaign must repeat feature-cost measurement in the complete gateway path.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
dataplane/CMakeLists.txt
dataplane/benchmarks/endpoint_selector_benchmark.cc
dataplane/include/bonvoyage/runtime/endpoint_selector.hh
dataplane/src/endpoint_selector.cc
scripts/phase3-load-balancing-cost.sh
EOF
while IFS= read -r source_file; do
  hash_file "$source_file"
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md build-image.inspect.json metadata.txt raw.csv \
    source-checksums.sha256 summary.csv summary.json summary.txt; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-load-balancing-cost.txt.tmp"
mv "$output_root/current-load-balancing-cost.txt.tmp" \
  "$output_root/current-load-balancing-cost.txt"

printf 'Load-balancing selector cost captured: %s\n' "$output_dir"
cat "$output_dir/summary.txt"
