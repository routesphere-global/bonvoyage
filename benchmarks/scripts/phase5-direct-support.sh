#!/bin/sh
set -eu
export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
output=''
load_host=''
upstream_host_a=''
upstream_host_b=''
load_repository='/home/ubuntu/RouteSphere-BonVoyage'

fail() { echo "phase5-direct-support: $*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --load-host) load_host="$2"; shift 2 ;;
    --upstream-host-a) upstream_host_a="$2"; shift 2 ;;
    --upstream-host-b) upstream_host_b="$2"; shift 2 ;;
    --load-repository) load_repository="$2"; shift 2 ;;
    --) shift; break ;;
    *) fail "unknown option: $1" ;;
  esac
done
[ -n "$output" ] && [ -n "$load_host" ] && [ -n "$upstream_host_a" ] &&
  [ -n "$upstream_host_b" ] && [ "$#" -gt 0 ] ||
  fail 'usage: --output DIR --load-host HOST --upstream-host-a HOST --upstream-host-b HOST [--load-repository DIR] -- CLIENT ARG...'
[ "$load_host" != "$upstream_host_a" ] && [ "$load_host" != "$upstream_host_b" ] &&
  [ "$upstream_host_a" != "$upstream_host_b" ] ||
  fail 'support roles must be separate hosts'
case "$load_repository" in /*) ;; *) fail 'load repository must be absolute' ;; esac
[ ! -e "$output" ] || fail "output already exists: $output"
for tool in cmp git sha256sum ssh; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
[ -z "$(git -C "$repo" status --porcelain)" ] || fail 'clean source required'

umask 077
mkdir -p "$output"
git -C "$repo" rev-parse HEAD >"$output/source-commit.txt"
sha256sum "$script_dir/phase5-oha-lanes.mjs" | awk '{print $1}' \
  >"$output/expected-runner-sha256.txt"
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$load_host" hostname \
  >"$output/loadgen-host.txt"
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$upstream_host_a" hostname \
  >"$output/upstream-a-host.txt"
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$upstream_host_b" hostname \
  >"$output/upstream-b-host.txt"

support_cpu() {
  stage="$1"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$load_host" cat /proc/stat \
    >"$output/loadgen-proc-$stage.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$upstream_host_a" cat /proc/stat \
    >"$output/upstream-a-proc-$stage.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$upstream_host_b" cat /proc/stat \
    >"$output/upstream-b-proc-$stage.txt"
}

load_source() {
  stage="$1"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$load_host" \
    git -C "$load_repository" rev-parse HEAD \
    >"$output/loadgen-source-commit-$stage.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$load_host" \
    git -C "$load_repository" status --porcelain \
    >"$output/loadgen-source-status-$stage.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$load_host" \
    sha256sum "$load_repository/benchmarks/scripts/phase5-oha-lanes.mjs" |
    awk '{print $1}' >"$output/loadgen-runner-sha256-$stage.txt"
}

load_source before
support_cpu before
set +e
"$@" >"$output/direct-upstream.oha.json" 2>"$output/client.stderr"
client_status="$?"
set -e
support_cpu after
load_source after
printf '%s\n' "$client_status" >"$output/client-exit-code.txt"

(
  cd "$output"
  manifest="$(mktemp "${TMPDIR:-/tmp}/bonvoyage-perf01-direct-checksums.XXXXXX")"
  find . -type f ! -name checksums.sha256 | LC_ALL=C sort |
    while IFS= read -r file; do sha256sum "$file"; done >"$manifest"
  mv "$manifest" checksums.sha256
  sha256sum -c checksums.sha256 >/dev/null
)

expected_commit="$(cat "$output/source-commit.txt")"
expected_runner="$(cat "$output/expected-runner-sha256.txt")"
for stage in before after; do
  [ "$(cat "$output/loadgen-source-commit-$stage.txt")" = "$expected_commit" ] ||
    fail "load-generator source commit changed during $stage capture"
  [ ! -s "$output/loadgen-source-status-$stage.txt" ] ||
    fail "load-generator source was dirty during $stage capture"
  [ "$(cat "$output/loadgen-runner-sha256-$stage.txt")" = "$expected_runner" ] ||
    fail "load-generator runner digest changed during $stage capture"
done
cmp -s "$output/loadgen-source-commit-before.txt" \
  "$output/loadgen-source-commit-after.txt" || fail 'load-generator source changed'
cmp -s "$output/loadgen-runner-sha256-before.txt" \
  "$output/loadgen-runner-sha256-after.txt" || fail 'load-generator runner changed'
[ "$client_status" -eq 0 ] ||
  fail "client exited $client_status; checksum-bound partial evidence retained in $output"
echo "DIRECT_SUPPORT_DIR=$output"
