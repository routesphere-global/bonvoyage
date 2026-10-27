#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"

if [ "$(uname -s)" != Linux ]; then
  echo "runtime glibc observer compilation requires Linux" >&2
  exit 2
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-glibc-trace-test.XXXXXX")"
cleanup() {
  status="$?"
  rm -rf "$work_dir"
  exit "$status"
}
trap cleanup EXIT INT TERM

cc -std=gnu11 -shared -fPIC -O2 -Wall -Wextra -Werror \
  -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
  -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
  -o "$work_dir/observer.so" \
  "$repo_root/scripts/runtime-glibc-call-trace.c" -ldl
cc -std=gnu11 -fPIE -pie -O2 -Wall -Wextra -Werror \
  -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
  -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
  -o "$work_dir/selftest" \
  "$repo_root/scripts/runtime-glibc-call-trace-selftest.c"

env BONVOYAGE_GLIBC_TRACE=1 LD_PRELOAD="$work_dir/observer.so" \
  "$work_dir/selftest" >"$work_dir/control.log" 2>&1
env BONVOYAGE_GLIBC_TRACE=1 LD_PRELOAD="$work_dir/observer.so" \
  /bin/true >"$work_dir/scenario.log" 2>&1

python3 -B "$repo_root/scripts/analyze-runtime-glibc-call-trace.py" \
  --control "selftest=$work_dir/control.log" \
  --scenario "no-op=$work_dir/scenario.log" \
  --output "$work_dir/result.json"
grep -F '"observation_gate_passed": true' "$work_dir/result.json" >/dev/null

echo "Runtime glibc call observer compilation and positive control passed."
