#!/bin/sh
set -eu
export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
output=''
service='bonvoyage.service'
snapshot_file='/etc/bonvoyage/snapshot.pb'
downstream_port=''
interval_id=''
tracer_launcher=''
tracer_stop_signal='none'

fail() { echo "phase5-socket-output-collector: $*" >&2; exit 1; }

capture_identity() {
  destination="$1"
  if [ "$(id -u)" -eq 0 ]; then
    python3 -B "$script_dir/linux_socket_output.py" identity \
      --service "$service" --interval-id "$interval_id" \
      --snapshot-file "$snapshot_file" --output "$destination"
  else
    # Root reads protected runtime artifacts; the operator owns the evidence.
    # shellcheck disable=SC2024
    sudo -n python3 -B "$script_dir/linux_socket_output.py" identity \
      --service "$service" --interval-id "$interval_id" \
      --snapshot-file "$snapshot_file" --output - >"$destination"
  fi
}

stop_tracer() {
  [ -n "$tracer_launcher" ] || return 0
  if kill -0 "$tracer_launcher" 2>/dev/null; then
    tracer_stop_signal='SIGINT'
    kill -INT "$tracer_launcher" 2>/dev/null || true
  fi
  attempt=0
  while kill -0 "$tracer_launcher" 2>/dev/null && [ "$attempt" -lt 50 ]; do
    attempt=$((attempt + 1))
    sleep 0.1
  done
  if kill -0 "$tracer_launcher" 2>/dev/null; then
    tracer_stop_signal='SIGTERM'
    kill -TERM "$tracer_launcher" 2>/dev/null || true
  fi
  attempt=0
  while kill -0 "$tracer_launcher" 2>/dev/null && [ "$attempt" -lt 10 ]; do
    attempt=$((attempt + 1))
    sleep 0.1
  done
  if kill -0 "$tracer_launcher" 2>/dev/null; then
    tracer_stop_signal='SIGKILL'
    kill -KILL "$tracer_launcher" 2>/dev/null || true
  fi
}

finalize_checksums() {
  [ -d "$output" ] || return 0
  (
    cd "$output"
    manifest="$(mktemp "${TMPDIR:-/tmp}/bonvoyage-socket-output.XXXXXX")"
    find . -type f ! -name checksums.sha256 | LC_ALL=C sort |
      while IFS= read -r file; do sha256sum "$file"; done >"$manifest"
    mv "$manifest" checksums.sha256
    sha256sum -c checksums.sha256 >/dev/null
  )
}

cleanup() {
  status="$?"
  trap - EXIT INT TERM
  set +e
  stop_tracer
  [ -z "$tracer_launcher" ] || wait "$tracer_launcher" 2>/dev/null
  if [ -d "$output" ]; then
    if ! git -C "$repo" status --porcelain \
      >"$output/source-status-after.txt" \
      2>"$output/source-status-after.stderr"; then
      status=1
    fi
    printf '%s\n' "$tracer_stop_signal" >"$output/tracer-stop-signal.txt"
    printf '%s\n' "$status" >"$output/collector-exit-code.txt"
    if ! finalize_checksums; then
      status=1
      printf '%s\n' "$status" >"$output/collector-exit-code.txt"
      finalize_checksums >/dev/null 2>&1 || true
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --service) service="$2"; shift 2 ;;
    --snapshot-file) snapshot_file="$2"; shift 2 ;;
    --downstream-port) downstream_port="$2"; shift 2 ;;
    --interval-id) interval_id="$2"; shift 2 ;;
    --) shift; break ;;
    *) fail "unknown option: $1" ;;
  esac
done

[ -n "$output" ] && [ -n "$downstream_port" ] &&
  [ -n "$interval_id" ] && [ "$#" -gt 0 ] ||
  fail 'usage: --output DIR --downstream-port PORT --interval-id ID [--service UNIT] [--snapshot-file FILE] -- CLIENT ARG...'
case "$output" in /*) ;; *) fail 'output must be an absolute path' ;; esac
case "$snapshot_file" in
  /*) ;;
  *) fail 'snapshot file must be an absolute path' ;;
esac
case "$downstream_port" in
  ''|*[!0-9]*) fail 'downstream port must be an integer' ;;
esac
[ "$downstream_port" -ge 1 ] && [ "$downstream_port" -le 65535 ] ||
  fail 'downstream port must be between 1 and 65535'
case "$interval_id" in
  *[!A-Za-z0-9._:-]*|'') fail 'interval id contains unsupported characters' ;;
esac
[ ! -e "$output" ] || fail "output already exists: $output"
for tool in bpftrace git python3 sha256sum systemctl uname; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
[ -r /sys/kernel/btf/vmlinux ] || fail 'kernel BTF is required'
[ -z "$(git -C "$repo" status --porcelain)" ] || fail 'clean source required'
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || fail 'sudo is required for bpftrace'
  sudo -n true >/dev/null 2>&1 || fail 'non-interactive sudo is required for bpftrace'
  if ! sudo -n test -f "$snapshot_file" ||
     ! sudo -n test -r "$snapshot_file"; then
    fail "snapshot file is not readable by the collector: $snapshot_file"
  fi
else
  [ -f "$snapshot_file" ] && [ -r "$snapshot_file" ] ||
    fail "snapshot file is not readable by the collector: $snapshot_file"
fi

umask 077
mkdir -p "$output"
git -C "$repo" rev-parse HEAD >"$output/source-commit.txt"
git -C "$repo" status --porcelain >"$output/source-status.txt"
cp "$script_dir/response-path-socket-output.bt" "$output/collector.bt"
cp "$script_dir/linux_socket_output.py" "$output/linux_socket_output.py"
bpftrace --version >"$output/bpftrace-version.txt"
uname -a >"$output/uname.txt"
capture_identity "$output/process-before.json"
pid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' \
  "$output/process-before.json")"
python3 - "$output/client-argv.json" "$@" <<'PY'
import json
import sys

with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(sys.argv[2:], output, indent=2)
    output.write("\n")
PY

if [ "$(id -u)" -eq 0 ]; then
  BPFTRACE_PERF_RB_PAGES=64 bpftrace -B line \
    "$script_dir/response-path-socket-output.bt" "$pid" "$downstream_port" \
    >"$output/bpftrace.stdout" 2>"$output/bpftrace.stderr" &
else
  # Keep evidence files owned by the operator; only bpftrace needs privilege.
  # shellcheck disable=SC2024
  sudo -n env BPFTRACE_PERF_RB_PAGES=64 bpftrace -B line \
    "$script_dir/response-path-socket-output.bt" "$pid" "$downstream_port" \
    >"$output/bpftrace.stdout" 2>"$output/bpftrace.stderr" &
fi
tracer_launcher="$!"

attempt=0
until grep -Fxq 'BONVOYAGE_SOCKET_OUTPUT_READY' "$output/bpftrace.stdout"; do
  attempt=$((attempt + 1))
  if ! kill -0 "$tracer_launcher" 2>/dev/null; then
    wait "$tracer_launcher" 2>/dev/null || true
    tracer_launcher=''
    fail "bpftrace exited before readiness; evidence retained in $output"
  fi
  [ "$attempt" -lt 100 ] ||
    fail "bpftrace readiness timed out; evidence retained in $output"
  sleep 0.1
done

started_ns="$(python3 -c 'import time; print(time.monotonic_ns())')"
set +e
"$@" >"$output/client.stdout" 2>"$output/client.stderr"
client_status="$?"
set -e
ended_ns="$(python3 -c 'import time; print(time.monotonic_ns())')"
printf '%s\n' "$client_status" >"$output/client-exit-code.txt"

stop_tracer
set +e
wait "$tracer_launcher"
tracer_status="$?"
set -e
tracer_launcher=''
duration_ns=$((ended_ns - started_ns))
printf '%s\n' "$tracer_status" >"$output/tracer-exit-code.txt"
printf '%s\n' "$started_ns" >"$output/started-monotonic-ns.txt"
printf '%s\n' "$ended_ns" >"$output/ended-monotonic-ns.txt"
printf '%s\n' "$duration_ns" >"$output/duration-nanoseconds.txt"

capture_identity "$output/process-after.json"
set +e
python3 -B "$script_dir/linux_socket_output.py" parse \
  --trace "$output/bpftrace.stdout" --stderr "$output/bpftrace.stderr" \
  --process-before "$output/process-before.json" \
  --process-after "$output/process-after.json" \
  --interval-id "$interval_id" --duration-nanoseconds "$duration_ns" \
  --output "$output/socket-output.json" \
  --diagnostics "$output/collector-diagnostics.json"
parser_status="$?"
set -e
printf '%s\n' "$parser_status" >"$output/parser-exit-code.txt"
git -C "$repo" status --porcelain >"$output/source-status-after.txt"
[ ! -s "$output/source-status-after.txt" ] ||
  fail "source changed during collection; evidence retained in $output"

[ "$client_status" -eq 0 ] ||
  fail "client exited $client_status; evidence retained in $output"
case "$tracer_status" in 0|130) ;; *)
  fail "bpftrace exited $tracer_status; evidence retained in $output" ;;
esac
[ "$parser_status" -eq 0 ] ||
  fail "collector parsing failed; evidence retained in $output"
python3 - "$output/socket-output.json" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
if value["fatal_errors"] != 0 or value["lost_events"] != 0:
    raise SystemExit("socket output contains fatal errors or lost events")
PY

echo "SOCKET_OUTPUT_DIR=$output"
