#!/bin/sh
set -eu
export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
output=''
service='bonvoyage.service'
snapshot_file='/etc/bonvoyage/snapshot.pb'
configuration_file=''
runtime_manifest=''
runtime_manifest_sha256=''
metrics_url='http://127.0.0.1:9090/metrics'
downstream_port=''
interval_id=''
run_id=''
point_id=''
tls=''
payload_bytes=''

fail() { echo "phase5-response-path-native: $*" >&2; exit 1; }

capture_identity() {
  destination="$1"
  if [ "$(id -u)" -eq 0 ]; then
    python3 -B "$script_dir/linux_socket_output.py" identity \
      --service "$service" --interval-id "$interval_id" \
      --snapshot-file "$snapshot_file" --output "$destination"
  else
    # Root reads the protected snapshot and process executable. Evidence files
    # remain owned by the unprivileged operator.
    # shellcheck disable=SC2024
    sudo -n python3 -B "$script_dir/linux_socket_output.py" identity \
      --service "$service" --interval-id "$interval_id" \
      --snapshot-file "$snapshot_file" --output - >"$destination"
  fi
}

capture_threads() {
  process_id="$1"
  destination="$2"
  python3 - "$process_id" "$destination" <<'PY'
import pathlib
import sys

pid = int(sys.argv[1])
root = pathlib.Path("/proc") / str(pid) / "task"
tids = sorted(int(entry.name) for entry in root.iterdir()
              if entry.is_dir() and entry.name.isdecimal())
if not tids or pid not in tids:
    raise SystemExit("gateway thread set is empty or excludes its leader")
pathlib.Path(sys.argv[2]).write_text(
    ",".join(str(tid) for tid in tids) + "\n", encoding="ascii")
PY
}

seal() {
  [ -d "$output" ] || return 0
  (
    cd "$output"
    manifest="$(mktemp "${TMPDIR:-/tmp}/bonvoyage-perf03-native.XXXXXX")"
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
  if [ -d "$output" ]; then
    git -C "$repo" status --porcelain >"$output/source-status-after.txt" \
      2>"$output/source-status-after.stderr" || status=1
    if [ -s "$output/source-status-after.txt" ]; then status=1; fi
    printf '%s\n' "$status" >"$output/runner-exit-code.txt"
    if ! seal; then
      status=1
      printf '%s\n' "$status" >"$output/runner-exit-code.txt"
      seal >/dev/null 2>&1 || true
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
    --configuration-file) configuration_file="$2"; shift 2 ;;
    --runtime-manifest) runtime_manifest="$2"; shift 2 ;;
    --runtime-manifest-sha256) runtime_manifest_sha256="$2"; shift 2 ;;
    --metrics-url) metrics_url="$2"; shift 2 ;;
    --downstream-port) downstream_port="$2"; shift 2 ;;
    --interval-id) interval_id="$2"; shift 2 ;;
    --run-id) run_id="$2"; shift 2 ;;
    --point-id) point_id="$2"; shift 2 ;;
    --tls) tls="$2"; shift 2 ;;
    --payload-bytes) payload_bytes="$2"; shift 2 ;;
    --) shift; break ;;
    *) fail "unknown option: $1" ;;
  esac
done

[ -n "$output" ] && [ -n "$configuration_file" ] &&
  [ -n "$runtime_manifest" ] && [ -n "$runtime_manifest_sha256" ] &&
  [ -n "$downstream_port" ] && [ -n "$interval_id" ] &&
  [ -n "$run_id" ] && [ -n "$point_id" ] && [ -n "$tls" ] &&
  [ -n "$payload_bytes" ] && [ "$#" -gt 0 ] ||
  fail 'usage: --output DIR --configuration-file FILE --runtime-manifest FILE --runtime-manifest-sha256 SHA256 --downstream-port PORT --interval-id ID --run-id ID --point-id ID --tls true|false --payload-bytes N [--service UNIT] [--snapshot-file FILE] [--metrics-url LOOPBACK_URL] -- CLIENT ARG...'
case "$output" in /*) ;; *) fail 'output must be an absolute path' ;; esac
case "$output" in "$repo"|"$repo"/*) fail 'output must be outside the source checkout' ;; esac
case "$snapshot_file" in /*) ;; *) fail 'snapshot file must be absolute' ;; esac
case "$metrics_url" in
  http://127.0.0.1:*/metrics)
    metrics_port="${metrics_url#http://127.0.0.1:}"
    metrics_port="${metrics_port%/metrics}"
    ;;
  *) fail 'metrics URL must be an explicit IPv4 loopback HTTP metrics endpoint' ;;
esac
case "$metrics_port" in ''|*[!0-9]*) fail 'metrics URL port must be an integer' ;; esac
[ "$metrics_port" -ge 1 ] && [ "$metrics_port" -le 65535 ] ||
  fail 'metrics URL port must be between 1 and 65535'
case "$service" in *[!A-Za-z0-9@_.:-]*|'') fail 'service name is unsafe' ;; esac
for value in "$interval_id" "$run_id" "$point_id"; do
  case "$value" in *[!A-Za-z0-9._:-]*|'') fail 'identifier contains unsupported characters' ;; esac
done
case "$tls" in true|false) ;; *) fail 'TLS must be true or false' ;; esac
case "$downstream_port" in ''|*[!0-9]*) fail 'downstream port must be an integer' ;; esac
[ "$downstream_port" -ge 1 ] && [ "$downstream_port" -le 65535 ] ||
  fail 'downstream port must be between 1 and 65535'
case "$payload_bytes" in ''|*[!0-9]*) fail 'payload bytes must be an integer' ;; esac
[ "$payload_bytes" -gt 0 ] || fail 'payload bytes must be positive'
case "$runtime_manifest_sha256" in
  *[!0-9a-f]*|'') fail 'runtime manifest SHA-256 is invalid' ;;
esac
[ "${#runtime_manifest_sha256}" -eq 64 ] || fail 'runtime manifest SHA-256 is invalid'
[ -f "$configuration_file" ] && [ ! -L "$configuration_file" ] ||
  fail 'configuration file must be a regular non-symlink file'
[ -f "$runtime_manifest" ] && [ ! -L "$runtime_manifest" ] ||
  fail 'runtime manifest must be a regular non-symlink file'
[ ! -e "$output" ] || fail "output already exists: $output"
for tool in cmp curl git node perf python3 sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
[ -z "$(git -C "$repo" status --porcelain)" ] || fail 'clean source required'
printf '%s  %s\n' "$runtime_manifest_sha256" "$runtime_manifest" |
  sha256sum -c - >/dev/null || fail 'runtime manifest digest mismatch'
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || fail 'sudo is required'
  sudo -n true >/dev/null 2>&1 || fail 'non-interactive sudo is required'
fi

umask 077
mkdir -p "$output"
git -C "$repo" rev-parse HEAD >"$output/source-commit.txt"
git -C "$repo" status --porcelain >"$output/source-status.txt"
cp "$runtime_manifest" "$output/runtime-manifest.json"
printf '%s\n' "$runtime_manifest_sha256" >"$output/runtime-manifest-sha256.txt"
sha256sum "$configuration_file" | awk '{print $1}' \
  >"$output/configuration-sha256-before.txt"

capture_identity "$output/runtime-before.json"
python3 - "$output/runtime-before.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    identity = json.load(source)
if identity.get("response_path_diagnostics") is not True:
    raise SystemExit("gateway response-path diagnostics are disabled")
PY
curl --fail --silent --show-error --max-time 10 "$metrics_url" \
  >"$output/application-before.prom"
pid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' \
  "$output/runtime-before.json")"
capture_threads "$pid" "$output/thread-ids-before.txt"
thread_ids="$(cat "$output/thread-ids-before.txt")"

set +e
"$script_dir/phase5-socket-output-collector.sh" \
  --output "$output/socket" --service "$service" \
  --snapshot-file "$snapshot_file" --downstream-port "$downstream_port" \
  --interval-id "$interval_id" -- \
  perf stat -x , \
    -e cycles,instructions,cache-misses,raw_syscalls:sys_enter \
    -t "$thread_ids" -o "$output/perf.csv" -- "$@"
collector_status="$?"
set -e
printf '%s\n' "$collector_status" >"$output/socket-collector-exit-code.txt"

curl --fail --silent --show-error --max-time 10 "$metrics_url" \
  >"$output/application-after.prom"
capture_identity "$output/runtime-after.json"
capture_threads "$pid" "$output/thread-ids-after.txt"
sha256sum "$configuration_file" | awk '{print $1}' \
  >"$output/configuration-sha256-after.txt"
git -C "$repo" status --porcelain >"$output/source-status-after-capture.txt"

[ "$collector_status" -eq 0 ] ||
  fail "socket/CPU collector failed; evidence retained in $output"
[ ! -s "$output/source-status-after-capture.txt" ] ||
  fail "source changed during native capture; evidence retained in $output"
cmp -s "$output/runtime-before.json" "$output/socket/process-before.json" ||
  fail 'runtime identity before the interval differs from socket collector'
cmp -s "$output/runtime-after.json" "$output/socket/process-after.json" ||
  fail 'runtime identity after the interval differs from socket collector'
cmp -s "$output/thread-ids-before.txt" "$output/thread-ids-after.txt" ||
  fail 'gateway thread set changed during CPU attribution'
(cd "$output/socket" && sha256sum -c checksums.sha256 >/dev/null) ||
  fail 'nested socket collector checksum verification failed'

node "$script_dir/response-path-attribution.mjs" assemble-native \
  --root "$output" --run-id "$run_id" --point-id "$point_id" \
  --tls "$tls" --payload-bytes "$payload_bytes"

echo "PERF03_NATIVE_CAPTURE_DIR=$output"
