#!/bin/sh
# Source this file; it does not change the caller's options, variables or traps.
# bv_stage_fixture_secrets [--refresh] VOLUME DIR IMAGE PLATFORM FILE...
# FILE... is the complete basename allowlist (ASCII alphanumeric first, then
# alphanumeric, dot, underscore or hyphen). DIR must be absolute, without CSV
# mount delimiters. Use an existing Python upstream image; nothing is pulled.
# The initial call must create VOLUME. --refresh requires its ownership label
# to match this shell PID and DIR, and requires the complete allowlist again.
# The caller owns cleanup, including after a failed copy, using
# bv_remove_fixture_secrets VOLUME DIR (same DIR spelling as the staging call).
# This checks ownership before removal, so a name collision is never deleted.
# Mount VOLUME read-only at /etc/bonvoyage/secrets on the unchanged gateway USER.

bv_stage_fixture_secrets() (
  refresh=false
  if [ "${1-}" = --refresh ]; then
    refresh=true
    shift
  fi
  if [ "$#" -lt 5 ]; then
    echo 'usage: bv_stage_fixture_secrets [--refresh] VOLUME DIR IMAGE PLATFORM FILE...' >&2
    return 1
  fi
  volume=$1 directory=$2 image=$3 platform=$4
  shift 4
  case "$volume" in
    ''|[!a-zA-Z0-9]*|*[!a-zA-Z0-9_.-]*)
      echo 'invalid fixture volume name' >&2; return 1 ;;
  esac
  case "$directory" in
    /*) ;;
    *) echo 'fixture directory must be absolute' >&2; return 1 ;;
  esac
  case "$directory" in
    *','*|*'"'*|*'
'*|*"$(printf '\r')"*)
      echo 'invalid fixture directory for Docker mount' >&2; return 1 ;;
  esac
  if [ ! -d "$directory" ] || [ -L "${directory%/}" ]; then
    echo 'fixture directory must be a real directory' >&2
    return 1
  fi
  case "$image" in
    ''|-*) echo 'fixture image is required' >&2; return 1 ;;
  esac
  if [ -z "$platform" ]; then
    echo 'fixture platform is required' >&2
    return 1
  fi
  seen='|'
  for name do
    case "$name" in
      ''|[!a-zA-Z0-9]*|*[!a-zA-Z0-9_.-]*)
        echo "invalid fixture basename: $name" >&2; return 1 ;;
    esac
    case "$seen" in
      *"|$name|"*) echo "duplicate fixture basename: $name" >&2; return 1 ;;
    esac
    seen="$seen$name|"
    if [ ! -f "$directory/$name" ] || [ -L "$directory/$name" ]; then
      echo "fixture must be a regular non-symlink file: $name" >&2
      return 1
    fi
  done

  label='com.bonvoyage.test-fixture-secrets'
  owner="v1:$$:$directory"
  format='{{ index .Labels "com.bonvoyage.test-fixture-secrets" }}'
  if [ "$refresh" = true ]; then
    actual=$(docker volume inspect --format "$format" "$volume") || return 1
  else
    if docker volume inspect "$volume" >/dev/null 2>&1; then
      echo "fixture volume already exists (use --refresh only for this caller's volume): $volume" >&2
      return 1
    fi
    docker volume create --label "$label=$owner" "$volume" >/dev/null || return 1
    actual=$(docker volume inspect --format "$format" "$volume") || return 1
  fi
  if [ "$actual" != "$owner" ]; then
    echo "fixture volume ownership label mismatch: $volume" >&2
    return 1
  fi

  # CHOWN sets the gateway owner; DAC_OVERRIDE reads host-private files and
  # writes the gateway-owned volume; FOWNER sets its directory mode on refresh.
  docker run --rm --interactive --pull never --platform "$platform" \
    --network none --read-only --user 0:0 --cap-drop ALL \
    --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    --mount "type=bind,src=$directory,dst=/fixture-source,readonly" \
    --mount "type=volume,src=$volume,dst=/fixture-secrets,volume-nocopy" \
    --entrypoint python "$image" - /fixture-source /fixture-secrets "$@" <<'BV_FIXTURE_COPY_PY'
import contextlib
import os
import re
import shutil
import stat
import sys
import uuid

source, destination, *names = sys.argv[1:]
if not names or len(set(names)) != len(names):
    raise ValueError("empty or duplicate fixture allowlist")
if any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) is None for name in names):
    raise ValueError("invalid fixture basename")

with contextlib.ExitStack() as stack:
    directories = []
    for directory in (source, destination):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, fd)
        directories.append(fd)
    src, dst = directories
    if set(os.listdir(dst)) - set(names):
        raise ValueError("destination contains files outside the allowlist")

    # Validate every input and existing destination before changing anything.
    # NONBLOCK prevents a raced-in FIFO from blocking before fstat rejects it.
    inputs = []
    for name in names:
        if not stat.S_ISREG(os.stat(name, dir_fd=src, follow_symlinks=False).st_mode):
            raise ValueError("fixture is not a regular non-symlink file: " + name)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=src)
        stream = stack.enter_context(os.fdopen(fd, "rb"))
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("fixture changed to a non-regular file: " + name)
        inputs.append((name, stream))
        try:
            existing = os.stat(name, dir_fd=dst, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(existing.st_mode):
                raise ValueError("destination is not a regular non-symlink file: " + name)

    os.fchmod(dst, 0o700)
    os.fchown(dst, 65532, 65532)
    for name, stream in inputs:
        temporary = ".bv-fixture-" + uuid.uuid4().hex
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=dst)
        try:
            with os.fdopen(fd, "wb") as output:
                shutil.copyfileobj(stream, output)
                output.flush()
                os.fchmod(output.fileno(), 0o600)
                os.fchown(output.fileno(), 65532, 65532)
            # Replacement avoids modifying a pre-existing hardlink's target.
            os.replace(temporary, name, src_dir_fd=dst, dst_dir_fd=dst)
        finally:
            try:
                os.unlink(temporary, dir_fd=dst)
            except FileNotFoundError:
                pass
BV_FIXTURE_COPY_PY
)

# Safe for a caller's cleanup trap even if staging rejected a name collision.
bv_remove_fixture_secrets() (
  if [ "$#" -ne 2 ] || [ -z "$2" ]; then
    echo 'usage: bv_remove_fixture_secrets VOLUME DIR' >&2
    return 1
  fi
  case "$1" in
    ''|[!a-zA-Z0-9]*|*[!a-zA-Z0-9_.-]*)
      echo 'invalid fixture volume name' >&2; return 1 ;;
  esac
  actual=$(docker volume inspect \
    --format '{{ index .Labels "com.bonvoyage.test-fixture-secrets" }}' "$1") || return 1
  if [ "$actual" != "v1:$$:$2" ]; then
    echo "refusing to remove unowned fixture volume: $1" >&2
    return 1
  fi
  docker volume rm "$1" >/dev/null
)

# Optional guard for callers that have their own readiness protocol.
bv_gateway_running() (
  if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    echo 'usage: bv_gateway_running GATEWAY' >&2
    return 1
  fi
  if running=$(docker inspect --type container --format '{{.State.Running}}' "$1") &&
      [ "$running" = true ]; then
    return 0
  fi
  echo "BonVoyage gateway is not running: $1" >&2
  docker logs --tail 100 "$1" >&2 || :
  return 1
)

# Up to 30 attempts within about 30s, excluding Docker daemon stalls. Each
# urllib probe has a whole-operation alarm, including DNS, not just socket I/O.
# The probe container must already be running and provide Python.
bv_wait_gateway_ready() (
  if [ "$#" -ne 3 ] || [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo 'usage: bv_wait_gateway_ready GATEWAY PROBE_CONTAINER URL' >&2
    return 1
  fi
  gateway=$1 probe=$2 url=$3
  now=$(date +%s) || return 1
  deadline=$((now + 30))
  attempt=0
  while [ "$attempt" -lt 30 ] && [ "$now" -lt "$deadline" ]; do
    bv_gateway_running "$gateway" || return 1
    ready=false
    if docker exec --interactive "$probe" python - "$url" \
        >/dev/null 2>&1 <<'BV_GATEWAY_PROBE_PY'
import signal
import sys
import urllib.request

# The default action kills even a blocked libc resolver; a Python signal
# handler can be deferred until native code returns to the interpreter.
signal.signal(signal.SIGALRM, signal.SIG_DFL)
signal.alarm(1)
try:
    with urllib.request.urlopen(sys.argv[1], timeout=1) as response:
        if response.status != 200:
            raise SystemExit("readiness probe did not return HTTP 200")
finally:
    signal.alarm(0)
BV_GATEWAY_PROBE_PY
    then
      ready=true
    fi
    bv_gateway_running "$gateway" || return 1
    if [ "$ready" = true ]; then
      return 0
    fi
    attempt=$((attempt + 1))
    now=$(date +%s) || return 1
    if [ "$attempt" -ge 30 ] || [ "$now" -ge "$deadline" ]; then
      break
    fi
    sleep 1 || return 1
    now=$(date +%s) || return 1
  done
  echo "BonVoyage gateway did not become ready within 30s: $gateway ($url)" >&2
  docker logs --tail 100 "$gateway" >&2 || :
  return 1
)
