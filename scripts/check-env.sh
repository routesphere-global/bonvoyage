#!/bin/sh
set -eu

missing=0

check_required() {
  name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    printf '%-12s %s\n' "$name" "$(command -v "$name")"
  else
    printf '%-12s %s\n' "$name" "missing (required)" >&2
    missing=1
  fi
}

check_optional() {
  name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    printf '%-12s %s\n' "$name" "$(command -v "$name")"
  else
    printf '%-12s %s\n' "$name" "not installed (provided by Linux build container)"
  fi
}

echo "BonVoyage environment"
check_required go
check_required docker
check_required npm
check_required buf
check_optional cmake
check_optional c++

if [ "$missing" -ne 0 ]; then
  echo "Install the missing required tools before running BonVoyage checks." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed, but its engine is not available." >&2
  exit 1
fi

echo
echo "Environment is ready. Run 'make check-fast' or 'make check'."
