#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Development-only checker. Never install documentation dependencies globally.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
python="${HASH_OPENAPI_PYTHON:-python3}"
command -v "$python" >/dev/null 2>&1 || {
  echo "OpenAPI validation requires CPython 3.11 through 3.14 with venv and pip" >&2
  exit 1
}
"$python" -I -c 'import sys; assert sys.implementation.name == "cpython" and (3, 11) <= sys.version_info[:2] < (3, 15), "OpenAPI validation requires CPython 3.11 through 3.14"'
wheelhouse="${HASH_OPENAPI_WHEELHOUSE:-}"
if [ -n "$wheelhouse" ] && [ ! -d "$wheelhouse" ]; then
  echo "HASH_OPENAPI_WHEELHOUSE must name a local directory" >&2
  exit 1
fi
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/hash-openapi.XXXXXXXX")"
cleanup() {
  local result=$?
  trap - EXIT
  if ! rm -rf -- "$work_dir"; then
    echo "OpenAPI temporary environment cleanup failed" >&2
    result=1
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
"$python" -I -m venv "$work_dir/venv"
installer=("$work_dir/venv/bin/python" -I -m pip --isolated --disable-pip-version-check --no-input install --no-cache-dir --require-hashes --only-binary=:all: --timeout=10 --retries=0)
if [ -n "$wheelhouse" ]; then
  installer+=(--no-index --find-links "$wheelhouse")
else
  installer+=(--index-url https://pypi.org/simple)
fi
PIP_CONFIG_FILE=/dev/null "${installer[@]}" --requirement scripts/requirements-openapi.txt
"$work_dir/venv/bin/python" -I -m pip check
"$work_dir/venv/bin/python" -I scripts/check-automation-openapi.py
