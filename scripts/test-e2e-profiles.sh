#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Bright Interaction
# Run every tagged Go package once against its declared disposable profile.
set +x
set -eu
umask 077

fail() { printf 'e2e profiles: %s\n' "$1" >&2; exit 1; }
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
command -v go >/dev/null 2>&1 || fail 'Go is required'
for prerequisite in HASH_E2E_DB_URL HASH_E2E_BACKLOG_DB_URL HASH_E2E_RECIPIENT_LOCK_DB_URL \
  HASH_E2E_EXPECT_MIGRATIONS_SHA256 HASH_E2E_S3_ENDPOINT HASH_E2E_S3_ACCESS_KEY \
  HASH_E2E_S3_SECRET_KEY HASH_E2E_GOTENBERG_URL HASH_E2E_RENDERER_URL; do
  # Indirection names come only from the fixed list above; values stay private.
  eval 'value=${'"$prerequisite"'-}'
  [ -n "$value" ] || fail "missing prerequisite: $prerequisite"
done
[ "${HASH_BROWSER_E2E:-0}" != 1 ] || fail 'external browser qualification needs its separate handoff runner'

scratch_root=${TMPDIR:-/tmp}
[ -d "$scratch_root" ] || fail 'TMPDIR must exist'
scratch=$(mktemp -d "$scratch_root/hash-e2e-profiles.XXXXXXXX")
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export TMPDIR="$scratch"

# Retain only event/accounting evidence, never a source or runtime copy. Its
# lifetime belongs to the caller's TMPDIR budget or explicit evidence policy.
if [ -n "${HASH_E2E_EVIDENCE_DIR:-}" ]; then
  case "$HASH_E2E_EVIDENCE_DIR" in /*) ;; *) fail 'evidence directory must be absolute' ;; esac
  mkdir -m 700 -- "$HASH_E2E_EVIDENCE_DIR" || fail 'evidence directory must be fresh'
  evidence=$(CDPATH= cd -- "$HASH_E2E_EVIDENCE_DIR" && pwd -P)
  case "$evidence" in "$PWD"|"$PWD"/*)
    rmdir -- "$evidence"
    fail 'evidence must remain outside the source checkout' ;;
  esac
else
  evidence=$(mktemp -d "$scratch_root/hash-e2e-evidence.XXXXXXXX")
fi
printf 'e2e profile evidence: %s\n' "$evidence"

# These two bounded binaries are built before any timed test. Keep the caller's
# normal Go/module caches; remove only this invocation's temporary directory.
go build -o "$scratch/hash-pdf-worker" ./cmd/pdfworker
go build -tags=e2e -o "$scratch/profile-preflight" ./scripts/e2eprofile
migration_digest=$("$scratch/profile-preflight" "$PWD" "$scratch/hash-pdf-worker")
export HASH_E2E_PDF_WORKER_PATH="$scratch/hash-pdf-worker"
export HASH_E2E_RECIPIENT_LOCK_MIGRATION_SHA256="$migration_digest"

module_path=$(go list -m -f '{{.Path}}')
go list -tags=e2e -f '{{.ImportPath}}' ./... > "$scratch/packages"
go list -tags=e2e -f '{{.ImportPath}} {{if or .TestGoFiles .XTestGoFiles}}tests{{else}}no-tests{{end}}' ./... > "$evidence/source-test-inventory.txt"
sort -u "$scratch/packages" > "$scratch/unique-packages"
[ "$(wc -l < "$scratch/packages")" -eq "$(wc -l < "$scratch/unique-packages")" ] || fail 'duplicate package inventory'
: > "$scratch/ordinary-packages"
special_count=0
while IFS= read -r package; do
  case "$package" in
    "$module_path/cmd/worker"|"$module_path/internal/db"|"$module_path/internal/fitprepare"|"$module_path/internal/fitselect")
      special_count=$((special_count + 1)) ;;
    '') fail 'empty package inventory entry' ;;
    *) printf '%s\n' "$package" >> "$scratch/ordinary-packages" ;;
  esac
done < "$scratch/packages"
[ "$special_count" -eq 4 ] || fail 'the four dedicated profile packages must each be present exactly once'

# Identity/ownership checks above run against all three fresh databases before
# this first write. Only this dedicated recipient profile is migrated here.
HASH_DB_URL="$HASH_E2E_RECIPIENT_LOCK_DB_URL" go run ./cmd/migrate

failed=0
run_profile() {
  profile=$1
  database=$2
  shift 2
  printf 'e2e profile: %s (%s packages)\n' "$profile" "$#"
  printf '%s\n' "$@" > "$evidence/$profile.packages"
  # Bound simultaneous fresh-database/checkpoint work across packages and
  # independent parallel test cases; each package keeps its existing180s
  # deadline, and tests' own concurrency/interleaving assertions still run.
  if HASH_E2E_DB_URL="$database" go test -json -tags=e2e -count=1 -timeout=180s -p=2 -parallel=2 "$@" \
      > "$evidence/$profile.events.jsonl" 2> "$evidence/$profile.stderr"; then
    go_exit=0
  else
    go_exit=$?
  fi
  if ! "$scratch/profile-preflight" audit "$profile" "$evidence/$profile.packages" \
      "$evidence/$profile.events.jsonl" "$evidence/$profile.summary.json" \
      "$evidence/$profile.skipped-tests.txt" "$go_exit" "$evidence/source-test-inventory.txt"; then
    failed=1
  fi
}
set --
while IFS= read -r package; do set -- "$@" "$package"; done < "$scratch/ordinary-packages"
[ "$#" -gt 0 ] || fail 'ordinary package partition is empty'
run_profile ordinary "$HASH_E2E_DB_URL" "$@"
run_profile backlog "$HASH_E2E_BACKLOG_DB_URL" "$module_path/cmd/worker"
run_profile recipient-lock "$HASH_E2E_RECIPIENT_LOCK_DB_URL" "$module_path/internal/db"
run_profile original-capture "$HASH_E2E_DB_URL" "$module_path/internal/fitprepare"
run_profile fit-selection "$HASH_E2E_DB_URL" "$module_path/internal/fitselect"
printf '%s\n' 'External browser qualification is separate; this run does not activate or claim it.'
exit "$failed"
