#!/usr/bin/env bash
# Prepare only the two synthetic billing plans used by the browser fixture.
# Run from the Hash project directory with the controlled browser Compose overlay.
set -euo pipefail
export LC_ALL=C

readonly catalog_application_name=hash-browser-e2e-catalog
catalog_receipt_file="$(mktemp)"
trap 'rm -f -- "$catalog_receipt_file"' EXIT

database_scalar() {
  docker compose --ansi never exec -T postgres \
    psql -X -v ON_ERROR_STOP=1 -U hash -d hash -Atq -c "$1"
}

if [[ "$(database_scalar "SELECT current_setting('server_version_num');")" != 160015 ]]; then
  printf '%s\n' 'Browser catalog preparation requires the pinned PostgreSQL 16.15 fixture.' >&2
  exit 1
fi

if [[ "$(database_scalar "SELECT count(*) FROM orgs o JOIN users u ON u.org_id=o.id JOIN org_subscriptions s ON s.org_id=o.id JOIN billing_plans p ON p.id=s.plan_id WHERE o.id='11111111-1111-4111-8111-111111111111' AND u.id='22222222-2222-4222-8222-222222222222' AND u.email='browser-ci@example.invalid' AND p.slug='enterprise' AND s.provider='mock';")" != 1 ]]; then
  printf '%s\n' 'Expected the disposable browser fixture identity and subscription.' >&2
  exit 1
fi

for catalog_slug in free enterprise; do
  # Migration 21 generates UUIDs for each fresh database. Never select arbitrary
  # plans or infer that a successful seed also populated migration 95's cache.
  catalog_plan_id="$(database_scalar "SELECT CASE WHEN count(*) = 1 THEN min(id::text) ELSE '' END FROM billing_plans WHERE (CASE WHEN octet_length(slug)<=100 THEN slug ELSE NULL::text END) = '${catalog_slug}';")"
  if [[ ! "$catalog_plan_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    printf 'Expected exactly one synthetic %s plan UUID.\n' "$catalog_slug" >&2
    exit 1
  fi

  # Reuse the finite runtime allocation already supplied to this service by
  # docker-compose.browser-e2e.yml. This CLI uses a direct pgx connection, so its
  # DSN must omit the pool-only option. Do not print the inherited DSN.
  docker compose --ansi never exec -T hash /bin/sh -eu -c '
    case "$HASH_DB_URL" in
      *"&pool_max_conns=8") HASH_DB_URL=${HASH_DB_URL%&pool_max_conns=8} ;;
      *) printf "%s\n" "Expected the controlled browser database pool profile." >&2; exit 1 ;;
    esac
    HASH_DB_URL="${HASH_DB_URL}&application_name=hash-browser-e2e-catalog"
    export HASH_DB_URL
    exec /usr/local/bin/hash-catalogmeasure --kind=plan --id="$1"
  ' hash-browser-catalog "$catalog_plan_id" > "$catalog_receipt_file"
  python3 - "$catalog_plan_id" "$catalog_receipt_file" <<'PY'
import json
import sys

with open(sys.argv[2], encoding="utf-8") as source:
    result = json.load(source)
measurement = result.get("measurement", {})
if not (
    result.get("measurement_committed") is True
    and measurement.get("Kind") == "plan"
    and measurement.get("SourceID") == sys.argv[1]
    and measurement.get("WireBytes", 0) > 0
    and measurement.get("ServerVersionNum") == 160015
):
    raise SystemExit("The selected synthetic plan measurement did not commit.")
PY
done

catalog_cache_rows="$(database_scalar "SELECT count(*) FROM billing_plans p JOIN billing_plan_feature_sizes_v1 m ON m.plan_id = p.id AND m.plan_created_at = p.created_at WHERE p.slug IN ('free', 'enterprise') AND m.features_wire_bytes > 0 AND m.measurement_server_version_num = 160015;")"
if [[ "$catalog_cache_rows" != 2 ]]; then
  printf '%s\n' 'Expected current measured catalog entries for both synthetic plans.' >&2
  exit 1
fi

# Successful measurement reports observer retirement as pending. Establish that
# both actual CLI processes have released their database sessions independently.
catalog_live_sessions="$(database_scalar "SELECT count(*) FROM pg_stat_activity WHERE application_name = '${catalog_application_name}';")"
if [[ "$catalog_live_sessions" != 0 ]]; then
  printf '%s\n' 'Browser catalog preparation still has database sessions.' >&2
  exit 1
fi

printf '%s\n' 'Prepared and retired synthetic free and enterprise catalog measurements.'
