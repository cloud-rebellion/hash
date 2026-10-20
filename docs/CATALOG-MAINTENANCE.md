# Controlled plan catalog maintenance

Plan measurement is an explicit deployment prerequisite, not plan approval or
an entitlement grant. M95 intentionally does not backfill historical/default
plans, and normal readers never repair missing or stale measurements. Migration21
seeds `free`, `pro` and `enterprise` before M95, so a freshly migrated database
still needs the selected plans prepared before ordinary authoring. Server boot
checks plan existence/business validity, and `/health` checks dependencies;
neither certifies M95 readiness.

## Select only approved plans

Record the exact candidate commit/image, database contract, maintenance owner,
review reference and explicit plan UUIDs before making a measurement. No
`--all`, slug selector or inventory mode exists in `hash-catalogmeasure`.

- Internal operator mode: select each distinct plan in the reviewed operator
  bindings. There is no free-plan fallback for unassigned organizations. Preserve
  active status, positive finite document/recipient quotas and boolean feature
  validation. The seeded unlimited Enterprise plan is not a valid operator
  binding merely because it is measured.
- Ordinary/Mollie mode: select `free` for absent/non-entitled subscriptions,
  every plan referenced by an entitled subscription, and plans intentionally
  offered for new purchases before enabling that path. Do not assume the three
  seeded slugs are the complete deployed catalog or that inactive historical
  subscription plans cannot still be selected by existing entitlement rules.

Resolve a reviewed slug to its UUID with a bounded, read-only scalar query in
an already approved database context. Do not select `features_json` bodies:

```sql
SELECT id FROM public.billing_plans
WHERE (CASE WHEN octet_length(slug)<=100 THEN slug ELSE NULL::text END)
      = :'approved_slug'::text;
```

Require exactly one result and independently review the intended business plan.
Do not turn query results into an automatically approved measurement list.
Measure each selected UUID separately. Measurement neither creates nor updates
plan features, quotas, prices, subscriptions or operator bindings.

## Owned execution and connection prerequisites

Use the exact reviewed immutable candidate image containing
`/usr/local/bin/hash-catalogmeasure`; the server entrypoint is unchanged. The
command uses only `HASH_DB_URL` and the existing complete explicit work profile:
all seven `HASH_WORK_GLOBAL_*` and seven `HASH_WORK_ORG_*` dimensions plus
`HASH_WORK_MAX_GRANTS`, `HASH_WORK_MAX_ORG_GRANTS` and
`HASH_WORK_DB_CONNECTION_ALLOCATION`. Missing/partial configuration refuses;
there are no guessed allocations. SQL-session allocation must fit the assigned
connection allocation. Allocate this maintenance process explicitly in the
aggregate process/database budget; do not borrow or infer spare serving budget.

Use the existing managed database identity/connection contract and secret
snapshot. Retain normal database authentication/TLS policy, the approved role,
unprivileged/read-only container policy, finite process-group owner, resource
limits and DB-only network access. Do not print a DSN, place it in argv, use
blanket TLS bypasses, inherit unrelated product secrets or grant new privileges
on failure. This document supplies no host-specific Docker command: the approved
maintenance allocation, network, immutable image and effective secret snapshot
must be bound by that deployment's owner first. If they are unavailable, hold
the release rather than inventing a successful preflight.

The native source proof is specifically PostgreSQL **16.15**, UTF8 and direct
uncompressed stored JSONB. Compressed/other-version sources are unsupported by
this command and remain refused. Do not decompress/rewrite plan features or
change the server-version guard to make this procedure pass.

## Strict read-only gate for one selected UUID

Save the following reviewed SQL as `plan-catalog-gate.sql` in the private
maintenance evidence directory. Invoke `psql -X` through the approved connection
context (`PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, restrictive `PGPASSFILE`, and
normal TLS settings), never with a credential-bearing URL argument. The SQL
independently checks that this connection matches the same immutable database
contract; matching database names alone are insufficient. It reuses the existing
release identity requirements, including the non-superuser database-owner role.
Unavailable identity inspection is a failed gate, not permission to elevate.
Only non-secret contract identifiers/UUIDs are command arguments.

```sql
\set ON_ERROR_STOP on
BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '1s';
WITH identity AS MATERIALIZED (
 SELECT current_database()='hash'
    AND current_database()=:'expected_database'::text
    AND session_user=:'expected_user'::text AND current_user=session_user
    AND system_identifier::text=:'expected_system_identifier'::text
    AND (SELECT oid::text FROM pg_database WHERE datname=current_database())
        =:'expected_database_oid'::text
    AND current_schema()='public'
    AND current_schemas(false)=ARRAY['public']::name[]
    AND EXISTS (
      SELECT 1 FROM pg_roles r JOIN pg_database d ON d.datdba=r.oid
      WHERE d.datname=current_database() AND r.rolname=current_user
        AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb
        AND NOT r.rolreplication AND NOT r.rolbypassrls
    ) AS exact_identity
 FROM pg_control_system()
), selected AS MATERIALIZED (
 SELECT id,created_at,
        pg_column_compression(features_json) IS NULL AS uncompressed,
        pg_column_size(features_json)>0 AS stored_source_present
 FROM public.billing_plans WHERE id=:'plan_id'::uuid
)
SELECT COALESCE((SELECT exact_identity FROM identity),false)
   AND current_setting('server_encoding')='UTF8'
   AND current_setting('server_version_num')::integer=160015
   AND (SELECT count(*)=1 FROM selected)
   AND COALESCE((
     SELECT bool_and(p.uncompressed AND p.stored_source_present AND
       (NOT :'require_measurement'::boolean OR
         (m.plan_id IS NOT NULL AND m.plan_created_at=p.created_at
          AND m.features_wire_bytes>=1
          AND m.measurement_server_version_num=
              current_setting('server_version_num')::integer
          AND isfinite(m.measured_at))))
     FROM selected p LEFT JOIN public.billing_plan_feature_sizes_v1 m
       ON m.plan_id=p.id
   ),false) AS gate_ok
\gset
\if :gate_ok
 COMMIT;
\else
 ROLLBACK;
 \quit 1
\endif
```

Before measurement, run the gate with these non-secret values from the existing
approved contract, under the finite maintenance owner:

```sh
psql -X --set=ON_ERROR_STOP=1 \
  --set=expected_database=hash --set=expected_user="$APPROVED_DATABASE_USER" \
  --set=expected_system_identifier="$APPROVED_SYSTEM_IDENTIFIER" \
  --set=expected_database_oid="$APPROVED_DATABASE_OID" \
  --set=plan_id="$APPROVED_PLAN_UUID" --set=require_measurement=false \
  --file=plan-catalog-gate.sql
```

Missing variables, invalid SQL parameters, missing source, identity mismatch,
unsupported storage/version, query timeout or any nonzero exit holds the release.
The preflight is a point-in-time observation, not a work loan or measurement
permission. The command performs its own original locked-source proof.

## Explicit measurement and postflight

Invoke exactly one selected UUID with the privately supplied `HASH_DB_URL` and
complete reviewed work allocation, inside the approved finite process owner:

```text
/usr/local/bin/hash-catalogmeasure --kind=plan --id=<approved-plan-uuid>
```

`--org` is rejected for process-scoped plan maintenance. There are no migrations,
startup loops, automatic retries or reader fallbacks. The existing command has a
30-second measurement context and attempts fresh five-second cleanup; retain
those bounds and the owner's original execution/cleanup deadlines. Keep stdout
as a restrictive evidence file, requiring process exit0 and
`measurement_committed:true`, with receipt `Kind=plan`, exact `SourceID`, nil
`OrgID`, positive `WireBytes`, server version160015 and finite acknowledged
creation/measurement stamps. Do not treat UUID equality as source authority.

Then repeat the same read-only gate with `--set=require_measurement=true`.
It must exit0 for every selected UUID. This joins the actual parent creation
stamp to M95 metadata, positive wire bytes and the current server version,
without expanding a JSON body. A later source/feature update can invalidate
that result; repeat the explicit preparation/gate after such a change. Neither
startup nor a prior receipt repairs that condition.

The command intentionally reports
`process_observer_retirement_pending:true`. An acknowledged measurement and
exit0 are **not** complete physical-retirement proof. Keep the owned command
joined, require the existing independent database/backend retirement acceptance,
and retain its receipt. The current CLI does not emit an exact backend identity
or independently prove its final observer gone. If the deployment owner has no
safe independent retirement witness, record that limitation and hold the
physical acceptance claim; do not infer it from a zero pending cache or `/health`.

## Release acceptance and holds

Before enabling authoring traffic, require the exact image/tool provenance,
approved plan selection, bound maintenance allocation/DB identity, committed
measurement receipts, passing postflight for all selected UUIDs, joined physical
execution/retirement evidence, and an ordinary authenticated create/Send
preflight appropriate to the release. Preserve normal quota/permission checks.
A component fixture or controlled issuer is not live provider/ingress acceptance.

Absent/stale metadata remains a retryable503 at owned authoring/Send boundaries;
a valid plan row, operator startup validation or dependency health200 is not a
catalog-ready signal. On refusal, keep the release held and inspect the fixed
failure and receipt. Do not insert fabricated size rows, disable triggers,
repin versions, raise caps or bypass billing. This runbook adds no automatic
measurement, readiness endpoint, alert default or entitlement.
