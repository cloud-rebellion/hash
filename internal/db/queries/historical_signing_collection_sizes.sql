-- Distinct fixed native historical signing/finalization collection reads.
-- Original Send draft/sealing projections remain unchanged. Actual native
-- stage purpose and business/credential gates are mandatory before these reads.

-- name: GetHistoricalSigningCollectionReadHeaderV1 :one
-- SCALAR-ONLY before collection admission: no ordered row IDs, variable keys,
-- cache rowsets or scalable materialized CTE. Each aggregate CTE has ONE row.
-- The fixed owner first holds the real parent UPDATE in a preceding statement.
-- Correlated single-PK cache subqueries avoid collecting/hash-materializing
-- field cache rows before their actual row/raw/options loan exists.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL
  AND CASE WHEN octet_length(d.status)<=11 THEN d.status IN ('sent','in_progress','finalizing') ELSE false END FOR UPDATE OF d
), recipient_stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(r.role),0)::numeric+COALESCE(octet_length(r.email),0)::numeric+COALESCE(octet_length(r.name),0)::numeric+COALESCE(octet_length(r.status),0)::numeric+COALESCE(octet_length(r.locale),0)::numeric+COALESCE(octet_length(r.declined_reason),0)::numeric+COALESCE(octet_length(r.magic_token_hash),0)::numeric),0)::bigint AS raw_bytes
 FROM recipients r JOIN parent d ON d.id=r.document_id
), field_stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(f.type),0)::numeric+COALESCE(octet_length(f.label),0)::numeric+COALESCE(octet_length(f.value),0)::numeric),0)::bigint AS raw_bytes,
 COALESCE(sum(COALESCE((SELECT s.options_wire_bytes FROM field_signing_policy_sizes_v1 s
  WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),0)::numeric),0)::bigint AS options_wire_bytes,
 count(*) FILTER (WHERE COALESCE((SELECT 1 FROM field_signing_policy_sizes_v1 s
  WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),0)=0)::bigint AS missing_size_count,
 count(*) FILTER (WHERE COALESCE((SELECT s.measurement_server_version_num FROM field_signing_policy_sizes_v1 s
  WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),-1)<>current_setting('server_version_num')::integer)::bigint AS server_mismatch_count
 FROM document_fields f JOIN parent d ON d.id=f.document_id
), binding_stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(b.variable_name),0)::numeric+COALESCE(octet_length(b.source_kind),0)::numeric+COALESCE(octet_length(b.source_ref),0)::numeric+COALESCE(octet_length(b.source_path),0)::numeric+COALESCE(octet_length(b.fallback),0)::numeric+COALESCE(octet_length(b.last_value),0)::numeric+COALESCE(octet_length(b.last_error),0)::numeric),0)::bigint AS raw_bytes
 FROM document_variable_bindings b JOIN parent d ON d.id=b.document_id
)
SELECT d.id AS document_id,d.org_id,r.n AS recipient_count,r.raw_bytes AS recipient_raw_bytes,
 f.n AS field_count,f.raw_bytes AS field_raw_bytes,f.options_wire_bytes AS field_options_wire_bytes,
 f.missing_size_count AS field_missing_size_count,f.server_mismatch_count AS field_measurement_server_mismatch_count,
 b.n AS binding_count,b.raw_bytes AS binding_raw_bytes,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent d CROSS JOIN recipient_stats r CROSS JOIN field_stats f CROSS JOIN binding_stats b;

-- name: LockHistoricalSigningCollectionRowsV1 :one
-- AFTER the native count/raw/options collection loan: materialize and sort only
-- fixed-width identifiers/stamps. Immediate parent FKs fence new committed rows;
-- row/cache SHARE pins use NOWAIT: real M88 invalidation can lock row->parent.
-- Rows deleted meanwhile can only reduce the paid count. Existing text may grow
-- before SHARE, so never sort/store a variable_name or any raw model here.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL
  AND CASE WHEN octet_length(d.status)<=11 THEN d.status IN ('sent','in_progress','finalizing') ELSE false END FOR UPDATE OF d
), recipient_locks AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id ORDER BY r.id FOR SHARE OF r NOWAIT
), recipient_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM recipient_locks), field_locks AS MATERIALIZED (
 SELECT f.id FROM document_fields f JOIN parent d ON d.id=f.document_id CROSS JOIN recipient_done g
 ORDER BY f.id FOR SHARE OF f NOWAIT
), field_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM field_locks), cache_locks AS MATERIALIZED (
 SELECT s.field_id FROM field_signing_policy_sizes_v1 s JOIN field_locks f ON f.id=s.field_id
 JOIN parent d ON d.id=s.document_id AND d.org_id=s.org_id CROSS JOIN field_done g
 ORDER BY s.field_id FOR SHARE OF s NOWAIT
), cache_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM cache_locks), binding_locks AS MATERIALIZED (
 -- Count-only pins need no unique binding identity: ties are safe under
 -- NOWAIT. Price both fixed timestamp Datums (16 logical bytes), retain the
 -- existing row overhead, and verify the fresh whole header before any body.
 SELECT b.created_at AS row_created_at,b.updated_at AS row_updated_at
 FROM document_variable_bindings b JOIN parent d ON d.id=b.document_id CROSS JOIN cache_done g
 ORDER BY b.created_at,b.updated_at FOR SHARE OF b NOWAIT
), binding_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM binding_locks)
SELECT d.id AS document_id,d.org_id,r.n AS recipient_count,f.n AS field_count,c.n AS field_cache_count,b.n AS binding_count
FROM parent d CROSS JOIN recipient_done r CROSS JOIN field_done f CROSS JOIN cache_done c CROSS JOIN binding_done b;

-- name: VerifyHistoricalSigningCollectionReadHeaderV1 :one
-- NEW statement after the actual collection loan and row/cache pin call, before
-- ANY body/exposure. READ COMMITTED lock waits can change observed rows; refuse
-- stale lengths/counts/cache server values, including ambiguous zero-row bodies.
-- This scalar receipt grants no row/credential/native-session authority.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL
  AND CASE WHEN octet_length(d.status)<=11 THEN d.status IN ('sent','in_progress','finalizing') ELSE false END FOR UPDATE OF d
), recipient_stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(r.role),0)::numeric+COALESCE(octet_length(r.email),0)::numeric+COALESCE(octet_length(r.name),0)::numeric+COALESCE(octet_length(r.status),0)::numeric+COALESCE(octet_length(r.locale),0)::numeric+COALESCE(octet_length(r.declined_reason),0)::numeric+COALESCE(octet_length(r.magic_token_hash),0)::numeric),0)::bigint AS raw_bytes
 FROM recipients r JOIN parent d ON d.id=r.document_id
), field_stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(f.type),0)::numeric+COALESCE(octet_length(f.label),0)::numeric+COALESCE(octet_length(f.value),0)::numeric),0)::bigint AS raw_bytes,
 COALESCE(sum(COALESCE((SELECT s.options_wire_bytes FROM field_signing_policy_sizes_v1 s
  WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),0)::numeric),0)::bigint AS options_wire_bytes,
 count(*) FILTER (WHERE COALESCE((SELECT 1 FROM field_signing_policy_sizes_v1 s
  WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),0)=0)::bigint AS missing_size_count,
 count(*) FILTER (WHERE COALESCE((SELECT s.measurement_server_version_num FROM field_signing_policy_sizes_v1 s
  WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),-1)<>current_setting('server_version_num')::integer)::bigint AS server_mismatch_count
 FROM document_fields f JOIN parent d ON d.id=f.document_id
), binding_stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(b.variable_name),0)::numeric+COALESCE(octet_length(b.source_kind),0)::numeric+COALESCE(octet_length(b.source_ref),0)::numeric+COALESCE(octet_length(b.source_path),0)::numeric+COALESCE(octet_length(b.fallback),0)::numeric+COALESCE(octet_length(b.last_value),0)::numeric+COALESCE(octet_length(b.last_error),0)::numeric),0)::bigint AS raw_bytes
 FROM document_variable_bindings b JOIN parent d ON d.id=b.document_id
)
SELECT d.id AS document_id,d.org_id
FROM parent d CROSS JOIN recipient_stats r CROSS JOIN field_stats f CROSS JOIN binding_stats b
WHERE r.n=sqlc.arg(expected_recipient_count)::bigint AND r.raw_bytes=sqlc.arg(expected_recipient_raw_bytes)::bigint
 AND f.n=sqlc.arg(expected_field_count)::bigint AND f.raw_bytes=sqlc.arg(expected_field_raw_bytes)::bigint
 AND f.options_wire_bytes=sqlc.arg(expected_field_options_wire_bytes)::bigint
 AND f.missing_size_count=0 AND f.server_mismatch_count=0
 AND b.n=sqlc.arg(expected_binding_count)::bigint AND b.raw_bytes=sqlc.arg(expected_binding_raw_bytes)::bigint;

-- name: ListHistoricalSigningRecipientsV1 :many
-- Exact count/raw guards bind the original header. They confer no authority
-- without its retained SAME native parent/row locks and resource loan.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
  AND CASE WHEN octet_length(d.status)<=11 THEN d.status IN ('sent','in_progress','finalizing') ELSE false END
), actual AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum((COALESCE(octet_length(r.role),0)::numeric+COALESCE(octet_length(r.email),0)::numeric+COALESCE(octet_length(r.name),0)::numeric+COALESCE(octet_length(r.status),0)::numeric+COALESCE(octet_length(r.locale),0)::numeric+COALESCE(octet_length(r.declined_reason),0)::numeric+COALESCE(octet_length(r.magic_token_hash),0)::numeric)::numeric),0)::bigint AS raw_bytes
 FROM recipients r JOIN parent d ON d.id=r.document_id
), admitted AS MATERIALIZED (
 SELECT d.id FROM parent d CROSS JOIN actual a
 WHERE a.n=sqlc.arg(expected_count)::bigint AND a.raw_bytes=sqlc.arg(expected_raw_bytes)::bigint
)
SELECT r.* FROM recipients r JOIN admitted d ON d.id=r.document_id ORDER BY r.order_index,r.created_at;

-- name: ListHistoricalSigningFieldsV1 :many
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
  AND CASE WHEN octet_length(d.status)<=11 THEN d.status IN ('sent','in_progress','finalizing') ELSE false END
), actual AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum((COALESCE(octet_length(f.type),0)::numeric+COALESCE(octet_length(f.label),0)::numeric+COALESCE(octet_length(f.value),0)::numeric)::numeric),0)::bigint AS raw_bytes,
 COALESCE(sum(s.options_wire_bytes::numeric),0)::bigint AS options_wire_bytes,
 count(*) FILTER (WHERE s.field_id IS NULL)::bigint AS missing_size_count,
 count(*) FILTER (WHERE s.measurement_server_version_num<>current_setting('server_version_num')::integer)::bigint AS server_mismatch_count
 FROM document_fields f JOIN parent d ON d.id=f.document_id
 LEFT JOIN field_signing_policy_sizes_v1 s ON s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id
), admitted AS MATERIALIZED (
 SELECT d.id FROM parent d CROSS JOIN actual a
 WHERE a.n=sqlc.arg(expected_count)::bigint AND a.raw_bytes=sqlc.arg(expected_raw_bytes)::bigint
  AND a.options_wire_bytes=sqlc.arg(expected_options_wire_bytes)::bigint AND a.missing_size_count=0 AND a.server_mismatch_count=0
)
SELECT f.* FROM document_fields f JOIN admitted d ON d.id=f.document_id ORDER BY f.page,f.y_pct,f.x_pct;
