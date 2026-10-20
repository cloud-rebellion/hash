-- Scalar metadata precedes every scalable collection. The fixed native owner
-- already holds the actual document UPDATE and recipient SHARE locks. Own and
-- unassigned fields retain the original public endpoint's visibility.
-- name: GetSignerFieldListReadHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND CASE WHEN octet_length(d.status)<=17 THEN d.status IN ('sent','in_progress','changes_requested') ELSE false END
 FOR UPDATE OF d
), fields AS MATERIALIZED (
 SELECT count(*)::bigint AS n,
 COALESCE(sum(COALESCE(octet_length(f.type),0)::numeric+COALESCE(octet_length(f.label),0)::numeric+COALESCE(octet_length(f.value),0)::numeric),0)::bigint AS raw_bytes,
 COALESCE(sum(COALESCE((SELECT s.options_wire_bytes FROM field_signing_policy_sizes_v1 s WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),0)::numeric),0)::bigint AS options_wire_bytes,
 count(*) FILTER (WHERE NOT EXISTS(SELECT 1 FROM field_signing_policy_sizes_v1 s WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id))::bigint AS missing_size_count,
 count(*) FILTER (WHERE COALESCE((SELECT s.measurement_server_version_num FROM field_signing_policy_sizes_v1 s WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),-1)<>current_setting('server_version_num')::integer)::bigint AS server_mismatch_count
 FROM document_fields f JOIN parent d ON d.id=f.document_id
 WHERE f.recipient_id=sqlc.arg(recipient_id)::uuid OR f.recipient_id IS NULL
)
SELECT d.id AS document_id,d.org_id,f.n AS field_count,f.raw_bytes,f.options_wire_bytes,f.missing_size_count,f.server_mismatch_count,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent d CROSS JOIN fields f;

-- name: LockSignerFieldListReadRowsV1 :one
-- Only after the original count/raw/options loan exists. Never sort/store
-- variable text here. NOWAIT avoids row->parent invalidation deadlocks.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND CASE WHEN octet_length(d.status)<=17 THEN d.status IN ('sent','in_progress','changes_requested') ELSE false END
 FOR UPDATE OF d
), field_locks AS MATERIALIZED (
 SELECT f.id FROM document_fields f JOIN parent d ON d.id=f.document_id
 WHERE f.recipient_id=sqlc.arg(recipient_id)::uuid OR f.recipient_id IS NULL
 ORDER BY f.id FOR SHARE OF f NOWAIT
), field_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM field_locks), cache_locks AS MATERIALIZED (
 SELECT s.field_id FROM field_signing_policy_sizes_v1 s JOIN field_locks f ON f.id=s.field_id
 JOIN parent d ON d.id=s.document_id AND d.org_id=s.org_id CROSS JOIN field_done g
 ORDER BY s.field_id FOR SHARE OF s NOWAIT
), cache_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM cache_locks)
SELECT d.id AS document_id,d.org_id,f.n AS field_count,c.n AS cache_count
FROM parent d CROSS JOIN field_done f CROSS JOIN cache_done c;

-- name: ListSignerFieldListReadRowsV1 :many
-- Fresh scalar verification under the SAME original locks precedes this body.
-- Exact lengths/counts are coherence guards, never standalone read authority.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND CASE WHEN octet_length(d.status)<=17 THEN d.status IN ('sent','in_progress','changes_requested') ELSE false END
), actual AS MATERIALIZED (
 SELECT count(*)::bigint AS n,
 COALESCE(sum(COALESCE(octet_length(f.type),0)::numeric+COALESCE(octet_length(f.label),0)::numeric+COALESCE(octet_length(f.value),0)::numeric),0)::bigint AS raw_bytes,
 COALESCE(sum(COALESCE(s.options_wire_bytes,0)::numeric),0)::bigint AS options_wire_bytes,
 count(*) FILTER (WHERE s.field_id IS NULL)::bigint AS missing_size_count,
 count(*) FILTER (WHERE COALESCE(s.measurement_server_version_num,-1)<>current_setting('server_version_num')::integer)::bigint AS server_mismatch_count
 FROM document_fields f JOIN parent d ON d.id=f.document_id
 LEFT JOIN field_signing_policy_sizes_v1 s ON s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id
 WHERE f.recipient_id=sqlc.arg(recipient_id)::uuid OR f.recipient_id IS NULL
), admitted AS MATERIALIZED (
 SELECT d.id FROM parent d CROSS JOIN actual a
 WHERE a.n=sqlc.arg(expected_count)::bigint AND a.raw_bytes=sqlc.arg(expected_raw_bytes)::bigint
 AND a.options_wire_bytes=sqlc.arg(expected_options_wire_bytes)::bigint AND a.missing_size_count=0 AND a.server_mismatch_count=0
)
SELECT f.* FROM document_fields f JOIN admitted d ON d.id=f.document_id
WHERE f.recipient_id=sqlc.arg(recipient_id)::uuid OR f.recipient_id IS NULL
ORDER BY f.page,f.y_pct,f.x_pct;
