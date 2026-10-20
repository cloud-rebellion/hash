-- Closed comment fanout only. No HTML/signing-role predicate; parent and pins
-- are owned by the genuine native transaction, not by these measurements.
-- name: GetCommentRecipientReadHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND CASE WHEN octet_length(d.status)<=17 THEN d.status IN ('sent','in_progress','changes_requested') ELSE false END
 FOR UPDATE OF d
), stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(r.role),0)::numeric+COALESCE(octet_length(r.email),0)+COALESCE(octet_length(r.name),0)+COALESCE(octet_length(r.status),0)+COALESCE(octet_length(r.locale),0)+COALESCE(octet_length(r.declined_reason),0)+COALESCE(octet_length(r.magic_token_hash),0)),0)::bigint AS raw_bytes
 FROM recipients r JOIN parent d ON d.id=r.document_id
)
SELECT d.id AS document_id,d.org_id,s.n AS recipient_count,s.raw_bytes AS recipient_raw_bytes,current_setting('server_version_num')::integer AS server_version_num
FROM parent d CROSS JOIN stats s;

-- name: LockCommentRecipientRowsV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND CASE WHEN octet_length(d.status)<=17 THEN d.status IN ('sent','in_progress','changes_requested') ELSE false END
 FOR UPDATE OF d
), pins AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id ORDER BY r.id FOR SHARE OF r NOWAIT
), stats AS MATERIALIZED (SELECT count(*)::bigint AS n FROM pins)
SELECT d.id AS document_id,d.org_id,s.n AS recipient_count FROM parent d CROSS JOIN stats s;

-- name: ListCommentRecipientsV1 :many
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND CASE WHEN octet_length(d.status)<=17 THEN d.status IN ('sent','in_progress','changes_requested') ELSE false END
), stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(r.role),0)::numeric+COALESCE(octet_length(r.email),0)+COALESCE(octet_length(r.name),0)+COALESCE(octet_length(r.status),0)+COALESCE(octet_length(r.locale),0)+COALESCE(octet_length(r.declined_reason),0)+COALESCE(octet_length(r.magic_token_hash),0)),0)::bigint AS raw_bytes
 FROM recipients r JOIN parent d ON d.id=r.document_id
), admitted AS MATERIALIZED (
 SELECT d.id FROM parent d CROSS JOIN stats s WHERE s.n=sqlc.arg(expected_count)::bigint AND s.raw_bytes=sqlc.arg(expected_raw_bytes)::bigint
)
SELECT r.* FROM recipients r JOIN admitted d ON d.id=r.document_id ORDER BY r.order_index,r.created_at;
