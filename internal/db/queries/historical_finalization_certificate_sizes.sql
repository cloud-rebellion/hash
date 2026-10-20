-- Fixed native certificate sources. No source JSON measurement or reader repair.
-- Original ceremony-root subject semantics intentionally include every event
-- with document_id, even an invalid cross-org row; original claims validation
-- decides legal scope after the actual admitted body read.

-- name: GetHistoricalFinalizationCertificateEventReadHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.updated_at FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL FOR UPDATE OF d
), subject AS MATERIALIZED (
 SELECT d.id,hash_lock_html_snapshot_subject_v1(d.id) AS held FROM parent d
), stats AS MATERIALIZED (
 SELECT count(*)::bigint AS event_count,
 COALESCE(sum(COALESCE(octet_length(e.kind),0)::numeric+COALESCE(octet_length(e.ua),0)
  +COALESCE(octet_length(e.prev_hash),0)+COALESCE(octet_length(e.row_hash),0)
  +COALESCE(octet_length(e.payload_hashed),0)),0)::bigint AS raw_bytes,
 COALESCE(sum(COALESCE((SELECT s.payload_wire_bytes FROM html_snapshot_event_payload_sizes_v1 s
  WHERE s.event_id=e.id AND s.document_id=e.document_id AND s.org_id=e.org_id),0)::numeric),0)::bigint AS payload_wire_bytes,
 count(*) FILTER(WHERE NOT EXISTS(SELECT 1 FROM html_snapshot_event_payload_sizes_v1 s
  WHERE s.event_id=e.id AND s.document_id=e.document_id AND s.org_id=e.org_id))::bigint AS missing_size_count,
 count(*) FILTER(WHERE EXISTS(SELECT 1 FROM html_snapshot_event_payload_sizes_v1 s
  WHERE s.event_id=e.id AND s.document_id=e.document_id AND s.org_id=e.org_id
  AND s.measurement_server_version_num<>current_setting('server_version_num')::integer))::bigint AS server_mismatch_count
 FROM events e JOIN subject d ON d.id=e.document_id
)
SELECT d.id AS document_id,d.org_id,d.updated_at,s.event_count,s.raw_bytes,
 s.payload_wire_bytes,s.missing_size_count,s.server_mismatch_count FROM parent d CROSS JOIN stats s;

-- name: GetHistoricalFinalizationCertificateChainHeadHeaderV1 :one
SELECT e.id AS event_id,e.org_id,e.created_at,e.row_hash_bytes
FROM documents d JOIN LATERAL(
 SELECT e.id,e.org_id,e.created_at,octet_length(e.row_hash)::bigint AS row_hash_bytes FROM events e
 WHERE e.org_id=d.org_id AND e.row_hash IS NOT NULL
 ORDER BY e.created_at DESC,e.id DESC LIMIT 1
)e ON true
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
AND d.deleted_at IS NULL;

-- name: ReadHistoricalFinalizationCertificateChainHeadV1 :one
SELECT e.row_hash,e.created_at FROM events e
WHERE e.id=sqlc.arg(event_id)::uuid AND e.org_id=sqlc.arg(org_id)::uuid
AND e.created_at=sqlc.arg(expected_created_at)::timestamptz
AND octet_length(e.row_hash)::bigint=sqlc.arg(expected_row_hash_bytes)::bigint;
