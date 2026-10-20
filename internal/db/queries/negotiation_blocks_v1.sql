-- Only the actual native paused-block negotiation producer may derive this
-- fresh response measurement after its same-session admitted source write.
-- Original draft-only MeasureNativeBlocksResponseV1 is deliberately unchanged.
-- No missing/stale cache permits a reader repair or historical backfill.

-- name: MeasureNegotiatedBlocksResponseV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.updated_at=sqlc.arg(expected_updated_at)::timestamptz
  AND d.deleted_at IS NULL AND d.status='changes_requested' AND d.source_kind='blocks'
  AND d.html_source_json IS NULL AND d.html_current_source_json IS NULL
  AND d.html_current_materialization_id IS NULL
 FOR UPDATE OF d NOWAIT
)
INSERT INTO html_creation_response_sizes_v1(document_id,org_id,blocks_wire_bytes,metadata_wire_bytes,measurement_server_version_num,measured_at)
SELECT id,org_id,0,0,current_setting('server_version_num')::integer,clock_timestamp() FROM parent
ON CONFLICT(document_id) DO UPDATE SET org_id=EXCLUDED.org_id RETURNING *;
