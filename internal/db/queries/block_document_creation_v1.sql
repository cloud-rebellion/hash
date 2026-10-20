-- Fresh block producer identities are allocated by the actual native session.
-- This INSERT cannot adopt any pre-existing document, including identical rows.
-- name: CreateFreshBlocksDocumentV1 :one
INSERT INTO documents(id,org_id,template_id,name,source_kind,blocks_json,variables_json,sender_id,expires_at)
VALUES(sqlc.arg(id),sqlc.arg(org_id),sqlc.narg(template_id)::uuid,sqlc.arg(name),'blocks',sqlc.arg(blocks_json),sqlc.arg(variables_json),sqlc.arg(sender_id),sqlc.arg(expires_at))
RETURNING *;

-- The actual fresh INSERT or native block UPDATE owner has retained every input
-- and the original full source before this intrinsic M92 expansion. Identity or
-- missing cache alone never authorizes invoking this producer.
-- name: MeasureNativeBlocksResponseV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.updated_at=sqlc.arg(expected_updated_at)::timestamptz
  AND d.deleted_at IS NULL AND d.status='draft' AND d.source_kind='blocks'
  AND d.html_source_json IS NULL AND d.html_current_source_json IS NULL
 FOR UPDATE OF d NOWAIT
)
INSERT INTO html_creation_response_sizes_v1(document_id,org_id,blocks_wire_bytes,metadata_wire_bytes,measurement_server_version_num,measured_at)
SELECT id,org_id,0,0,current_setting('server_version_num')::integer,clock_timestamp() FROM parent
ON CONFLICT(document_id) DO UPDATE SET org_id=EXCLUDED.org_id RETURNING *;

-- name: GetLatestDocumentVersionIdentityV1 :one
-- Original linear parent choice under the caller's actual document lock. No
-- previous blocks/variables/HTML model is selected just to obtain its UUID.
SELECT id FROM document_versions WHERE document_id=$1 ORDER BY version_no DESC LIMIT 1;
