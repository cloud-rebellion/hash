-- name: ListPendingSendRecoveryScopesV1 :many
-- Keep the existing fifty-row quote. Sticky unknown-upload debt may consume
-- at most half a scan, so it cannot starve genuine committed publication.
-- With no cleanup debt all fifty original sealing positions remain available.
WITH cleanup AS MATERIALIZED (
 SELECT p.document_id,p.org_id,FALSE AS presign_execution,p.id AS cleanup_preparation_id,p.created_at AS sort_at FROM presign_preparations_v1 p
 JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id
 WHERE p.state='closed' AND EXISTS(SELECT 1 FROM presign_preparation_objects_v1 o
  WHERE o.org_id=p.org_id AND o.preparation_id=p.id AND o.upload_attempted AND o.deleted_at IS NULL)
 ORDER BY p.created_at,p.document_id,p.id LIMIT 25
), sealing AS MATERIALIZED (
 SELECT i.document_id,i.org_id,i.presign_execution_id IS NOT NULL AS presign_execution,NULL::uuid AS cleanup_preparation_id,i.updated_at AS sort_at
 FROM send_sealing_intents i JOIN documents d ON d.id=i.document_id AND d.org_id=i.org_id
 WHERE d.status='sealing' AND d.deleted_at IS NULL AND i.package_send_attempt_id IS NULL
 ORDER BY i.updated_at,i.document_id LIMIT (50-(SELECT count(*) FROM cleanup))
)
SELECT document_id,org_id,presign_execution::BOOLEAN AS presign_execution,cleanup_preparation_id FROM (
 SELECT * FROM sealing UNION ALL SELECT * FROM cleanup
) scopes ORDER BY sort_at,document_id,cleanup_preparation_id LIMIT 50;
