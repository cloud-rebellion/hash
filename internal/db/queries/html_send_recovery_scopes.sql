-- name: ListPendingSendRecoveryScopesV1 :many
SELECT i.document_id, i.org_id
FROM send_sealing_intents i
JOIN documents d ON d.id = i.document_id AND d.org_id = i.org_id
WHERE d.status = 'sealing'
  AND d.deleted_at IS NULL
  AND i.presign_execution_id IS NULL AND i.package_send_attempt_id IS NULL
ORDER BY i.updated_at, i.document_id
LIMIT 50;
