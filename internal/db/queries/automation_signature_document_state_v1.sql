-- name: GetAutomationSignatureDocumentStateV1 :one
-- Existing composite automation checks need fixed legal state, not any cold
-- document JSON; actual Send/Resume owns its independently admitted source.
SELECT id,org_id,status,expires_at,article13_notice_epoch_at
FROM documents WHERE id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid AND deleted_at IS NULL;
