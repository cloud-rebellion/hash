-- name: FindDocumentPackageSendAttemptForSelectionV1 :many
-- A bounded retry observation only. The native owner independently authorizes
-- the actor and inspects the unique durable attempt with all subject fences.
SELECT a.attempt_id
FROM document_package_send_attempts_v1 a
WHERE a.org_id=sqlc.arg(org_id)::uuid AND a.document_id=sqlc.arg(document_id)::uuid
 AND a.package_id=sqlc.arg(package_id)::uuid
 AND a.captured_draft_generation=sqlc.arg(captured_draft_generation)::bigint
 AND a.captured_root_updated_at=sqlc.arg(captured_root_updated_at)::timestamptz
ORDER BY a.created_at,a.attempt_id LIMIT 2;
