-- The original completion helper loads its sender after token rotation. Read
-- only fixed lengths first; the actual bounded projection retains that order
-- without new sender locks, role restrictions, or a historical body fallback.
-- name: GetHistoricalCompletionSenderHeaderV1 :one
SELECT u.id,u.org_id,u.created_at,
 (octet_length(u.email)::numeric+octet_length(u.name)+octet_length(u.role)+COALESCE(octet_length(u.zitadel_sub),0))::bigint AS raw_text_bytes
FROM users u JOIN documents d ON d.sender_id=u.id AND d.org_id=u.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid;

-- name: ReadHistoricalCompletionSenderV1 :one
SELECT u.*
FROM users u JOIN documents d ON d.sender_id=u.id AND d.org_id=u.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND u.id=sqlc.arg(expected_user_id)::uuid AND u.created_at=sqlc.arg(expected_created_at)::timestamptz
 AND (octet_length(u.email)::numeric+octet_length(u.name)+octet_length(u.role)+COALESCE(octet_length(u.zitadel_sub),0))<=sqlc.arg(expected_raw_text_bytes)::bigint;
