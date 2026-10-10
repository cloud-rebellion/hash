-- name: GetHTMLDocumentCreationResolutionForShare :one
-- Current live authorization is required separately. Even an owner reads only
-- their original actor-scoped nonce, independent of old receipt TTL.
SELECT * FROM html_document_creation_resolutions
WHERE org_id = $1 AND actor_user_id = $2 AND request_id = $3
FOR SHARE;

-- name: InsertHTMLDocumentCreationClosure :one
-- The caller locks quota unconditionally before authoring membership and holds
-- both through audit and COMMIT. No row returned means read the exact winning
-- outcome; it never proves that closure succeeded or that a new UUID is safe.
INSERT INTO html_document_creation_resolutions (
    org_id, actor_user_id, request_id, template_id, state
) VALUES (
    sqlc.arg(org_id)::uuid, sqlc.arg(actor_user_id)::uuid,
    sqlc.arg(request_id)::uuid, sqlc.arg(template_id)::uuid, 'closed'
)
ON CONFLICT (org_id, actor_user_id, request_id) DO NOTHING
RETURNING *;
