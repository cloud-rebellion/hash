-- name: GetHTMLDocumentCreationRequest :one
-- Actor-scoped even for owners. Recovery uses current live membership/session
-- authorization; an expired review receipt does not hide a committed result.
SELECT * FROM html_document_creation_requests
WHERE org_id = $1 AND actor_user_id = $2 AND request_id = $3;

-- name: GetHTMLDocumentCreationRequestForShare :one
SELECT * FROM html_document_creation_requests
WHERE org_id = $1 AND actor_user_id = $2 AND request_id = $3
FOR SHARE;

-- name: InsertHTMLDocumentCreationRequest :one
-- Caller serializes tenant creation with the quota lock and persists the
-- complete draft/source/fields/mappings/review/audit in this same transaction.
INSERT INTO html_document_creation_requests (
    org_id, actor_user_id, request_id, input_digest, template_id,
    original_document_id, current_document_id, html_materialization_id,
    html_source_commitment, pdf_sha256, page_count
)
SELECT d.org_id, d.sender_id, sqlc.arg(request_id)::uuid,
       sqlc.arg(input_digest)::bytea, d.template_id, d.id, d.id,
       m.id, encode(m.source_commitment, 'hex'), m.pdf_sha256, m.page_count
FROM documents d
JOIN html_document_materializations m
    ON m.id = d.html_current_materialization_id AND m.document_id = d.id AND m.org_id = d.org_id
WHERE d.id = sqlc.arg(document_id)::uuid AND d.org_id = sqlc.arg(org_id)::uuid
  AND d.sender_id = sqlc.arg(actor_user_id)::uuid
  AND d.template_id = sqlc.arg(template_id)::uuid
  AND d.status = 'draft' AND d.deleted_at IS NULL
  AND d.html_source_json IS NOT NULL AND d.html_current_materialization_id IS NOT NULL
  AND m.sequence = 1 AND encode(m.source_commitment, 'hex') = sqlc.arg(html_source_commitment)::text
  AND m.page_count = sqlc.arg(page_count)::integer
  AND m.pdf_sha256 = d.pdf_sha256 AND m.pdf_key = d.pdf_storage_key AND m.pdf_version_id = d.pdf_storage_version_id
ON CONFLICT (org_id, actor_user_id, request_id) DO NOTHING
RETURNING *;
