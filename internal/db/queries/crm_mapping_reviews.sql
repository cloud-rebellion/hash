-- name: GetDocumentCRMMappingReview :one
SELECT r.* FROM document_crm_mapping_reviews r
JOIN documents d ON d.id = r.document_id
WHERE d.id = sqlc.arg(document_id) AND d.org_id = sqlc.arg(org_id)
    AND d.deleted_at IS NULL;

-- name: ListCRMMappingBindingsForShare :many
-- Parent is already locked. The sentinel 129th row makes an oversized ledger
-- refuse admission rather than silently hashing a truncated prefix.
SELECT b.* FROM document_variable_bindings b
JOIN documents d ON d.id = b.document_id
WHERE d.id = sqlc.arg(document_id) AND d.org_id = sqlc.arg(org_id)
    AND d.deleted_at IS NULL
ORDER BY b.variable_name ASC LIMIT 129
FOR SHARE OF b;

-- name: DocumentHasCRMBindings :one
-- Parent is already locked. Check the full ledger before bounded review reads,
-- preserving ordinary manual documents without a CRM review-size restriction.
SELECT EXISTS (
    SELECT 1 FROM document_variable_bindings b
    JOIN documents d ON d.id = b.document_id
    WHERE d.id = sqlc.arg(document_id) AND d.org_id = sqlc.arg(org_id)
        AND d.deleted_at IS NULL
        AND b.source_kind IN ('crm.deal', 'crm.contact', 'crm.company')
);

-- name: GetDocumentCRMMappingReviewForShare :one
-- Caller holds the parent lock before reading authoring review/mappings.
SELECT r.* FROM document_crm_mapping_reviews r
JOIN documents d ON d.id = r.document_id
WHERE d.id = sqlc.arg(document_id) AND d.org_id = sqlc.arg(org_id)
    AND d.deleted_at IS NULL
FOR SHARE OF r;

-- name: UpsertDocumentCRMMappingReview :one
-- Caller owns one short authorized transaction, parent/member/connection locks,
-- exact ledger checks and immutable audit. This statement additionally refuses
-- foreign members/accounts and a stale parent; it does not supply authorization.
INSERT INTO document_crm_mapping_reviews (
    document_id, has_mappings, binding_digest, content_commitment,
    connection_id, connection_generation, origin, crm_team_id, crm_user_id, reviewed_by
)
SELECT d.id, sqlc.arg(has_mappings)::boolean, sqlc.arg(binding_digest)::text, sqlc.arg(content_commitment)::text,
    sqlc.narg(connection_id)::uuid, sqlc.narg(connection_generation)::bigint,
    sqlc.arg(origin)::text, sqlc.arg(crm_team_id)::text, sqlc.arg(crm_user_id)::text, u.id
FROM documents d JOIN users u ON u.id = sqlc.arg(reviewed_by) AND u.org_id = d.org_id
WHERE d.id = sqlc.arg(document_id) AND d.org_id = sqlc.arg(org_id)
    AND d.status = 'draft' AND d.deleted_at IS NULL
    AND d.updated_at = sqlc.arg(expected_updated_at)::timestamptz
    AND (u.role = 'owner' OR (u.role = 'sender' AND u.id = d.sender_id))
    AND (NOT sqlc.arg(has_mappings)::boolean OR EXISTS (
        SELECT 1 FROM crm_connections c WHERE c.org_id = d.org_id AND c.status = 'active'
            AND c.id = sqlc.narg(connection_id)::uuid AND c.generation = sqlc.narg(connection_generation)::bigint
            AND c.origin = sqlc.arg(origin) AND c.crm_team_id = sqlc.arg(crm_team_id) AND c.crm_user_id = sqlc.arg(crm_user_id)))
ON CONFLICT (document_id) DO UPDATE SET
    has_mappings = EXCLUDED.has_mappings, binding_digest = EXCLUDED.binding_digest,
    content_commitment = EXCLUDED.content_commitment, connection_id = EXCLUDED.connection_id,
    connection_generation = EXCLUDED.connection_generation, origin = EXCLUDED.origin,
    crm_team_id = EXCLUDED.crm_team_id, crm_user_id = EXCLUDED.crm_user_id,
    reviewed_by = EXCLUDED.reviewed_by, updated_at = clock_timestamp()
RETURNING *;
