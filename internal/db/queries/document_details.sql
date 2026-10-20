-- name: UpdateDraftDocumentDetailsV1 :one
-- Name/expiry or parent edit-witness changes carry no metadata JSON intent.
-- The caller retains its original parent/CAS/member authorization guards.
-- Omitting metadata is deliberate: UPDATE OF invalidation fires even when
-- PostgreSQL considers two JSONB values equal, and 1 versus 1.0 has distinct
-- wire size. Genuine metadata changes still use UpdateDocumentMetadata.
UPDATE documents
SET name = sqlc.arg(name)::text,
    expires_at = sqlc.narg(expires_at)::timestamptz,
    updated_at = now()
WHERE id = sqlc.arg(id)::uuid AND org_id = sqlc.arg(org_id)::uuid
  AND status = 'draft' AND deleted_at IS NULL
RETURNING *;
