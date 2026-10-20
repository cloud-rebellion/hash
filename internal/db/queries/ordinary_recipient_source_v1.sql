-- Actual scalar source discrimination only. This is not body/audit/actor or
-- cached-work authority. Ordinary native mutation rechecks the locked header
-- below in its own physical transaction; HTML/ambiguous callers keep the
-- original complete contract-recipient policy path.
-- name: GetRecipientMutationSourceDiscriminatorV1 :one
SELECT d.id,d.org_id,d.source_kind,d.status,
 (d.html_source_json IS NOT NULL)::boolean AS has_html_origin,
 (d.html_current_source_json IS NOT NULL)::boolean AS has_html_current,
 (d.html_current_materialization_id IS NOT NULL)::boolean AS has_html_materialization
FROM documents d
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL;

-- name: GetRecipientMutationSourceHeaderV1 :one
SELECT d.id,d.org_id,d.source_kind,d.status,
 (d.html_source_json IS NOT NULL)::boolean AS has_html_origin,
 (d.html_current_source_json IS NOT NULL)::boolean AS has_html_current,
 (d.html_current_materialization_id IS NOT NULL)::boolean AS has_html_materialization
FROM documents d
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
FOR UPDATE OF d;
