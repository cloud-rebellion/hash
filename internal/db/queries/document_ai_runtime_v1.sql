-- Fixed scalar premeasure and same-statement body fences for the genuine AI
-- dispatch scope. Header readers never expand JSON or fetch private text.
-- name: GetDocumentAIRecipientHeaderV1 :one
SELECT COUNT(*)::bigint AS rows, COALESCE(SUM(octet_length(r.name)),0)::bigint AS name_bytes
FROM recipients r JOIN documents d ON d.id=r.document_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL;

-- name: ReadDocumentAIRecipientNamesV1 :many
WITH sized AS MATERIALIZED (
 SELECT COUNT(*)::bigint AS rows, COALESCE(SUM(octet_length(r.name)),0)::bigint AS name_bytes
 FROM recipients r JOIN documents d ON d.id=r.document_id
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
)
SELECT r.name FROM recipients r JOIN documents d ON d.id=r.document_id CROSS JOIN sized x
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND x.rows=sqlc.arg(expected_rows)::bigint AND x.name_bytes=sqlc.arg(expected_name_bytes)::bigint
ORDER BY r.order_index,r.created_at;

-- name: GetDocumentAIOrganizationProviderHeaderV1 :one
SELECT s.org_id,s.updated_at,s.created_at,s.enabled,
 octet_length(s.provider)::bigint AS provider_bytes,octet_length(s.base_url)::bigint AS base_url_bytes,
 octet_length(s.model)::bigint AS model_bytes,octet_length(s.api_key_ct)::bigint AS key_bytes,
 octet_length(s.key_last4)::bigint AS key_last4_bytes
FROM org_ai_settings s JOIN documents d ON d.org_id=s.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
FOR SHARE OF s;

-- name: ReadDocumentAIOrganizationProviderV1 :one
SELECT s.* FROM org_ai_settings s JOIN documents d ON d.org_id=s.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND s.updated_at=sqlc.arg(updated_at)::timestamptz AND s.created_at=sqlc.arg(created_at)::timestamptz
 AND s.enabled=sqlc.arg(enabled)::boolean
 AND octet_length(s.provider)=sqlc.arg(provider_bytes)::bigint AND octet_length(s.base_url)=sqlc.arg(base_url_bytes)::bigint
 AND octet_length(s.model)=sqlc.arg(model_bytes)::bigint AND octet_length(s.api_key_ct)=sqlc.arg(key_bytes)::bigint
 AND octet_length(s.key_last4)=sqlc.arg(key_last4_bytes)::bigint;
